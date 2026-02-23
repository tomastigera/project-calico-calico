// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package watcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/projectcalico/calico/third_party/dex/wrapper/pkg/types"
	log "github.com/sirupsen/logrus"
)

// Watcher wraps a fsnotify.Watcher and the target directory to watch.
type Watcher struct {
	fsw      *fsnotify.Watcher
	watchDir string
	// base filename -> last known trimmed content (empty if missing)
	lastContents   map[string]string
	debounceActive bool
	restartCh      chan<- struct{}
	stopDebounceCh <-chan struct{}
}

// New creates a new Watcher configured to watch the specified directory.
func New(watchDir string, restartCh chan<- struct{}, stopDebounceCh <-chan struct{}) (*Watcher, error) {
	log.WithField("dir", watchDir).Info("initializing file watcher")

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating watcher: %w", err)
	}

	wr := &Watcher{
		fsw:            w,
		watchDir:       watchDir,
		lastContents:   map[string]string{},
		restartCh:      restartCh,
		stopDebounceCh: stopDebounceCh,
	}
	// Prime the cache for monitored files.
	for _, f := range types.WatchedFilenames {
		content, _ := readTrimmedFile(filepath.Join(watchDir, f))
		wr.lastContents[f] = content
	}

	return wr, nil
}

// Start begins the watch loop and blocks until context is done or an unrecoverable error occurs.
func (w *Watcher) Start(ctx context.Context) error {
	log.WithField("dir", w.watchDir).Info("starting file watcher...")

	// Add the watch on the directory at start time rather than during construction.
	if err := w.fsw.Add(w.watchDir); err != nil {
		return fmt.Errorf("adding watch on %s: %w", w.watchDir, err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-w.stopDebounceCh:
			// DexWrapper signaled a successful restart; end the debounce window.
			w.debounceActive = false
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return errors.New("watcher channel closed")
			}
			w.processFsnotifyEvent(ctx, ev)
		case err := <-w.fsw.Errors:
			if err != nil {
				return fmt.Errorf("watcher error: %w", err)
			}
		}
	}
}

func (w *Watcher) processFsnotifyEvent(ctx context.Context, ev fsnotify.Event) {
	base := filepath.Base(ev.Name)
	log.Debugf("file event detected: %s", ev.String())
	if w.shouldRestartDexForEvent(ev) {
		_ = w.updateCache(base)
		if !w.debounceActive {
			w.startDebounce(ctx)
		} else {
			log.Debug("event during debounce window; restart already scheduled")
		}
	}
}

// shouldRestartDexForEvent decides whether a given fsnotify event should trigger a Dex restart.
func (w *Watcher) shouldRestartDexForEvent(ev fsnotify.Event) bool {
	base := filepath.Base(ev.Name)
	if !isWatchedFilename(base) {
		return false
	}
	if ev.Has(fsnotify.Remove) {
		return true
	}
	if ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create) {
		changed, err := w.contentChanged(base)
		if err != nil {
			log.WithError(err).Warnf("failed to evaluate content change for %s; skipping to avoid constant restart", base)
			return false
		}
		return changed
	}
	return false
}

// contentChanged compares the current file content against the cached value without updating the cache.
func (w *Watcher) contentChanged(base string) (bool, error) {
	newContent, err := w.getCurrentContent(base)
	if err != nil {
		return false, err
	}
	prev := w.lastContents[base]
	return newContent != prev, nil
}

func readTrimmedFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// getCurrentContent returns the current on-disk content for the given base filename (joined with watchDir).
// If the file does not exist, it returns an empty string and no error.
func (w *Watcher) getCurrentContent(base string) (string, error) {
	path := filepath.Join(w.watchDir, base)
	newContent, err := readTrimmedFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return newContent, nil
}

// updateCache refreshes the cached content for the given base filename.
// If the file does not exist, it caches an empty string.
func (w *Watcher) updateCache(base string) error {
	newContent, err := w.getCurrentContent(base)
	if err != nil {
		log.WithError(err).Warnf("failed to update cache for %s", base)
		return err
	}
	w.lastContents[base] = newContent
	return nil
}

func isWatchedFilename(filename string) bool {
	return slices.Contains(types.WatchedFilenames, filename)
}

// Close releases underlying watcher resources.
func (w *Watcher) Close() error {
	if w.fsw != nil {
		return w.fsw.Close()
	}
	return nil
}

// startDebounce begins the debounce window if not already active. After the delay, it requests Dex restart once.
func (w *Watcher) startDebounce(ctx context.Context) {
	if w.debounceActive {
		return
	}
	w.debounceActive = true
	log.WithField("delay", types.DebounceRestartDelay).Info("debounce window started; will request Dex restart after delay")
	go func() {
		t := time.NewTimer(types.DebounceRestartDelay)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			log.Info("debounce window elapsed; sending restart request")
			w.restartCh <- struct{}{}
		}
	}()
}
