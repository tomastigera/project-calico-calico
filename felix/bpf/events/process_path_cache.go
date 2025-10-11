// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package events

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

// processPathCacheEntry is a cache entry for process path information.
// It wraps the ProcessPathInfo with cache-tracking metadata.
type processPathCacheEntry struct {
	source    pidInfoSource
	expiresAt time.Time

	ProcessPathInfo
}

type ProcessPathInfo struct {
	Path string
	Args string
}

type pidInfoSource int

const (
	sourceKprobe pidInfoSource = iota
	sourceProc
)

func (p pidInfoSource) String() string {
	switch p {
	case sourceKprobe:
		return "kprobe"
	case sourceProc:
		return "proc"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}

// BPFProcessPathCache caches process path and args read via kprobes/proc
type BPFProcessPathCache struct {
	// Read-Write mutex for process path info
	lock sync.Mutex
	// Map of PID to process path information
	cache map[int]processPathCacheEntry

	// Max time for which an entry is retained.
	entryTTL   time.Duration
	gcInterval time.Duration

	stopOnce sync.Once
	wg       sync.WaitGroup
	stopC    chan struct{}

	eventProcessPath <-chan ProcessPath
	rll              *logutils.RateLimitedLogger
	procfs           readDirReadFileFS

	UnexpectedErrorCount atomic.Int64
}

type readDirReadFileFS interface {
	fs.ReadFileFS
	fs.ReadDirFS
}

type ProcPathCacheOpt func(*BPFProcessPathCache)

func WithProcfs(fs readDirReadFileFS) ProcPathCacheOpt {
	return func(cache *BPFProcessPathCache) {
		cache.procfs = fs
	}
}

// NewBPFProcessPathCache returns a new BPFProcessPathCache
func NewBPFProcessPathCache(
	eventProcessPathChan <-chan ProcessPath,
	gcInterval time.Duration,
	entryTTL time.Duration,
	opts ...ProcPathCacheOpt,
) *BPFProcessPathCache {
	c := &BPFProcessPathCache{
		stopC:            make(chan struct{}),
		eventProcessPath: eventProcessPathChan,
		gcInterval:       gcInterval,
		entryTTL:         entryTTL,
		cache:            make(map[int]processPathCacheEntry),
		lock:             sync.Mutex{},
		rll:              logutils.NewRateLimitedLogger(),
		procfs:           os.DirFS("/proc").(readDirReadFileFS),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (r *BPFProcessPathCache) Start() {
	if r.eventProcessPath == nil {
		return
	}
	log.Debugf("starting BPFProcessPathCache")
	r.wg.Add(1)
	go r.run()
}

func (r *BPFProcessPathCache) run() {
	defer r.wg.Done()

	expireTicker := jitter.NewTicker(r.gcInterval, r.gcInterval/10)
	defer expireTicker.Stop()

	refreshTicker := jitter.NewTicker(r.entryTTL/2, r.entryTTL/20)
	defer refreshTicker.Stop()

	for {
		select {
		case <-r.stopC:
			log.Info("BPFProcessPathCache background loop stopping.")
			return
		case processEvent, ok := <-r.eventProcessPath:
			log.Debugf("Received process path event: %v", processEvent)
			if ok {
				info := ProcessPathInfo{
					Path: processEvent.Filename,
					Args: processEvent.Arguments,
				}
				r.updateCache(sourceKprobe, processEvent.Pid, info)
			}
		case <-expireTicker.Channel():
			r.expireCacheEntries()
		case <-refreshTicker.Channel():
			err := r.updateAllPIDsFromProcFS()
			if err != nil {
				log.WithError(err).Error("Failed to scan procfs to refresh PID cache.")
			}
		}
	}
}

func (r *BPFProcessPathCache) Stop() {
	r.stopOnce.Do(func() {
		log.Info("Stopping BPFProcessPathCache")
		close(r.stopC)
	})
	r.wg.Wait()
}

// Lookup returns the process path and args for a given PID.  The cache is
// used if possible, otherwise, it consults /proc and stores the result in
// the cache.
func (r *BPFProcessPathCache) Lookup(pid int) (ProcessPathInfo, bool) {
	r.lock.Lock()
	entry, ok := r.cache[pid]
	r.lock.Unlock()
	if !ok || entry.source == sourceKprobe {
		// Though the data is available from kprobes, we still do a check in /proc.
		// This is to avoid inconsistencies especially in cases like nginx deployments
		// where the kprobe data is that of the container process and proc data is
		// that of nginx. Hence if /proc/pid/cmdline is available that takes the higher
		// precedence.
		entry = r.updateSinglePIDFromProcfs(pid)
	}
	// If the lookup failed, updateSinglePIDFromProcfs will have written a
	// tombstone entry to the cache.  Caller only cares about whether we have
	// a path or not.
	ok = entry.Path != ""
	return entry.ProcessPathInfo, ok
}

// updateAllPIDsFromProcFS reads all of /proc, refreshing all the cache
// entries that it sees.
func (r *BPFProcessPathCache) updateAllPIDsFromProcFS() error {
	proc, err := r.procfs.ReadDir(".")
	if err != nil {
		return fmt.Errorf("failed to read /proc: %w", err)
	}
	for _, f := range proc {
		if !f.IsDir() {
			continue
		}
		name := f.Name()
		pid, err := strconv.Atoi(name)
		if err != nil {
			// Skip non-numeric directories...
			continue
		}
		r.updateSinglePIDFromProcfs(pid)
	}
	return nil
}

func (r *BPFProcessPathCache) updateSinglePIDFromProcfs(pid int) processPathCacheEntry {
	cmdlinePath := fmt.Sprintf("%d/cmdline", pid)
	pathInfo := ProcessPathInfo{}
	content, err := r.procfs.ReadFile(cmdlinePath)
	if errors.Is(err, fs.ErrNotExist) {
		log.Debugf("PID not found in /proc: %d.", pid)
	} else if errors.Is(err, syscall.ESRCH) {
		log.Debugf("Read of /proc/%d/cmdline failed because process exited.", pid)
	} else if err != nil {
		r.UnexpectedErrorCount.Add(1) // Counter for the UTs to check.
		r.rll.WithError(err).Warnf("Unexpected error when trying to read /proc/%d/cmdline, ignoring.", pid)
	} else {
		path, args, _ := strings.Cut(string(content), "\x00")
		pathInfo.Path = path
		pathInfo.Args = args
	}
	return r.updateCache(sourceProc, pid, pathInfo)
}

func (r *BPFProcessPathCache) updateCache(source pidInfoSource, pid int, info ProcessPathInfo) processPathCacheEntry {
	r.lock.Lock()
	defer r.lock.Unlock()

	log.Debugf("Updating process path info pid=%d %+v", pid, info)
	entry, ok := r.cache[pid]
	if !ok {
		// Cache miss, take what we're given.
		entry = processPathCacheEntry{
			ProcessPathInfo: info,
			source:          source,
		}
	} else {
		// Merge the info into the current entry.
		if info.Path != "" {
			entry.Path = info.Path
			entry.Args = info.Args

		}
		// Record the most recent source that has checked the cache.
		entry.source = source
	}

	// Update the cache.
	entry.expiresAt = time.Now().Add(r.entryTTL)
	r.cache[pid] = entry

	// Return the updated entry to save the caller from having to re-take
	// the lock.
	return entry
}

func (r *BPFProcessPathCache) expireCacheEntries() {
	r.lock.Lock()
	defer r.lock.Unlock()
	log.Debug("Running PID cache GC.")

	for pid, entry := range r.cache {
		if entry.expiresAt.After(time.Now()) {
			continue
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Debugf("Expiring PID %d -> name cache %+v.", pid, entry)
		}
		delete(r.cache, pid)
	}
}
