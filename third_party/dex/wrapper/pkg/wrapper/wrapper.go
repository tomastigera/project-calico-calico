// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package wrapper

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/third_party/dex/wrapper/pkg/types"
)

// DexWrapper manages the lifecycle of a Dex process instance.
// It holds state (the current exec.Cmd) so that the package is concurrency-safe
// and multiple instances can be used independently if needed.
type DexWrapper struct {
	currentDexCmd        *exec.Cmd
	dexRuntimeConfigPath string
	dexBaseConfigPath    string
	watchDir             string

	restartCh      chan struct{}
	stopDebounceCh chan struct{}
}

// New constructs a new DexWrapper.
func New() *DexWrapper {
	return &DexWrapper{
		dexRuntimeConfigPath: types.BaseConfigPath,
		dexBaseConfigPath:    types.BaseConfigPath,
		watchDir:             os.Getenv(types.EnvWatchDir),
	}
}

func (d *DexWrapper) SetRestartCh(ch chan struct{}) {
	d.restartCh = ch
}

func (d *DexWrapper) SetStopDebounceCh(ch chan struct{}) {
	d.stopDebounceCh = ch
}

// NeedsWatching reports whether the wrapper should watch files for changes.
// It is true when WATCH_DIR is set (i.e., non-empty).
func (d *DexWrapper) NeedsWatching() bool {
	return d.watchDir != ""
}

func (d *DexWrapper) GetWatchDir() string {
	return d.watchDir
}

func (d *DexWrapper) Cleanup() {
	if d.currentDexCmd != nil && d.currentDexCmd.Process != nil {
		d.stopDex()
	}
}

func (d *DexWrapper) startDex() error {
	log.Info("starting Dex...")
	if _, err := os.Stat(types.DexBinary); err != nil {
		return fmt.Errorf("dex binary not found at %s: %w", types.DexBinary, err)
	}

	if _, err := os.Stat(d.dexRuntimeConfigPath); err != nil {
		return fmt.Errorf("dex config not found at %s: %w", d.dexRuntimeConfigPath, err)
	}

	cmd := exec.Command(types.DexBinary, "serve", d.dexRuntimeConfigPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start dex: %w", err)
	}
	d.currentDexCmd = cmd

	// Give Dex a moment to start and check if it's running
	time.Sleep(types.DexStartupWaitTime)
	if cmd.Process == nil {
		return fmt.Errorf("dex failed to start (no process)")
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return fmt.Errorf("dex failed to start (not alive): %w", err)
	}
	log.Infof("Dex started successfully (PID: %d)", cmd.Process.Pid)
	return nil
}

func (d *DexWrapper) stopDex() {
	if d.currentDexCmd == nil || d.currentDexCmd.Process == nil {
		log.Info("dex is not running")
		return
	}
	pid := d.currentDexCmd.Process.Pid
	log.Infof("stopping Dex gracefully (PID: %d)...", pid)
	if err := d.currentDexCmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Warnf("error occurred when sending SIGTERM to dex: %v", err)
	}

	// Wait for a graceful shutdown with timeout
	done := make(chan struct{})
	go func() {
		if err := d.currentDexCmd.Wait(); err != nil {
			log.Warnf("dex exited with error: %v", err)
		}
		done <- struct{}{}
	}()

	select {
	case <-time.After(types.GracefulShutdownTimeout):
		log.Warn("graceful shutdown timed out, force killing Dex...")
		if err := d.currentDexCmd.Process.Kill(); err != nil {
			log.Warnf("error occurred when killing dex: %v", err)
		}
		<-done // ensure wait returns
	case <-done:
		// exited normally
	}
	log.Info("dex stopped")
	d.currentDexCmd = nil
}

func (d *DexWrapper) restartDex() error {
	log.Info("restarting Dex due to file change...")
	d.stopDex()
	if err := d.BuildDexRuntimeConfig(); err != nil {
		return err
	}
	return d.startDex()
}

func (d *DexWrapper) waitForDex(ctx context.Context) {
	if d.currentDexCmd == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		if err := d.currentDexCmd.Wait(); err != nil {
			log.Warnf("dex exited with error: %v", err)
		}
		done <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		d.stopDex()
	case <-done:
		// dex exited
	}
}

func (d *DexWrapper) Run(ctx context.Context) error {
	if d.NeedsWatching() {
		// Build runtime config from files and start Dex, then handle restart requests.
		if err := d.BuildDexRuntimeConfig(); err != nil {
			return err
		}
		if err := d.startDex(); err != nil {
			return err
		}
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-d.restartCh:
				// Attempt restart and signal watcher to end debounce regardless of outcome.
				err := d.restartDex()
				d.stopDebounceCh <- struct{}{}
				if err != nil {
					return err
				}
			}
		}
	}

	// No watching needed: start Dex and wait for it to exit or context cancellation.
	if err := d.startDex(); err != nil {
		return err
	}
	d.waitForDex(ctx)
	return nil
}
