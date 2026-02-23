// Copyright (c) 2018 Tigera, Inc. All rights reserved.
// Copyright 2017 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipsec

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bronze1man/goStrongswanVici"
	log "github.com/sirupsen/logrus"
)

const (
	viciSocketPath = "/var/run/charon.vici"

	defaultRetryCount   = 3
	firstConnRetrycount = 100
)

type Uri struct {
	Network, Address string
}

type CharonIKEDaemon struct {
	viciUri     Uri
	espProposal string
	ikeProposal string
	rekeyTime   time.Duration
	ctx         context.Context

	firstConnSucceeded bool
	cachedClient       VICIClient

	runAndCaptureLogs func(execPath string, doneWG *sync.WaitGroup) (CharonCommand, error)
	newClient         viciClientFactory
	sleep             func(duration time.Duration)
	after             func(duration time.Duration) <-chan time.Time
	cleanUpOldCharon  func() error

	childExitedCallback func()
}

type VICIClient interface {
	io.Closer
	LoadConn(conn *map[string]goStrongswanVici.IKEConf) error
	UnloadConn(r *goStrongswanVici.UnloadConnRequest) error
	LoadShared(key *goStrongswanVici.Key) error
	UnloadShared(key *goStrongswanVici.UnloadKeyRequest) error
}

type viciClientFactory func(ctx context.Context, viciUri Uri) (client VICIClient, err error)

func NewCharonIKEDaemon(
	espProposal,
	ikeProposal string,
	rekeyTime time.Duration,
	childExitedCallback func()) *CharonIKEDaemon {
	return NewCharonWithShims(
		espProposal, ikeProposal, rekeyTime, childExitedCallback,
		runAndCaptureLogs, getRealVICIClient, time.Sleep, time.After, CleanUpOldCharon,
	)
}

func NewCharonWithShims(
	espProposal,
	ikeProposal string,
	rekeyTime time.Duration,
	childExitedCallback func(),

	runAndCaptureLogs func(execPath string, doneWG *sync.WaitGroup) (CharonCommand, error),
	newClient viciClientFactory,
	sleep func(duration time.Duration),
	after func(duration time.Duration) <-chan time.Time,
	cleanUpOldCharon func() error,
) *CharonIKEDaemon {
	charon := &CharonIKEDaemon{
		espProposal: espProposal,
		ikeProposal: ikeProposal,
		viciUri:     Uri{"unix", viciSocketPath},
		rekeyTime:   rekeyTime,

		runAndCaptureLogs: runAndCaptureLogs,
		newClient:         newClient,
		sleep:             sleep,
		after:             after,
		cleanUpOldCharon:  cleanUpOldCharon,

		childExitedCallback: childExitedCallback,
	}

	return charon
}

// CharonCommand interface for the parts of exec.Cmd that we use.  Intended for mocking.
type CharonCommand interface {
	Wait() error
	Signal(signal os.Signal) error
	Kill() error
}

func (charon *CharonIKEDaemon) Start(ctx context.Context, doneWG *sync.WaitGroup) error {
	charon.ctx = ctx

	err := os.MkdirAll("/var/run/", 0755 /* rwxr-xr-x (matches value on my test system) */)
	if err != nil {
		log.WithError(err).Error("Failed to ensure /var/run directory exists")
		return err
	}

	err = charon.cleanUpOldCharon()
	if err != nil {
		log.WithError(err).Error("Failed to clean up old charon")
		return err
	}

	cmd, err := charon.runAndCaptureLogs("/usr/lib/ipsec/charon", doneWG)

	if err != nil {
		log.Errorf("Error starting charon daemon: %v", err)
		return err
	} else {
		log.Info("Charon daemon started")
	}

	// Convert cmd.Wait() into a channel close event that we can select on.
	processExited := make(chan struct{}) // closed when the process exits.
	go func() {
		log.Info("Started charon process monitor goroutine.")
		err := cmd.Wait()
		log.Infof("Charon exited, signaling to monitor goroutine.  Exit error details: %v", err)
		close(processExited)
	}()

	doneWG.Go(func() {
		log.Info("Started charon shutdown management goroutine.")

		select {
		case <-ctx.Done():
			log.Info("Context finished, shutting down charon.")
			if err := cmd.Signal(syscall.SIGTERM); err != nil {
				log.WithError(err).Error("failed to send SIGTERM signal")
			}
			select {
			case <-charon.after(5 * time.Second):
				log.Error("charon didn't exit, killing it")
				if err := cmd.Kill(); err != nil {
					log.WithError(err).Error("failed to kill charon")
				}
			case <-processExited:
				log.Info("Charon exited.")
			}
		case <-processExited:
			log.Error("Charon exited unexpectedly.  Reporting the failure.")
			charon.childExitedCallback()
		}
	})

	return nil
}

func runAndCaptureLogs(execPath string, doneWG *sync.WaitGroup) (CharonCommand, error) {
	path, err := exec.LookPath(execPath)
	if err != nil {
		return nil, err
	}
	cmd := &exec.Cmd{
		Path: path,
		SysProcAttr: &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGTERM,
		},
	}

	// Start charon log collector
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("Error get stdout pipe: %v", err)
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Errorf("Error get stderr pipe: %v", err)
		return nil, err
	}
	doneWG.Add(2)
	go CopyOutputToLog("stdout", stdout, doneWG)
	go CopyOutputToLog("stderr", stderr, doneWG)

	err = cmd.Start()

	return (*cmdAdapter)(cmd), err
}

type cmdAdapter exec.Cmd

func (c *cmdAdapter) Wait() error {
	return (*exec.Cmd)(c).Wait()
}

func (c *cmdAdapter) Signal(s os.Signal) error {
	return c.Process.Signal(s)
}

func (c *cmdAdapter) Kill() error {
	return c.Process.Kill()
}

func (charon *CharonIKEDaemon) LoadConnection(localIP, remoteIP string) error {
	return charon.withClientRetry("LoadConnection", func(c VICIClient) error {
		if localIP == "" || remoteIP == "" {
			log.WithFields(log.Fields{
				"localIP":  localIP,
				"remoteIP": remoteIP,
			}).Panic("Missing local or remote Address")
		}

		childConfMap := make(map[string]goStrongswanVici.ChildSAConf)
		childSAConf := goStrongswanVici.ChildSAConf{
			Local_ts:      []string{"0.0.0.0/0"},
			Remote_ts:     []string{"0.0.0.0/0"},
			ESPProposals:  []string{charon.espProposal},
			StartAction:   "start",
			CloseAction:   "none",
			Mode:          "tunnel",
			ReqID:         fmt.Sprint(ReqID),
			RekeyTime:     fmt.Sprintf("%ds", int(charon.rekeyTime.Seconds())), //Can set this to a low time to check that rekeys are handled properly
			InstallPolicy: "no",
			HWOffload:     "auto",
		}

		childSAConfName := formatName(localIP, remoteIP)
		childConfMap[childSAConfName] = childSAConf

		localAuthConf := goStrongswanVici.AuthConf{
			AuthMethod: "psk",
		}
		remoteAuthConf := goStrongswanVici.AuthConf{
			AuthMethod: "psk",
		}

		ikeConf := goStrongswanVici.IKEConf{
			LocalAddrs:  []string{localIP},
			RemoteAddrs: []string{remoteIP},
			Proposals:   []string{charon.ikeProposal},
			Version:     "2",
			KeyingTries: "0", //continues to retry
			LocalAuth:   localAuthConf,
			RemoteAuth:  remoteAuthConf,
			Children:    childConfMap,
			Encap:       "no",
			Mobike:      "no",
		}
		ikeConfMap := make(map[string]goStrongswanVici.IKEConf)

		connectionName := formatName(localIP, remoteIP)
		ikeConfMap[connectionName] = ikeConf

		err := c.LoadConn(&ikeConfMap)
		if err != nil {
			return err
		}

		log.Infof("Loaded connection: %v", connectionName)
		return nil
	})
}

func (charon *CharonIKEDaemon) UnloadCharonConnection(localIP, remoteIP string) error {
	return charon.withClientRetry("UnloadCharonConnection", func(c VICIClient) error {
		connectionName := formatName(localIP, remoteIP)
		unloadConnRequest := &goStrongswanVici.UnloadConnRequest{
			Name: connectionName,
		}

		err := c.UnloadConn(unloadConnRequest)
		if err != nil {
			return err
		}

		log.Infof("Unloaded connection: %v", connectionName)
		return nil
	})
}

func (charon *CharonIKEDaemon) LoadSharedKey(remoteIP, password string) error {
	return charon.withClientRetry("LoadSharedKey", func(c VICIClient) error {
		sharedKey := &goStrongswanVici.Key{
			ID:     remoteIP,
			Typ:    "IKE",
			Data:   password,
			Owners: []string{remoteIP},
		}
		err := c.LoadShared(sharedKey)
		if err != nil {
			log.WithError(err).Errorf("Failed to load key for %v", remoteIP)
			return err
		}
		log.Infof("Loaded shared key for: %v", remoteIP)
		return nil
	})
}

func (charon *CharonIKEDaemon) UnloadSharedKey(remoteIP string) error {
	return charon.withClientRetry("UnloadSharedKey", func(c VICIClient) error {
		sharedKey := &goStrongswanVici.UnloadKeyRequest{
			ID: remoteIP,
		}
		err := c.UnloadShared(sharedKey)
		if err != nil {
			log.WithError(err).Errorf("Failed to unload key for %v.", remoteIP)
			return err
		}
		log.Infof("Unloaded shared key for: %v", remoteIP)
		return nil
	})
}

func (charon *CharonIKEDaemon) client() VICIClient {
	attempts := defaultRetryCount
	if !charon.firstConnSucceeded {
		// The Charon takes a while to accept connections at start of day, give it a substantially longer time for the
		// first connection.
		attempts = firstConnRetrycount
	}
	if charon.cachedClient == nil {
		var err error
		for attempt := 0; attempt < attempts; attempt++ {
			log.WithError(err).Info("Attempting to connect to IPsec IKE daemon...")
			c, err := charon.newClient(charon.ctx, charon.viciUri)
			if err == nil {
				log.Info("Connected to IPsec IKE daemon.")
				charon.cachedClient = c
				break
			}
			charon.sleep(100 * time.Millisecond)
		}
		if charon.cachedClient == nil {
			log.WithError(err).Panic("Failed to connect to charon after multiple retries")
		}
		charon.firstConnSucceeded = true
	}
	return charon.cachedClient
}

func (charon *CharonIKEDaemon) discardClient() {
	err := charon.cachedClient.Close()
	if err != nil {
		// This generally means that a deferred socket operation (i.e. flushing the buffer) failed.
		// We're about to reconnect or give up so we ignore.
		log.WithError(err).Error("Closing the VICI client returned error")
	}
	charon.cachedClient = nil
}

func (charon *CharonIKEDaemon) withClientRetry(opName string, f func(c VICIClient) error) error {
	debug := log.GetLevel() >= log.DebugLevel
	var err error
	for range defaultRetryCount {
		if debug {
			log.WithField("operation", opName).Debug("Attempting VICI operation")
		}
		c := charon.client()
		err = f(c)
		if err == nil {
			if debug {
				log.WithField("operation", opName).Debug("VICI operation succeeded")
			}
			return nil
		}
		log.WithField("operation", opName).WithError(err).Warn("VICI operation failed")
		charon.discardClient()
		time.Sleep(100 * time.Millisecond)
	}
	log.WithField("operation", opName).WithError(err).Error("VICI operation consistently failed")
	return err
}

func getRealVICIClient(ctx context.Context, viciUri Uri) (client VICIClient, err error) {
	socketConn, err := net.Dial(viciUri.Network, viciUri.Address)
	if err != nil {
		return nil, err
	}
	return goStrongswanVici.NewClientConn(socketConn), nil
}

func CopyOutputToLog(streamName string, stream io.Reader, doneWG *sync.WaitGroup) {
	defer doneWG.Done()

	scanner := bufio.NewScanner(stream)
	scanner.Buffer(nil, 4*1024*1024) // Increase maximum buffer size (but don't pre-alloc).
	for scanner.Scan() {
		line := scanner.Text()
		log.Info("[", streamName, "] ", line)
	}
	logCxt := log.WithFields(log.Fields{
		"name":   "charon",
		"stream": stream,
	})
	if err := scanner.Err(); err != nil {
		log.Warnf("Non-EOF error reading charon [%s], err %v; will pause and then exit...", streamName, err)
		// Very likely that the charon exited.  The charon process watch goroutine should shut felix down cleanly.
		// give it a chance to do that before we panic.
		time.Sleep(10 * time.Second)
		log.Panicf("Non-EOF error reading charon [%s], err %v", streamName, err)
	}
	logCxt.Info("Stream finished")
}

func formatName(local, remote string) string {
	return fmt.Sprintf("%s-%s", local, remote)
}

func CleanUpOldCharon() error {
	const pidfilePath = "/var/run/charon.pid"
	if f, err := os.Open(pidfilePath); err == nil {
		defer f.Close()
		bs, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(bs)))
		if err != nil {
			return err
		}

		// check if process do exist.
		// os.FindProcess() always succeeds.
		killErr := syscall.Kill(pid, syscall.Signal(0))
		procExists := killErr == nil
		if procExists {
			log.WithField("pid", pid).Info("charon already running, killing it")
			proc, err := os.FindProcess(pid)
			if err == nil {
				err = proc.Kill()
				if err != nil {
					log.WithError(err).Error("Failed to kill old Charon")
					return err
				}
			}
		} else {
			log.WithField("pid", pid).Info("charon is not running, but pid file exists")
		}
		os.Remove(pidfilePath)
	}

	// Clean up any old socket.  Without this, the VICI client can try to connect to the old socket
	// rather than waiting for the new.
	if _, err := os.Stat(viciSocketPath); err == nil {
		err := os.Remove(viciSocketPath)
		if err != nil {
			log.WithError(err).Error("Failed to remove old VICI socket.")
		}
	}

	return nil
}
