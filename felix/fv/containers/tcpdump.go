// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.

package containers

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/utils"
)

func AttachTCPDump(c *Container, iface string, filter ...string) *TCPDump {
	t := &TCPDump{
		logEnabled:       true,
		containerID:      c.GetID(),
		containerName:    c.Name,
		iface:            iface,
		filter:           filter,
		matchers:         map[string]*tcpDumpMatcher{},
		listeningStarted: make(chan struct{}),
	}
	return t
}

type stringMatcher interface {
	MatchString(string) bool
}

type tcpDumpMatcher struct {
	regex stringMatcher
	count int
}

type TCPDump struct {
	lock sync.Mutex

	logEnabled       bool
	containerID      string
	containerName    string
	iface            string
	filter           []string
	cmd              *exec.Cmd
	out, err         io.ReadCloser
	listeningStarted chan struct{}

	matchers map[string]*tcpDumpMatcher
}

func (t *TCPDump) SetLogEnabled(logEnabled bool) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.logEnabled = logEnabled
}

func (t *TCPDump) AddMatcher(name string, s stringMatcher) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.matchers[name] = &tcpDumpMatcher{
		regex: s,
	}
}

func (t *TCPDump) MatchCount(name string) int {
	t.lock.Lock()
	defer t.lock.Unlock()

	c := t.matchers[name].count
	logrus.Infof("[%s] Match count for %s is %v", t.containerName, name, c)
	return c
}

type CleanupProvider interface {
	AddCleanup(func())
}

func (t *TCPDump) Start(infra CleanupProvider) {
	// docker run --rm --network=container:48b6c5f44d57 --privileged corfr/tcpdump -nli cali01

	args := []string{
		"run",
		"--rm",
		fmt.Sprintf("--network=container:%s", t.containerID),
		"--privileged",
		"corfr/tcpdump", "-nli", t.iface,
	}
	if len(t.filter) > 0 {
		args = append(args, t.filter...)
	}
	t.cmd = utils.Command("docker", args...)
	var err error
	t.out, err = t.cmd.StdoutPipe()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	t.err, err = t.cmd.StderrPipe()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	go t.readStdout()
	go t.readStderr()

	err = t.cmd.Start()

	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	infra.AddCleanup(t.Stop)

	select {
	case <-t.listeningStarted:
	case <-time.After(60 * time.Second):
		ginkgo.Fail("Failed to start tcpdump: it never reported that it was listening")
	}

}

func (t *TCPDump) Stop() {
	err := t.cmd.Process.Kill()
	if err != nil {
		logrus.WithError(err).Error("Failed to kill tcp dump; maybe it failed to start?")
	}
}

func (t *TCPDump) readStdout() {
	s := bufio.NewScanner(t.out)
	for s.Scan() {
		line := s.Text()

		t.lock.Lock()
		logEnabled := t.logEnabled
		t.lock.Unlock()

		t.lock.Lock()
		hits := map[string]int{}
		for name, m := range t.matchers {
			if m.regex.MatchString(line) {
				m.count++
				hits[name] = m.count
			}
		}
		t.lock.Unlock()

		if logEnabled {
			hitsStr := ""
			if len(hits) > 0 {
				hitsStr = "HIT: "
				for n, c := range hits {
					hitsStr += fmt.Sprint(n, ":", c, " ")
				}
			}
			logrus.Infof("[%s] %s %v", t.containerName, line, hitsStr)
		}
	}
	logrus.WithError(s.Err()).Info("TCPDump stdout finished")
}

func (t *TCPDump) readStderr() {
	s := bufio.NewScanner(t.err)
	closedChan := false
	safeClose := func() {
		if !closedChan {
			close(t.listeningStarted)
			closedChan = true
		}
	}
	defer safeClose()
	for s.Scan() {
		line := s.Text()
		logrus.Infof("[%s] ERR: %s", t.containerName, line)
		if strings.Contains(line, "listening") {
			safeClose()
		}
	}
	logrus.WithError(s.Err()).Info("TCPDump stderr finished")
}
