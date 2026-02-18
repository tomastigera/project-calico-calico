// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package tproxy

import (
	"bufio"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
)

var proxiedRegexp = regexp.MustCompile(
	`Proxying from (\d+\.\d+\.\d+\.\d+):\d+ to (\d+\.\d+\.\d+\.\d+:\d+) orig dest (\d+\.\d+\.\d+\.\d+:\d+)`)

var acceptedRegexp = regexp.MustCompile(
	`Accepted connection from (\d+\.\d+\.\d+\.\d+):\d+ to (\d+\.\d+\.\d+\.\d+:\d+) orig dest (\d+\.\d+\.\d+\.\d+:\d+)`)

type TProxy struct {
	cmd              *exec.Cmd
	out              io.ReadCloser
	err              io.ReadCloser
	listeningStarted chan struct{}

	cname string
	port  uint16

	proxied  map[ConnKey]int
	accepted map[ConnKey]int
	connLock sync.Mutex
}

type ConnKey struct {
	ClientIP      string
	ServiceIPPort string
	PodIPPort     string
}

func New(f *infrastructure.Felix, port uint16) *TProxy {
	return &TProxy{
		cname: f.Name,
		port:  port,

		listeningStarted: make(chan struct{}),

		proxied:  make(map[ConnKey]int),
		accepted: make(map[ConnKey]int),
	}
}

func (t *TProxy) Start() {
	t.cmd = utils.Command("docker", "exec", t.cname, "tproxy",
		strconv.Itoa(int(t.port)), strconv.Itoa(int(t.port+1)))

	var err error
	t.out, err = t.cmd.StdoutPipe()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	t.err, err = t.cmd.StderrPipe()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	go t.readStdout()
	go t.readStderr()

	err = t.cmd.Start()

	select {
	case <-t.listeningStarted:
	case <-time.After(60 * time.Second):
		ginkgo.Fail("Failed to start tproxy: it never reported that it was listening")
	}

	gomega.Expect(err).NotTo(gomega.HaveOccurred())
}

func (t *TProxy) Stop() {
	err := t.cmd.Process.Kill()
	if err != nil {
		log.WithError(err).Error("Failed to kill tproxy; maybe it failed to start?")
	}
}

func (t *TProxy) readStdout() {
	s := bufio.NewScanner(t.out)
	for s.Scan() {
		line := s.Text()

		log.Infof("[tproxy %s] %s", t.cname, line)
	}
	log.WithError(s.Err()).Info("TProxy stdout finished")
}

func (t *TProxy) readStderr() {
	defer ginkgo.GinkgoRecover()

	s := bufio.NewScanner(t.err)
	closedChan := false
	safeClose := func() {
		if !closedChan {
			close(t.listeningStarted)
			closedChan = true
		}
	}

	listening := false

	defer func() {
		gomega.Expect(listening).To(gomega.BeTrue(), "Proxy did not start to listen")
		safeClose()
	}()

	for s.Scan() {
		line := s.Text()
		log.Infof("[tproxy %s] ERR: %s", t.cname, line)
		if !listening && strings.Contains(line, "Listening") {
			listening = true
			safeClose()
			continue
		}

		m := acceptedRegexp.FindStringSubmatch(line)
		if len(m) == 4 {
			t.acceptedAdd(m[1], m[2], m[3])
			continue
		}
		m = proxiedRegexp.FindStringSubmatch(line)
		if len(m) == 4 {
			t.proxiedAdd(m[1], m[2], m[3])
			continue
		}
	}
	log.WithError(s.Err()).Info("TProxy stderr finished")
}

func (t *TProxy) proxiedAdd(client, pod, service string) {
	t.connLock.Lock()
	t.proxied[ConnKey{ClientIP: client, PodIPPort: pod, ServiceIPPort: service}]++
	t.connLock.Unlock()
}

func (t *TProxy) ProxiedCount(client, pod, service string) int {
	t.connLock.Lock()
	defer t.connLock.Unlock()
	return t.proxied[ConnKey{ClientIP: client, PodIPPort: pod, ServiceIPPort: service}]
}

func (t *TProxy) ProxiedCountFn(client, pod, service string) func() int {
	return func() int {
		return t.ProxiedCount(client, pod, service)
	}
}

func (t *TProxy) acceptedAdd(client, pod, service string) {
	t.connLock.Lock()
	t.accepted[ConnKey{ClientIP: client, PodIPPort: pod, ServiceIPPort: service}]++
	t.connLock.Unlock()
}

func (t *TProxy) AcceptedCount(client, pod, service string) int {
	t.connLock.Lock()
	defer t.connLock.Unlock()
	return t.accepted[ConnKey{ClientIP: client, PodIPPort: pod, ServiceIPPort: service}]
}

func (t *TProxy) AcceptedCountFn(client, pod, service string) func() int {
	return func() int {
		return t.AcceptedCount(client, pod, service)
	}
}
