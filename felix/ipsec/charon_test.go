// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.

package ipsec_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bronze1man/goStrongswanVici"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/calico/felix/ipsec"
	"github.com/projectcalico/calico/felix/testutils"
)

const TestPSK = "top-secret"

var _ = Describe("Charon", func() {
	var charon *CharonIKEDaemon
	var childExitedC chan struct{}
	var totalSleep time.Duration
	var afterCalled chan struct{}
	var afterDone chan time.Time

	var cmd *mockCmd
	var runProcErr error
	var runProcExecPath string
	var runProcDoneWG *sync.WaitGroup

	var cleanUpCharonErr error

	var mockCharon *mockCharon

	runProc := func(execPath string, doneWG *sync.WaitGroup) (CharonCommand, error) {
		runProcExecPath = execPath
		runProcDoneWG = doneWG

		if runProcErr != nil {
			return nil, runProcErr
		}
		return cmd, nil
	}

	cleanUpCharon := func() error {
		return cleanUpCharonErr
	}

	sleep := func(d time.Duration) {
		totalSleep += d
	}

	BeforeEach(func() {
		cmd = &mockCmd{
			StopWait: make(chan struct{}),
			Signals:  make(chan os.Signal, 2),
		}
		runProcErr = nil
		runProcExecPath = ""
		runProcDoneWG = nil
		totalSleep = 0
		childExitedC = make(chan struct{})

		// Make sure our mock after function closes over a unique channel so that we can't get
		// cross-talk between tests if the test ends before after gets called.
		afterCalledFresh := make(chan struct{})
		afterCalled = afterCalledFresh

		afterDone = make(chan time.Time)
		mockCharon = newMockCharon()
		charon = NewCharonWithShims(
			"esp-algo",
			"ike-algo",
			10*time.Second,
			func() {
				close(childExitedC)
			},
			runProc,
			mockCharon.NewClient,
			sleep,
			func(d time.Duration) <-chan time.Time {
				close(afterCalledFresh)
				return afterDone
			},
			cleanUpCharon,
		)
	})

	Context("after starting the daemon", func() {
		var ctx context.Context
		var cancel context.CancelFunc
		var doneWG *sync.WaitGroup

		BeforeEach(func() {
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			doneWG = &sync.WaitGroup{}
			Expect(charon.Start(ctx, doneWG)).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cancel()

			select {
			case <-afterDone:
			default:
				close(afterDone)
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				doneWG.Wait()
			}()
			Eventually(done).Should(BeClosed())
		})

		It("should start the daemon", func() {
			Expect(runProcExecPath).To(Equal("/usr/lib/ipsec/charon"))
			Expect(runProcDoneWG).To(Equal(doneWG))
		})

		It("shouldn't trigger the child exit func by default", func() {
			Consistently(childExitedC).ShouldNot(BeClosed())
		})

		It("after the charon dies, it should trigger the child exit func", func() {
			close(cmd.StopWait)
			Eventually(childExitedC).Should(BeClosed())
		})

		It("should gracefully shut down the charon after the context is canceled", func() {
			cancel()
			Eventually(cmd.Signals).Should(Receive(Equal(syscall.SIGTERM)))
			close(cmd.StopWait)

			done := make(chan struct{})
			go func() {
				doneWG.Wait()
				close(done)
			}()

			Eventually(done).Should(BeClosed())
			Consistently(cmd.Signals).ShouldNot(Receive())
		})

		It("should kill the charon if it fails to exit", func() {
			cancel()

			done := make(chan struct{})
			go func() {
				doneWG.Wait()
				close(done)
			}()

			Eventually(cmd.Signals).Should(Receive(Equal(syscall.SIGTERM)))

			// After the SIGTERM, it should call After and wait for a timeout.
			Eventually(afterCalled).Should(BeClosed(), "never called (our mock of) time.After()")
			Expect(done).NotTo(BeClosed())

			// Simulate the timeout finishing.
			close(afterDone)
			// Should escalate to kill.
			Eventually(cmd.Signals).Should(Receive(Equal(syscall.SIGKILL)))
			Eventually(done).Should(BeClosed())
		})

		It("should panic if given an invalid conn", func() {
			Expect(func() {
				_ = charon.LoadConnection("", "")
			}).To(Panic())
		})

		const numToleratedErrors = 3

		for numErrors := 0; numErrors < numToleratedErrors; numErrors++ {
			numErrors := numErrors // Fresh variable to capture on each loop.
			Describe(fmt.Sprintf("with %d errors queued up", numErrors), func() {
				BeforeEach(func() {
					for _, e := range []string{"LoadConn", "UnloadConn", "LoadShared", "UnloadShared"} {
						mockCharon.Errors.QueueNErrors(e, numErrors)
					}
				})

				It("should load and unload a connection", func() {
					err := charon.LoadConnection("10.0.0.1", "10.0.0.2")
					Expect(err).NotTo(HaveOccurred())
					Expect(mockCharon.IKEConfig).To(Equal(map[string]goStrongswanVici.IKEConf{
						"10.0.0.1-10.0.0.2": {
							LocalAddrs:  []string{"10.0.0.1"},
							RemoteAddrs: []string{"10.0.0.2"},
							Proposals:   []string{"ike-algo"},
							Version:     "2",
							Encap:       "no",
							KeyingTries: "0",
							LocalAuth:   goStrongswanVici.AuthConf{AuthMethod: "psk"},
							RemoteAuth:  goStrongswanVici.AuthConf{AuthMethod: "psk"},
							Pools:       nil,
							Children: map[string]goStrongswanVici.ChildSAConf{
								"10.0.0.1-10.0.0.2": {
									Local_ts:      []string{"0.0.0.0/0"},
									Remote_ts:     []string{"0.0.0.0/0"},
									ESPProposals:  []string{"esp-algo"},
									StartAction:   "start",
									CloseAction:   "none",
									ReqID:         "13242816",
									RekeyTime:     "10s",
									Mode:          "tunnel",
									InstallPolicy: "no",
									HWOffload:     "auto",
								},
							},
							Mobike: "no",
						},
					}))

					err = charon.UnloadCharonConnection("10.0.0.1", "10.0.0.2")
					Expect(err).NotTo(HaveOccurred())
					Expect(mockCharon.IKEConfig).To(BeEmpty())
				})

				It("should load and unload a key", func() {
					err := charon.LoadSharedKey("10.0.0.2", TestPSK)
					Expect(err).NotTo(HaveOccurred())
					Expect(mockCharon.Keys).To(Equal(map[string]string{
						"10.0.0.2": TestPSK,
					}))

					err = charon.UnloadSharedKey("10.0.0.2")
					Expect(err).NotTo(HaveOccurred())
					Expect(mockCharon.Keys).To(BeEmpty())
				})
			})
		}
		Describe("with too many errors queued up", func() {
			BeforeEach(func() {
				for _, e := range []string{"LoadConn", "UnloadConn", "LoadShared", "UnloadShared"} {
					mockCharon.Errors.QueueNErrors(e, numToleratedErrors+1)
				}
			})

			It("should give up loading a connection", func() {
				err := charon.LoadConnection("10.0.0.1", "10.0.0.2")
				Expect(err).To(HaveOccurred())
			})

			It("should give up unloading a connection", func() {
				err := charon.UnloadCharonConnection("10.0.0.1", "10.0.0.2")
				Expect(err).To(HaveOccurred())
			})

			It("should give up loading a key", func() {
				err := charon.LoadSharedKey("10.0.0.2", TestPSK)
				Expect(err).To(HaveOccurred())
			})

			It("should give up unloading a key", func() {
				err := charon.UnloadSharedKey("10.0.0.2")
				Expect(err).To(HaveOccurred())
			})
		})
	})
})

var _ = Context("CopyOutputToLog", func() {
	It("should read to the end then signal its waitgroup", func() {
		var wg sync.WaitGroup
		r := strings.NewReader("line 1\nline 2\nline 3\n")
		wg.Add(1)
		CopyOutputToLog("test", r, &wg)
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		Eventually(done).Should(BeClosed())
		Expect(r.Len()).To(BeZero())
	})
})

type mockCmd struct {
	StopWait chan struct{}
	Signals  chan os.Signal
}

func (c *mockCmd) Wait() error {
	<-c.StopWait
	return &exec.ExitError{}
}

func (c *mockCmd) Signal(signal os.Signal) error {
	c.Signals <- signal
	return nil
}

func (c *mockCmd) Kill() error {
	c.Signals <- os.Kill
	return nil
}

type mockCharon struct {
	Errors testutils.ErrorProducer

	clientOpen bool

	IKEConfig map[string]goStrongswanVici.IKEConf
	Keys      map[string]string
}

func newMockCharon() *mockCharon {
	return &mockCharon{
		Errors:    testutils.NewErrorProducer(),
		IKEConfig: map[string]goStrongswanVici.IKEConf{},
		Keys:      map[string]string{},
	}
}

func (c *mockCharon) NewClient(ctx context.Context, viciUri Uri) (VICIClient, error) {
	log.Info("Opening VICI client")
	Expect(viciUri).To(Equal(Uri{"unix", "/var/run/charon.vici"}))
	Expect(c.clientOpen).To(BeFalse(), "VICI client already open")
	c.clientOpen = true
	return c, nil
}

func (c *mockCharon) Close() error {
	log.Info("Closing VICI client")
	Expect(c.clientOpen).To(BeTrue(), "VICI client Close() called when already closed")
	c.clientOpen = false
	return nil
}

func (c *mockCharon) LoadConn(conn *map[string]goStrongswanVici.IKEConf) error {
	if err := c.Errors.NextError("LoadConn"); err != nil {
		return err
	}

	Expect(conn).ToNot(BeNil())
	Expect(*conn).To(HaveLen(1))
	for k, v := range *conn {
		c.IKEConfig[k] = v
	}

	return nil
}

func (c *mockCharon) UnloadConn(r *goStrongswanVici.UnloadConnRequest) error {
	if err := c.Errors.NextError("UnloadConn"); err != nil {
		return err
	}

	Expect(r).NotTo(BeNil())
	Expect(r.Name).NotTo(Equal(""))
	Expect(c.IKEConfig).To(HaveKey(r.Name))
	delete(c.IKEConfig, r.Name)

	return nil
}

func (c *mockCharon) LoadShared(key *goStrongswanVici.Key) error {
	if err := c.Errors.NextError("LoadShared"); err != nil {
		return err
	}

	Expect(key).NotTo(BeNil())
	Expect(key.ID).NotTo(Equal(""))
	Expect(key.Owners).To(ConsistOf(key.ID), "Expected key owner to be used as key ID")
	Expect(key.Data).To(Equal(TestPSK))
	Expect(key.Typ).To(Equal("IKE"))

	c.Keys[key.ID] = key.Data

	return nil
}

func (c *mockCharon) UnloadShared(key *goStrongswanVici.UnloadKeyRequest) error {
	Expect(key).NotTo(BeNil())

	if err := c.Errors.NextError("UnloadShared"); err != nil {
		return err
	}

	Expect(c.Keys).To(HaveKey(key.ID))
	delete(c.Keys, key.ID)

	return nil
}
