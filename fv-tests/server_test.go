// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package fv_tests_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"fmt"
	"sync"

	log "github.com/Sirupsen/logrus"

	gob "encoding/gob"
	"net"

	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/typha/pkg/snapcache"
	"github.com/projectcalico/typha/pkg/syncclient"
	"github.com/projectcalico/typha/pkg/syncproto"
	"github.com/projectcalico/typha/pkg/syncserver"
)

var (
	configFoobarBazzBiff = api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: "foobar"},
			Value:    "bazzbiff",
			Revision: "1234",
			TTL:      12,
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	configFoobarDeleted = api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: "foobar"},
			Revision: "1235",
		},
		UpdateType: api.UpdateTypeKVDeleted,
	}
	configFoobar2BazzBiff = api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: "foobar2"},
			Value:    "bazzbiff",
			Revision: "1234",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	configFoobar2Deleted = api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: "foobar2"},
			Revision: "1235",
		},
		UpdateType: api.UpdateTypeKVDeleted,
	}
)

// Tests that rely on starting a real Server (on a real TCP port) in this process.
// We driver the server via a real snapshot cache usnig the snapshot cache's function
// API.
var _ = Describe("With an in-process Server", func() {
	var cacheCxt context.Context
	var cacheCancel context.CancelFunc
	var cache *snapcache.Cache
	var server *syncserver.Server
	var serverCxt context.Context
	var serverCancel context.CancelFunc
	var serverAddr string

	BeforeEach(func() {
		cache = snapcache.New(snapcache.Config{
			// Set the batch size small so we can force new Breadcrumbs easily.
			MaxBatchSize: 10,
			// Reduce the wake up interval from the default to give us faster tear down.
			WakeUpInterval: 50 * time.Millisecond,
		})
		server = syncserver.New(cache, syncserver.Config{
			PingInterval: 10 * time.Second,
			Port:         syncserver.PortRandom,
			DropInterval: 50 * time.Millisecond,
		})
		cacheCxt, cacheCancel = context.WithCancel(context.Background())
		cache.Start(cacheCxt)
		serverCxt, serverCancel = context.WithCancel(context.Background())
		server.Start(serverCxt)
		serverAddr = fmt.Sprintf("127.0.0.1:%d", server.Port())
	})

	It("should choose a port", func() {
		Expect(server.Port()).ToNot(BeZero())
	})

	sendNUpdatesThenInSync := func(n int) map[string]api.Update {
		expectedEndState := map[string]api.Update{}
		cache.OnStatusUpdated(api.ResyncInProgress)
		for i := 0; i < n; i++ {
			update := api.Update{
				KVPair: model.KVPair{
					Key: model.GlobalConfigKey{
						Name: fmt.Sprintf("foo%v", i),
					},
					Value:    fmt.Sprintf("baz%v", i),
					Revision: fmt.Sprintf("%v", i),
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			path, err := model.KeyToDefaultPath(update.Key)
			Expect(err).NotTo(HaveOccurred())
			expectedEndState[path] = update
			cache.OnUpdates([]api.Update{update})
		}
		cache.OnStatusUpdated(api.InSync)
		return expectedEndState
	}

	Describe("with a client connection", func() {
		var clientCxt context.Context
		var clientCancel context.CancelFunc
		var client *syncclient.SyncerClient
		var recorder *stateRecorder

		BeforeEach(func() {
			clientCxt, clientCancel = context.WithCancel(context.Background())
			recorder = &stateRecorder{
				kvs: map[string]api.Update{},
			}
			client = syncclient.New(
				serverAddr,
				"test-version",
				"test-host",
				"test-info",
				recorder,
			)
			err := client.StartContext(clientCxt)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			clientCancel()
			if client != nil {
				log.Info("Waiting for client to shut down.")
				client.Finished.Wait()
				log.Info("Done waiting for client to shut down.")
			}
		})

		// expectClientState asserts that the client eventually reaches the given state.  Then, it
		// simulates a second connection and check that that also converges to the given state.
		expectClientState := func(status api.SyncStatus, kvs map[string]api.Update) {
			// Wait until we reach that state.
			Eventually(recorder.Status).Should(Equal(status))
			Eventually(recorder.KVs).Should(Equal(kvs))

			// Now, a newly-connecting client should also reach the same state.
			log.Info("Starting transient client to read snapshot.")
			newRecorder := &stateRecorder{
				kvs: map[string]api.Update{},
			}
			newClientCxt, cancelNewClient := context.WithCancel(context.Background())
			newClient := syncclient.New(
				serverAddr,
				"test-version",
				"test-host-sampler",
				"test-info",
				newRecorder,
			)
			err := newClient.StartContext(newClientCxt)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				log.Info("Stopping transient client.")
				cancelNewClient()
				newClient.Finished.Wait()
				log.Info("Stopped transient client.")
			}()
			Eventually(newRecorder.Status).Should(Equal(status))
			Eventually(newRecorder.KVs).Should(Equal(kvs))
		}

		It("should drop a bad KV", func() {
			cache.OnStatusUpdated(api.ResyncInProgress)
			cache.OnUpdates([]api.Update{{
				KVPair: model.KVPair{
					// NodeKeys can't be serialized right now.
					Key:      model.NodeKey{Hostname: "foobar"},
					Value:    "bazzbiff",
					Revision: "1234",
					TTL:      12,
				},
				UpdateType: api.UpdateTypeKVNew,
			}})
			cache.OnStatusUpdated(api.InSync)
			expectClientState(api.InSync, map[string]api.Update{})
		})

		It("should pass through a KV and status", func() {
			cache.OnStatusUpdated(api.ResyncInProgress)
			cache.OnUpdates([]api.Update{configFoobarBazzBiff})
			cache.OnStatusUpdated(api.InSync)
			Eventually(recorder.Status).Should(Equal(api.InSync))
			expectClientState(
				api.InSync,
				map[string]api.Update{
					"/calico/v1/config/foobar": configFoobarBazzBiff,
				},
			)
		})

		It("should handle deletions", func() {
			// Create two keys then delete in reverse order.  One of the keys happens to have
			// a default path that is the prefix of the other, just to make sure the Ctrie doesn't
			// accidentally delete the whole prefix.
			cache.OnUpdates([]api.Update{configFoobarBazzBiff})
			cache.OnUpdates([]api.Update{configFoobar2BazzBiff})
			cache.OnStatusUpdated(api.InSync)
			expectClientState(api.InSync, map[string]api.Update{
				"/calico/v1/config/foobar":  configFoobarBazzBiff,
				"/calico/v1/config/foobar2": configFoobar2BazzBiff,
			})
			cache.OnUpdates([]api.Update{configFoobarDeleted})
			expectClientState(api.InSync, map[string]api.Update{
				"/calico/v1/config/foobar2": configFoobar2BazzBiff,
			})
			cache.OnUpdates([]api.Update{configFoobar2Deleted})
			expectClientState(api.InSync, map[string]api.Update{})
		})

		It("should pass through many KVs", func() {
			expectedEndState := sendNUpdatesThenInSync(1000)
			expectClientState(api.InSync, expectedEndState)
		})

		It("should report the correct number of connections", func() {
			expectGaugeValue("typha_connections_active", 1.0)
		})

		It("should report the correct number of connections after killing the client", func() {
			clientCancel()
			expectGaugeValue("typha_connections_active", 0.0)
		})
	})

	Describe("with 100 client connections", func() {
		type clientState struct {
			clientCxt    context.Context
			clientCancel context.CancelFunc
			client       *syncclient.SyncerClient
			recorder     *stateRecorder
		}
		var clientStates []clientState

		BeforeEach(func() {
			clientStates = nil
			for i := 0; i < 100; i++ {
				clientCxt, clientCancel := context.WithCancel(context.Background())
				recorder := &stateRecorder{
					kvs: map[string]api.Update{},
				}
				client := syncclient.New(
					fmt.Sprintf("127.0.0.1:%d", server.Port()),
					"test-version",
					"test-host",
					"test-info",
					recorder,
				)
				client.PanicOnFailure = false
				err := client.StartContext(clientCxt)
				Expect(err).NotTo(HaveOccurred())

				clientStates = append(clientStates, clientState{
					clientCxt:    clientCxt,
					client:       client,
					clientCancel: clientCancel,
					recorder:     recorder,
				})
			}
		})

		AfterEach(func() {
			for _, c := range clientStates {
				c.clientCancel()
				if c.client != nil {
					log.Info("Waiting for client to shut down.")
					c.client.Finished.Wait()
					log.Info("Done waiting for client to shut down.")
				}
			}
		})

		// expectClientState asserts that the client eventually reaches the given state.  Then, it
		// simulates a second connection and check that that also converges to the given state.
		expectClientStates := func(status api.SyncStatus, kvs map[string]api.Update) {
			for _, s := range clientStates {
				// Wait until we reach that state.
				Eventually(s.recorder.Status, 10*time.Second, 200*time.Millisecond).Should(Equal(status))
				Eventually(s.recorder.KVs, 10*time.Second).Should(Equal(kvs))
			}
		}

		It("should drop expected number of connections", func() {
			// Start a goroutine to watch each client and send us a message on the channel when it stops.
			finishedC := make(chan int)
			for _, s := range clientStates {
				go func(s clientState) {
					s.client.Finished.Wait()
					finishedC <- 1
				}(s)
			}

			// We start with 100 connections, set the max to 60 so we kill 40 connections.
			server.SetMaxConns(60)

			// We set the srop interval to 50ms so it should take 2-2.2 seconds (due to jitter) to drop the
			// connections.  Wait 3 seconds so that we verify that the server doesn't go on to kill any
			// more than the target.
			timeout := time.NewTimer(3 * time.Second)
			oneSec := time.NewTimer(1 * time.Second)
			numFinished := 0
		loop:
			for {
				select {
				case <-timeout.C:
					break loop
				case <-oneSec.C:
					// Check the rate is in the right ballpark: after one second we should have
					// dropped approximately 20 clients.
					Expect(numFinished).To(BeNumerically(">", 10))
					Expect(numFinished).To(BeNumerically("<", 30))
				case c := <-finishedC:
					numFinished += c
				}
			}
			// After the timeout we should have dropped exactly the right number of connections.
			Expect(numFinished).To(Equal(40))
			expectGaugeValue("typha_connections_active", 60.0)
		})

		It("should pass through a KV and status", func() {
			cache.OnStatusUpdated(api.ResyncInProgress)
			cache.OnUpdates([]api.Update{configFoobarBazzBiff})
			cache.OnStatusUpdated(api.InSync)
			expectClientStates(
				api.InSync,
				map[string]api.Update{
					"/calico/v1/config/foobar": configFoobarBazzBiff,
				},
			)
		})

		It("should pass through many KVs", func() {
			expectedEndState := sendNUpdatesThenInSync(1000)
			expectClientStates(api.InSync, expectedEndState)
		})

		It("should report the correct number of connections", func() {
			expectGaugeValue("typha_connections_active", 100.0)
		})

		It("should report the correct number of connections after killing the clients", func() {
			for _, c := range clientStates {
				c.clientCancel()
			}
			expectGaugeValue("typha_connections_active", 0.0)
		})

		It("with churn, it should report the correct number of connections after killing the clients", func() {
			// Generate some churn while we disconnect the clients.
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				sendNUpdatesThenInSync(1000)
				wg.Done()
			}()
			defer wg.Wait()
			for _, c := range clientStates {
				c.clientCancel()
				time.Sleep(100 * time.Microsecond)
			}
			expectGaugeValue("typha_connections_active", 0.0)
		})
	})

	AfterEach(func() {
		if server != nil {
			serverCancel()
			log.Info("Waiting for server to shut down")
			server.Finished.Wait()
			log.Info("Done waiting for server to shut down")
		}
		if cache != nil {
			cacheCancel()
		}
	})
})

var _ = Describe("With an in-process Server with short ping timeout", func() {
	var cacheCxt context.Context
	var cacheCancel context.CancelFunc
	var cache *snapcache.Cache
	var server *syncserver.Server
	var serverCxt context.Context
	var serverCancel context.CancelFunc
	var serverAddr string

	BeforeEach(func() {
		cache = snapcache.New(snapcache.Config{
			// Set the batch size small so we can force new Breadcrumbs easily.
			MaxBatchSize: 10,
			// Reduce the wake up interval from the default to give us faster tear down.
			WakeUpInterval: 50 * time.Millisecond,
		})
		server = syncserver.New(cache, syncserver.Config{
			PingInterval: 100 * time.Millisecond,
			PongTimeout:  500 * time.Millisecond,
			Port:         syncserver.PortRandom,
			DropInterval: 50 * time.Millisecond,
		})
		cacheCxt, cacheCancel = context.WithCancel(context.Background())
		cache.Start(cacheCxt)
		serverCxt, serverCancel = context.WithCancel(context.Background())
		server.Start(serverCxt)
		serverAddr = fmt.Sprintf("127.0.0.1:%d", server.Port())
	})

	AfterEach(func() {
		if server != nil {
			serverCancel()
			log.Info("Waiting for server to shut down")
			server.Finished.Wait()
			log.Info("Done waiting for server to shut down")
		}
		if cache != nil {
			cacheCancel()
		}
	})

	It("should disconnect an unresponsive client", func() {
		rawConn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			err := rawConn.Close()
			if err != nil {
				log.WithError(err).Info("Error recorded while closing conn.")
			}
		}()
		w := gob.NewEncoder(rawConn)
		err = w.Encode(syncproto.Envelope{
			Message: syncproto.MsgClientHello{
				Hostname: "me",
				Version:  "test",
				Info:     "test info",
			},
		})
		r := gob.NewDecoder(rawConn)
		Expect(err).NotTo(HaveOccurred())
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				var envelope syncproto.Envelope
				err := r.Decode(&envelope)
				if err != nil {
					return
				}
			}
		}()
		timeout := time.NewTimer(1 * time.Second)
		startTime := time.Now()
		select {
		case <-done:
			// Check we didn't get dropped too soon.
			Expect(time.Since(startTime) >= 500*time.Millisecond).To(BeTrue())
			timeout.Stop()
		case <-timeout.C:
			Fail("timed out waiting for unresponsive client to be dropped")
		}
	})
})

type stateRecorder struct {
	L      sync.Mutex
	status api.SyncStatus
	kvs    map[string]api.Update
	err    error
}

func (r *stateRecorder) KVs() map[string]api.Update {
	r.L.Lock()
	defer r.L.Unlock()

	kvsCpy := map[string]api.Update{}
	for k, v := range r.kvs {
		kvsCpy[k] = v
	}
	return kvsCpy
}

func (r *stateRecorder) Status() api.SyncStatus {
	r.L.Lock()
	defer r.L.Unlock()

	return r.status
}

func (r *stateRecorder) OnUpdates(updates []api.Update) {
	r.L.Lock()
	defer r.L.Unlock()

	for _, u := range updates {
		path, err := model.KeyToDefaultPath(u.Key)
		if err != nil {
			r.err = err
			continue
		}
		if u.Value == nil {
			delete(r.kvs, path)
		} else {
			r.kvs[path] = u
		}
	}
}

func (r *stateRecorder) OnStatusUpdated(status api.SyncStatus) {
	r.L.Lock()
	defer r.L.Unlock()

	r.status = status
}

func getGauge(name string) (float64, error) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return 0, err
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf.Metric[0].GetGauge().GetValue(), nil
		}
	}
	return 0, errors.New("not found")
}

func expectGaugeValue(name string, value float64) {
	Eventually(func() (float64, error) {
		return getGauge(name)
	}).Should(Equal(value))
}
