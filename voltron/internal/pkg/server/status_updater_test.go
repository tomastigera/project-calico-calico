// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jwt"
	"github.com/felixge/httpsnoop"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	runtimeClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/projectcalico/calico/voltron/internal/pkg/config"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/metrics"
)

var updateErrorPerManagedCluster = map[string]v3.ManagedClusterStatusValue{}

func InterceptStatusUpdate(ctx context.Context, client runtimeClient.WithWatch, obj runtimeClient.Object, opts ...runtimeClient.UpdateOption) error {
	if x, ok := updateErrorPerManagedCluster[obj.GetName()]; ok {
		switch obj := obj.(type) {
		case *v3.ManagedCluster:
			for _, c := range obj.Status.Conditions {
				if c.Type == v3.ManagedClusterStatusTypeConnected && c.Status == x {
					return fmt.Errorf("update %s errors for testing purposes", obj.GetName())
				}
			}
		}
	}
	return client.Update(ctx, obj, opts...)
}

var testStatusConfig = &StatusConfig{
	tickPeriod:     5 * time.Millisecond,
	initialBackoff: time.Millisecond,
	maxBackoff:     20 * time.Millisecond,
	metricsPeriod:  10 * time.Millisecond,
}

var _ = describe("statusUpdater", func(clusterNamespace string) {
	logrus.SetLevel(logrus.DebugLevel)

	var fakeClient runtimeClient.WithWatch
	var ctx context.Context
	var cancel context.CancelFunc
	var statusUpdater StatusUpdater

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())
		scheme := kscheme.Scheme
		err := v3.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		fakeClient = fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{Update: InterceptStatusUpdate}).Build()

		statusUpdater = NewStatusUpdater(ctx, fakeClient, config.Config{
			TenantClaim:     "test_tenant",
			TenantNamespace: clusterNamespace,
		}, testStatusConfig)
	})
	AfterEach(func() {
		cancel()
	})
	When("update fails", func() {
		BeforeEach(func() {
			Expect(fakeClient.Create(context.Background(), &v3.ManagedCluster{
				TypeMeta: metav1.TypeMeta{
					Kind:       v3.KindManagedCluster,
					APIVersion: v3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "update1",
					Namespace: clusterNamespace,
				},
				Status: v3.ManagedClusterStatus{
					Conditions: []v3.ManagedClusterStatusCondition{{
						Type:   v3.ManagedClusterStatusTypeConnected,
						Status: v3.ManagedClusterStatusValueUnknown,
					}},
				},
			})).NotTo(HaveOccurred())
		})
		It("should add to the list of updates to retry", func() {
			updateErrorPerManagedCluster["update1"] = v3.ManagedClusterStatusValueTrue
			statusUpdater.SetStatus("update1", v3.ManagedClusterStatusValueTrue)
			Consistently(func() v3.ManagedClusterStatusValue {
				mc := &v3.ManagedCluster{}
				err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "update1", Namespace: clusterNamespace}, mc)
				if err != nil {
					return v3.ManagedClusterStatusValueTrue
				}
				for _, v := range mc.Status.Conditions {
					if v.Type == v3.ManagedClusterStatusTypeConnected {
						return v.Status
					}
				}
				return v3.ManagedClusterStatusValueTrue
			}, "0.5s").Should(Equal(v3.ManagedClusterStatusValueUnknown), "Managed cluster connection status should be set false when the update succeeds")
			Expect(statusUpdater.IsRetryInProgress("update1")).To(BeTrue())
		})
		It("should retry until the update succeeds", func() {
			updateErrorPerManagedCluster["update1"] = v3.ManagedClusterStatusValueTrue
			statusUpdater.SetStatus("update1", v3.ManagedClusterStatusValueTrue)
			Consistently(func() v3.ManagedClusterStatusValue {
				mc := &v3.ManagedCluster{}
				err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "update1", Namespace: clusterNamespace}, mc)
				if err != nil {
					return v3.ManagedClusterStatusValueTrue
				}
				for _, v := range mc.Status.Conditions {
					if v.Type == v3.ManagedClusterStatusTypeConnected {
						return v.Status
					}
				}
				return v3.ManagedClusterStatusValueTrue
			}, "0.5s").Should(Equal(v3.ManagedClusterStatusValueUnknown), "Managed cluster connection status should be unknown while the update fails")
			Expect(statusUpdater.IsRetryInProgress("update1")).To(BeTrue())
			delete(updateErrorPerManagedCluster, "update1")
			Eventually(func() v3.ManagedClusterStatusValue {
				mc := &v3.ManagedCluster{}
				err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "update1", Namespace: clusterNamespace}, mc)
				if err != nil {
					return v3.ManagedClusterStatusValueFalse
				}
				for _, v := range mc.Status.Conditions {
					if v.Type == v3.ManagedClusterStatusTypeConnected {
						return v.Status
					}
				}
				return v3.ManagedClusterStatusValueFalse
			}, "1s").Should(Equal(v3.ManagedClusterStatusValueTrue), "Managed cluster connection status should be set true when the update succeeds")
			Eventually(func() bool { return statusUpdater.IsRetryInProgress("update1") }, "0.5s").Should(BeFalse())
		})
		It("should clear retry if a new update is successful", func() {
			updateErrorPerManagedCluster["update1"] = v3.ManagedClusterStatusValueTrue
			statusUpdater.SetStatus("update1", v3.ManagedClusterStatusValueTrue)
			Eventually(func() bool {
				return statusUpdater.IsRetryInProgress("update1")
			}, "1s").Should(BeTrue())
			statusUpdater.SetStatus("update1", v3.ManagedClusterStatusValueFalse)
			Eventually(func() v3.ManagedClusterStatusValue {
				mc := &v3.ManagedCluster{}
				err := fakeClient.Get(context.Background(), types.NamespacedName{Name: "update1", Namespace: clusterNamespace}, mc)
				if err != nil {
					return v3.ManagedClusterStatusValueUnknown
				}
				for _, v := range mc.Status.Conditions {
					if v.Type == v3.ManagedClusterStatusTypeConnected {
						return v.Status
					}
				}
				return v3.ManagedClusterStatusValueUnknown
			}, "1s").Should(Equal(v3.ManagedClusterStatusValueFalse), "Managed cluster connection status should be set false")
			Eventually(func() bool {
				return statusUpdater.IsRetryInProgress("update1")
			}, ".5s").Should(BeFalse())
		})
	})

	When("an update is received from voltron for a cluster that doesn't exist in the datastore", func() {
		It("should process the update without crashing", func() {
			clusterName := "non-existent-cluster"
			statusUpdater.SetStatus(clusterName, v3.ManagedClusterStatusValueFalse)

			// This test is checking to see if the goroutines that process this update create a seg-fault.
			// We could check the internal state of the status updater, but we risk concurrent map read/write flakes.
			// Sleeping gives a sufficient window for the seg-fault to trigger and crash the suite.
			time.Sleep(3 * time.Second)
		})
	})
})
var _ = Describe("statusUpdater should provide metrics", func() {
	logrus.SetLevel(logrus.DebugLevel)

	var ctx context.Context
	var cancel context.CancelFunc

	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.NewHandler())

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var authToken jwt.JWT

		fakeAuthSub := r.Header.Get("FakeAuthSub")
		if fakeAuthSub != "" {
			authToken = newFakeJWT(fakeAuthSub)
		}

		var httpSnoopMetrics httpsnoop.Metrics

		onRequestEnd := metrics.OnRequestStart(r, authToken)
		defer onRequestEnd(&httpSnoopMetrics)

		httpSnoopMetrics = httpsnoop.CaptureMetricsFn(w, func(w http.ResponseWriter) {
			mux.ServeHTTP(w, r)
		})
	})

	httpServer := httptest.NewServer(handler)

	scrapeMetrics := func() []string {
		resp, err := http.Get(httpServer.URL + "/metrics")
		ExpectWithOffset(2, err).ToNot(HaveOccurred())
		respBody, err := io.ReadAll(resp.Body)
		ExpectWithOffset(2, err).ToNot(HaveOccurred())
		ExpectWithOffset(2, resp.StatusCode).To(Equal(http.StatusOK))
		lines := strings.Split(string(respBody), "\n")
		var result []string
		for _, line := range lines {
			if strings.HasPrefix(line, "managedcluster_connection_status") {
				result = append(result, line)
			}
		}
		return result
	}

	When("running", func() {
		var sui statusUpdaterImpl
		const wait_dur = ".5s"
		BeforeEach(func() {
			ctx, cancel = context.WithCancel(context.Background())
			sui = statusUpdaterImpl{
				connectionStatuses:      map[string]*managedClusterStatusState{},
				metricsTenant:           "test_tenant",
				managedClusterNamespace: "tenantNs",
				statusHandlerChan:       make(chan managedClusterStatusRequest, 2),
				statusUpdateChan:        make(chan *managedClusterStatusUpdate, 2),
				config:                  testStatusConfig,
				runDone:                 make(chan struct{}),
				listenDone:              make(chan struct{}),
			}
			go sui.run(ctx)
		})
		AfterEach(func() {
			cancel()
		})
		It("should report the number of unsynced statuses", func() {
			sui.SetStatus("update1", v3.ManagedClusterStatusValueTrue)
			Eventually(func() []string {
				return scrapeMetrics()
			}, wait_dur).Should(ContainElement(
				"managedcluster_connection_status_not_in_sync{tenant=\"test_tenant\"} 1",
			))
			sui.SetStatus("update2", v3.ManagedClusterStatusValueFalse)
			Eventually(func() []string {
				return scrapeMetrics()
			}, wait_dur).Should(ContainElement(
				"managedcluster_connection_status_not_in_sync{tenant=\"test_tenant\"} 2",
			))
			sui.SetStatus("update3", v3.ManagedClusterStatusValueTrue)
			Eventually(func() []string {
				return scrapeMetrics()
			}, wait_dur).Should(ContainElement(
				"managedcluster_connection_status_not_in_sync{tenant=\"test_tenant\"} 3",
			))
			// Simulate a successful update
			x := <-sui.statusHandlerChan
			x.finish(updateStateSucceeded, nil)
			Eventually(func() []string {
				return scrapeMetrics()
			}, wait_dur).Should(ContainElement(
				"managedcluster_connection_status_not_in_sync{tenant=\"test_tenant\"} 2",
			))
		})
		It("should report the number failed updates", func() {
			fail := 0
			// Need to get the initial fail count because if other tests ran before this, the fail
			// count wouldn't be at zero. This also means parallelizing test runs would probably
			// break these tests.
			for _, x := range scrapeMetrics() {
				if strings.HasPrefix(x, "managedcluster_connection_status_failed_updates{tenant=\"test_tenant\"}") {
					cnt := strings.TrimPrefix(x, "managedcluster_connection_status_failed_updates{tenant=\"test_tenant\"} ")
					var err error
					fail, err = strconv.Atoi(cnt)
					Expect(err).To(BeNil())

				}
			}
			sui.SetStatus("update1", v3.ManagedClusterStatusValueTrue)
			x := <-sui.statusHandlerChan
			x.finish(updateStateFailed, nil)
			fail++
			Eventually(func() []string {
				return scrapeMetrics()
			}, wait_dur).Should(ContainElement(
				"managedcluster_connection_status_failed_updates{tenant=\"test_tenant\"} " + strconv.Itoa(fail),
			))
			x = <-sui.statusHandlerChan
			x.finish(updateStateFailed, nil)
			fail++
			Eventually(func() []string {
				return scrapeMetrics()
			}, wait_dur).Should(ContainElement(
				"managedcluster_connection_status_failed_updates{tenant=\"test_tenant\"} " + strconv.Itoa(fail),
			))
			x = <-sui.statusHandlerChan
			x.finish(updateStateFailed, nil)
			fail++
			Eventually(func() []string {
				return scrapeMetrics()
			}, wait_dur).Should(ContainElement(
				"managedcluster_connection_status_failed_updates{tenant=\"test_tenant\"} " + strconv.Itoa(fail),
			))
		})
	})
})

var _ = Describe("statusUpdater test sorting", func() {
	logrus.SetLevel(logrus.DebugLevel)

	var ctx context.Context
	var cancel context.CancelFunc

	Context("multiple statuses need to be serviced", func() {
		var sui statusUpdaterImpl
		BeforeEach(func() {
			ctx, cancel = context.WithCancel(context.Background())
			sui = statusUpdaterImpl{
				connectionStatuses:      map[string]*managedClusterStatusState{},
				metricsTenant:           "test_tenant",
				managedClusterNamespace: "tenantNs",
				statusHandlerChan:       make(chan managedClusterStatusRequest, 1),
				statusUpdateChan:        make(chan *managedClusterStatusUpdate, 1),
				config:                  testStatusConfig,
				runDone:                 make(chan struct{}),
				listenDone:              make(chan struct{}),
			}
			// Don't start running becausewe want to setup some connectionStatuses before
			// starting
		})
		AfterEach(func() {
			cancel()
		})
		It("prioritize oldest retryTime first", func() {
			t := time.Now()
			sui.connectionStatuses["old"] = &managedClusterStatusState{
				managedClusterStatusUpdate: managedClusterStatusUpdate{
					status:             v3.ManagedClusterStatusValueTrue,
					managedClusterName: "old",
				},
				backoff:          time.Second,
				retryTime:        t.Add(-time.Second),
				updateState:      updateStateInitial,
				updateInProgress: false,
			}
			sui.connectionStatuses["older"] = &managedClusterStatusState{
				managedClusterStatusUpdate: managedClusterStatusUpdate{
					status:             v3.ManagedClusterStatusValueTrue,
					managedClusterName: "older",
				},
				backoff:          time.Second,
				retryTime:        t.Add(-3 * time.Second),
				updateState:      updateStateInitial,
				updateInProgress: false,
			}
			sui.connectionStatuses["oldest"] = &managedClusterStatusState{
				managedClusterStatusUpdate: managedClusterStatusUpdate{
					status:             v3.ManagedClusterStatusValueTrue,
					managedClusterName: "oldest",
				},
				backoff:          time.Second,
				retryTime:        t.Add(-5 * time.Second),
				updateState:      updateStateInitial,
				updateInProgress: false,
			}
			go sui.run(ctx)

			x := <-sui.statusHandlerChan
			Expect(x.managedClusterName).To(Equal("oldest"))
			x.finish(updateStateSucceeded, nil)

			x = <-sui.statusHandlerChan
			Expect(x.managedClusterName).To(Equal("older"))
			x.finish(updateStateSucceeded, nil)
		})
	})
})

type fakeJWT struct {
	claims map[string]any
}

func newFakeJWT(sub string) *fakeJWT {
	return &fakeJWT{claims: map[string]any{
		"sub": sub,
	}}
}

func (f *fakeJWT) Claims() jwt.Claims {
	return f.claims
}

func (f *fakeJWT) Validate(_ interface{}, _ crypto.SigningMethod, _ ...*jwt.Validator) error {
	panic("implement me")
}

func (f *fakeJWT) Serialize(_ interface{}) ([]byte, error) {
	panic("implement me")
}
