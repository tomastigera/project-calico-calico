// Copyright 2021 Tigera Inc. All rights reserved.

package forwarder

import (
	"context"
	"os"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
	v1scheme "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

var _ = Describe("Event forwarder", func() {
	var (
		ctx            context.Context
		cancel         context.CancelFunc
		storageService *storage.Service
		clusterName    string
		startTime      time.Time
		endTime        time.Time
		totalDocs      int
		lsc            lsclient.MockClient
	)

	BeforeEach(func() {
		now := time.Now()
		startTime = now.Add(time.Duration(-2) * time.Minute)

		clusterName = "cluster"
		err := os.Setenv("CLUSTER_NAME", clusterName)
		Expect(err).ShouldNot(HaveOccurred())

		ctx, cancel = context.WithCancel(context.Background())

		// mock controller runtime client.
		scheme := scheme.Scheme
		err = v1scheme.AddCalicoResourcesToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

		// Populate the linseed client with mock event data. We use a large number
		// of events to ensure that the forwarder properly handles pagination of data.
		// The Linseed client defaults to a page size of 1000.
		totalDocs = 1550
		data := lsv1.List[lsv1.Event]{Items: []lsv1.Event{}}
		for i := 0; i < totalDocs; i++ {
			event := lsv1.Event{
				Time:            lsv1.NewEventDate(time.Now()),
				Type:            "global_alert",
				Description:     "test event fwd",
				Severity:        100,
				Origin:          "event-fwd-resource",
				SourceNamespace: "sample-fwd-ns",
				DestNameAggr:    "sample-dest-*",
				Host:            "node0",
				Record:          map[string]string{"key1": "value1", "key2": "value2"},
			}
			data.Items = append(data.Items, event)
		}
		lsc = lsclient.NewMockClient("", rest.MockResult{Body: data})

		storageService = storage.NewService(lsc, fakeClient, "", time.Duration(1))
		storageService.Run(ctx)

		now = time.Now()
		endTime = now.Add(time.Duration(2) * time.Minute)
	})

	It("should read from events index and dispatches them", func() {
		dispatcher := &MockLogDispatcher{}
		dispatcher.On("Initialize").Return(nil)
		dispatchCount := 0
		dispatcher.On("Dispatch", mock.Anything).Run(func(args mock.Arguments) {
			for _, c := range dispatcher.ExpectedCalls {
				if c.Method == "Dispatch" {
					dispatchCount++
				}
			}
		}).Return(nil)

		eventFwdr := &eventForwarder{
			logger: log.WithFields(log.Fields{
				"context": "eventforwarder",
				"uid":     "fwd-test",
			}),
			once:       sync.Once{},
			cancel:     cancel,
			ctx:        ctx,
			events:     storageService,
			dispatcher: dispatcher,
			config:     &storage.ForwarderConfig{},
		}

		params := lsv1.EventParams{}
		params.SetTimeRange(&lmav1.TimeRange{From: startTime, To: endTime})
		pager := lsclient.NewMockListPager(&params, lsc.Events("").List)
		err := eventFwdr.retrieveAndForward(pager, startTime, endTime, 1, 30*time.Second)
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(func() int { return dispatchCount }).Should(Equal(totalDocs))
	})
})
