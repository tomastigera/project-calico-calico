package waf

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

var _ = Describe("WAF Controller", func() {
	var (
		numOfAlerts = 2
		mockClient  = client.NewMockClient("", rest.MockResult{})
		wac         = &wafAlertController{
			clusterName: "clusterName",
			wafLogs:     newMockWAFLogs(mockClient, "clustername"),
			events:      newMockEvents(mockClient, "clustername", false),
			logsCache:   NewWAFLogsCache(time.Minute),
		}
	)

	Context("Test Waf Controller", func() {
		It("Test Waf ProcessWAFLogs", func() {
			ctx := context.Background()

			err := wac.ProcessWafLogs(ctx)
			Expect(err).ToNot(HaveOccurred())

			now := time.Now()
			params := &v1.WAFLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: wac.lastQueryTimestamp,
						To:   now,
					},
				},
			}

			logs, err := wac.events.List(ctx, params)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(logs.Items)).To(Equal(numOfAlerts))

		})
	})

	Context("Test WAF Caching", func() {
		It("Test WAF caching", func() {
			ctx := context.Background()

			err := wac.ProcessWafLogs(ctx)
			Expect(err).ToNot(HaveOccurred())

			now := time.Now()
			params := &v1.WAFLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: wac.lastQueryTimestamp,
						To:   now,
					},
				},
			}

			logs, err := wac.events.List(ctx, params)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(logs.Items)).To(Equal(numOfAlerts))

			// run the process again to make sure no new events are generated
			err = wac.ProcessWafLogs(ctx)
			Expect(err).ToNot(HaveOccurred())

			params.TimeRange.To = time.Now()

			logs2, err := wac.events.List(ctx, params)
			Expect(err).ToNot(HaveOccurred())
			// no new Events should have been created
			Expect(len(logs2.Items)).To(Equal(numOfAlerts))

		})

		It("Test WAF caching fail", func() {

			mockClient2 := client.NewMockClient("", rest.MockResult{})
			wafAlertCtr := &wafAlertController{
				clusterName: "clusterName",
				wafLogs:     newMockWAFLogs(mockClient2, "clustername"),
				events:      newMockEvents(mockClient2, "clustername", true),
				logsCache:   NewWAFLogsCache(time.Minute),
			}
			ctx := context.Background()

			err := wafAlertCtr.ProcessWafLogs(ctx)
			Expect(err).To(HaveOccurred())

			now := time.Now()
			params := &v1.WAFLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: wac.lastQueryTimestamp,
						To:   now,
					},
				},
			}

			logs, err := wafAlertCtr.events.List(ctx, params)
			Expect(err).ToNot(HaveOccurred())

			Expect(len(logs.Items)).To(Equal(0))

			// run the process again to make sure new events are generated
			err = wafAlertCtr.ProcessWafLogs(ctx)
			Expect(err).ToNot(HaveOccurred())

			params.TimeRange.To = time.Now()

			logs2, err := wafAlertCtr.events.List(ctx, params)
			Expect(err).ToNot(HaveOccurred())
			// new Events should have been created
			Expect(len(logs2.Items)).To(Equal(numOfAlerts))

		})
	})

})
