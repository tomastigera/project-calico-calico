// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package alert_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/deep-packet-inspection/pkg/alert"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

var _ = Describe("Alert Forwarder", func() {
	var mockLinseedClient lsclient.MockClient
	var ctx context.Context

	BeforeEach(func() {
		mockLinseedClient = lsclient.NewMockClient("")
		ctx = context.Background()
	})

	It("should not retry after successfully indexing the document to ElasticSearch", func() {
		forwarder, err := alert.NewForwarder(mockLinseedClient, 1*time.Second, "cluster")
		forwarder.Run(ctx)
		Expect(err).ShouldNot(HaveOccurred())

		mockLinseedClient.SetResults(rest.MockResult{
			Body: v1.BulkResponse{
				Total:     1,
				Succeeded: 1,
			},
		})
		forwarder.Forward(v1.Event{})
	})

	It("should retry sending the document on connection error", func() {
		mockLinseedClient.SetResults(rest.MockResult{
			Body: v1.BulkResponse{
				Total:  1,
				Failed: 1,
			},
		})

		forwarder, err := alert.NewForwarder(mockLinseedClient, 1*time.Second, "cluster")
		forwarder.Run(ctx)
		Expect(err).ShouldNot(HaveOccurred())

		forwarder.Forward(v1.Event{})
	})
})
