// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package handlers_test

import (
	"context"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/es-gateway/pkg/handlers"
	"github.com/projectcalico/calico/es-gateway/pkg/metrics"
	"github.com/projectcalico/calico/es-gateway/pkg/middlewares"
)

type collectorMocker struct {
	mock.Mock
	metrics.Collector
}

func (c *collectorMocker) CollectLogBytesWritten(clusterID string, bytes float64) error {
	c.Called(clusterID, bytes)
	return nil
}

func (c *collectorMocker) CollectLogBytesRead(clusterID string, bytes float64) error {
	c.Called(clusterID, bytes)
	return nil
}

func (c *collectorMocker) Serve(address string) error {
	c.Called(address)
	return nil
}

var _ = Describe("Test the elastic response hook", func() {

	const clusterID = "my-cluster"

	var collector collectorMocker

	BeforeEach(func() {
		collector = collectorMocker{}
	})

	It("should call the metrics collector", func() {

		collector.On("CollectLogBytesRead", clusterID, mock.Anything).Return(nil)
		collector.On("CollectLogBytesWritten", clusterID, mock.Anything).Return(nil)

		fn := handlers.ElasticModifyResponseFunc(&collector)
		req := &http.Request{RequestURI: "/some-uri", ContentLength: 25}
		req = req.WithContext(context.WithValue(context.TODO(), middlewares.ClusterIDKey, clusterID))
		resp := &http.Response{
			Request:       req,
			ContentLength: 50,
			StatusCode:    200,
		}
		Expect(fn(resp)).NotTo(HaveOccurred())
	})
})
