// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package remotecluster

import (
	"github.com/aws/smithy-go/ptr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("prometheus metrics", func() {
	var (
		statusGauge *prometheus.GaugeVec
		wcb         wrappedCallbacks
	)

	BeforeEach(func() {
		statusGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "remote_cluster_connection_status",
			Help: "0-NotConnecting ,1-Connecting, 2-InSync, 3-ReSyncInProgress, 4-ConfigChangeRestartRequired, 5-ConfigInComplete.",
		}, []string{"remote_cluster_name"})
		prometheus.MustRegister(statusGauge)
		wcb = wrappedCallbacks{statusGauge: statusGauge}
	})

	AfterEach(func() {
		prometheus.Unregister(statusGauge)
	})

	It("should populate remote cluster gaugeVec with Insync status", func() {
		wcb.reportRemoteClusterStatus("cluster-one", model.RemoteClusterInSync)

		mfs, err := prometheus.DefaultGatherer.Gather()
		Expect(err).NotTo(HaveOccurred())

		metricType := io_prometheus_client.MetricType_GAUGE
		Expect(mfs).To(ContainElement(&io_prometheus_client.MetricFamily{
			Name: ptr.String("remote_cluster_connection_status"),
			Help: ptr.String("0-NotConnecting ,1-Connecting, 2-InSync, 3-ReSyncInProgress, 4-ConfigChangeRestartRequired, 5-ConfigInComplete."),
			Type: &metricType,
			Metric: []*io_prometheus_client.Metric{
				{
					Label: []*io_prometheus_client.LabelPair{
						{
							Name:  ptr.String("remote_cluster_name"),
							Value: ptr.String("cluster-one"),
						},
					},
					Gauge: &io_prometheus_client.Gauge{
						Value: ptr.Float64(2),
					},
				},
			},
		}))
	})
})
