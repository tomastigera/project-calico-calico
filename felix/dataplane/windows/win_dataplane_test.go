// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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

package windataplane_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/felix/config"
	windataplane "github.com/projectcalico/calico/felix/dataplane/windows"
	"github.com/projectcalico/calico/felix/dataplane/windows/hns"
)

var _ = Describe("Constructor test", func() {
	var configParams *config.Config
	var dpConfig windataplane.Config

	JustBeforeEach(func() {
		saveGetKubernetesService := config.GetKubernetesService
		defer func() { config.GetKubernetesService = saveGetKubernetesService }()
		config.GetKubernetesService = func(namespace, name string) (*v1.Service, error) {
			if namespace == "kube-system" && name == "kube-dns" {
				return &v1.Service{Spec: v1.ServiceSpec{
					ClusterIP: "10.96.0.45",
					Ports:     []v1.ServicePort{{Port: 54}},
				}}, nil
			}
			return nil, fmt.Errorf("No such service")
		}
		configParams = config.New()

		dpConfig = windataplane.Config{
			IPv6Enabled:      configParams.Ipv6Support,
			HealthAggregator: nil,

			Hostname:     configParams.FelixHostname,
			VXLANEnabled: configParams.Encapsulation.VXLANEnabled,
			VXLANID:      configParams.VXLANVNI,
			VXLANPort:    configParams.VXLANPort,

			Collector:    nil,
			LookupsCache: nil,

			DNSCacheFile:         configParams.GetDNSCacheFile(),
			DNSCacheSaveInterval: configParams.DNSCacheSaveInterval,
			DNSCacheEpoch:        configParams.DNSCacheEpoch,
			DNSExtraTTL:          configParams.GetDNSExtraTTL(),
			DNSLogsLatency:       configParams.DNSLogsLatency,
			DNSTrustedServers:    configParams.DNSTrustedServers,
		}
	})

	It("should be constructable", func() {
		var dp = windataplane.NewWinDataplaneDriver(hns.API{}, dpConfig, nil)
		Expect(dp).ToNot(BeNil())
	})
})
