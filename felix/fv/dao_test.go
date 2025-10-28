// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package fv_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	options2 "github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("drop action override tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPortStr = "8055"
	)

	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		ep1_1  *workload.Workload // Workloads on Felix0
		client client.Interface
	)

	BeforeEach(func() {
		iOpts := []infrastructure.CreateOption{}
		infra = getInfra(iOpts...)

		options := infrastructure.DefaultTopologyOptions()
		options.IPIPMode = api.IPIPModeNever
		options.EnableIPv6 = false
		tc, client = infrastructure.StartSingleNodeTopology(options, infra)

		// Install a default profile that deny all ingress in the absence of any Policy.
		err := infra.AddDefaultDeny()
		Expect(err).NotTo(HaveOccurred())

		// Create workload on host 1 (Felix0).
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
		ep1_1.ConfigureInInfra(infra)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				if NFTMode() {
					logNFTDiags(felix)
				} else {
					felix.Exec("iptables-save", "-c")
				}
			}
		}

		ep1_1.Stop()
		tc.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	Context("should create a LOG rule when the LogAndDrop action is used.", func() {
		BeforeEach(func() {
			if BPFMode() {
				Skip("Skipping for BPF dataplane.")
			}

			fc := api.NewFelixConfiguration()
			fc.SetName("default")
			fc.Spec.DropActionOverride = "LogAndDrop"

			fc, err := client.FelixConfigurations().Create(context.Background(), fc, options2.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		})
		DescribeTable("Test DropActionOverride LogAndDrop creates LOG rule",
			func(expectedComment string) {
				params := []string{"iptables-save", "-c"}
				expectedRuleRegexp := fmt.Sprintf(`-m comment --comment "%s".*-j LOG --log-prefix "calico-drop.*: "`, expectedComment)
				if NFTMode() {
					params = []string{"nft", "list", "ruleset"}
					expectedRuleRegexp = fmt.Sprintf(`log prefix "calico-drop.*".*%s`, expectedComment)
				}
				getRules := func() string {
					output, _ := tc.Felixes[0].ExecOutput(params...)
					return output
				}

				Eventually(getRules, 10*time.Second, 100*time.Millisecond).Should(MatchRegexp(expectedRuleRegexp))
				Consistently(getRules, 5*time.Second, 100*time.Millisecond).Should(MatchRegexp(expectedRuleRegexp))
			},
			Entry("End of tier", "End of tier .*. Drop if no policies passed packet"),
			Entry("End of profile", "Drop if no profiles matched"),
		)
	})
})
