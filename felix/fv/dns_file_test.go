// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

package fv_test

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ DNS Policy", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		felix  *infrastructure.Felix
		w      *workload.Workload
		client client.Interface
		infra  infrastructure.DatastoreInfra
		dnsDir string
	)

	BeforeEach(func() {
		felix = nil
		w = nil
		var err error
		dnsDir, err = os.MkdirTemp("", "dnsinfo")
		Expect(err).NotTo(HaveOccurred())
	})

	startWithPersistentFileContent := func(fileContent string) {
		// Populate the DNS info file that Felix will read.
		err := os.WriteFile(path.Join(dnsDir, "dnsinfo.txt"), []byte(fileContent), 0o644)
		Expect(err).NotTo(HaveOccurred())

		// Now start etcd and Felix.
		opts := infrastructure.DefaultTopologyOptions()
		opts.ExtraVolumes[dnsDir] = "/dnsinfo"
		opts.ExtraEnvVars["FELIX_DNSCACHEFILE"] = "/dnsinfo/dnsinfo.txt"
		opts.ExtraEnvVars["FELIX_PolicySyncPathPrefix"] = "/var/run/calico/policysync"
		var tc infrastructure.TopologyContainers
		infra = getInfra()
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)
		felix = tc.Felixes[0]
	}

	gen1000XYZMappings := func() string {
		fileContent := ""
		for i := range 1000 {
			fileContent = fileContent + fmt.Sprintf(`{"LHS":"xyz.com","RHS":"10.10.%v.%v","Expiry":"3019-04-16T00:12:13Z","Type":"ip"}
`,
				(i/254)+1,
				(i%254)+1)
		}
		return fileContent
	}

	triggerCreateXYZIPSet := func() {
		// Create a workload and a DNS policy with domain "xyz.com" so as to trigger
		// creation of the underlying IP set.

		w = workload.Run(felix, "w0", "default", "10.65.0.10", "8055", "tcp")
		w.Configure(client)

		policy := api.NewGlobalNetworkPolicy()
		policy.Name = "allow-xyz"
		order := float64(20)
		policy.Spec.Order = &order
		policy.Spec.Selector = "all()"
		policy.Spec.Egress = []api.Rule{
			{
				Action:      api.Allow,
				Destination: api.EntityRule{Domains: []string{"xyz.com"}},
			},
		}
		_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
	}

	findIPSetWith1000Entries := func() error {
		if os.Getenv("FELIX_FV_ENABLE_BPF") == "true" {
			ipsetsOutput, err := felix.ExecOutput("calico-bpf", "ipsets", "dump")
			if err != nil {
				return err
			}
			numMembers := 0
			for line := range strings.SplitSeq(ipsetsOutput, "\n") {
				if strings.HasPrefix(line, "IP set ") {
					// New IP set.
					numMembers = 0
				} else if strings.TrimSpace(line) != "" {
					// Member in current set.
					numMembers++
				} else {
					// Empty line => end of IP set.
					if numMembers == 1000 {
						return nil
					}
				}
			}
			return fmt.Errorf("No IP set with 1000 members (last=%d) in:\n[%v]", numMembers, ipsetsOutput)
		}

		if NFTMode() {
			for _, count := range felix.NFTSetSizes() {
				if count == 1000 {
					return nil
				}
			}
		} else {
			for name, count := range felix.IPSetSizes() {
				if strings.HasPrefix(name, "cali40d:") && count == 1000 {
					return nil
				}
			}
		}
		return errors.New("No IP set with 1000 members")
	}

	It("programs DNS info from v1 file", func() {
		startWithPersistentFileContent("1\n" + gen1000XYZMappings())
		triggerCreateXYZIPSet()
		Eventually(findIPSetWith1000Entries, "10s", "1s").Should(Succeed())
	})

	It("programs DNS info from v2 file with current epoch declaration", func() {
		startWithPersistentFileContent("2\n{\"Epoch\":0,\"RequiredFeatures\":[\"Epoch\"]}\n" + gen1000XYZMappings())
		triggerCreateXYZIPSet()
		Eventually(findIPSetWith1000Entries, "10s", "1s").Should(Succeed())
	})

	It("ignores DNS info from v2 file with non-current epoch declaration", func() {
		startWithPersistentFileContent("2\n{\"Epoch\":11,\"RequiredFeatures\":[\"Epoch\"]}\n" + gen1000XYZMappings())
		triggerCreateXYZIPSet()
		Consistently(findIPSetWith1000Entries, "10s", "2s").ShouldNot(Succeed())
	})

	It("ignores DNS info from v2 file with unsupported features", func() {
		startWithPersistentFileContent("2\n{\"Epoch\":0,\"RequiredFeatures\":[\"Epoch\",\"NewSemantics\"]}\n" + gen1000XYZMappings())
		triggerCreateXYZIPSet()
		Consistently(findIPSetWith1000Entries, "10s", "2s").ShouldNot(Succeed())
	})

	It("ignores DNS info from file with unsupported version", func() {
		startWithPersistentFileContent("3\n{\"Epoch\":0,\"RequiredFeatures\":[\"Epoch\"]}\n" + gen1000XYZMappings())
		triggerCreateXYZIPSet()
		Consistently(findIPSetWith1000Entries, "10s", "2s").ShouldNot(Succeed())
	})

	DescribeTable("Persistent file errors",
		func(fileContent string) {
			startWithPersistentFileContent(fileContent)

			// Now stop Felix again.
			felix.Stop()
			felix = nil

			// If Felix failed to cope with reading the persistent file, we'd either see
			// the start up call failing like this:
			//
			//    Container failed before being listed in 'docker ps'
			//
			// or the Stop() call would fail because of the container no longer existing.
		},

		Entry("Empty", ""),
		Entry("Just whitespace", `

`),
		Entry("Unsupported version", "6\n"),
		Entry("Supported version, no mappings", "1\n"),
		Entry("Supported version without newline", "1"),
		Entry("Non-JSOF content", `1
gobble de gook {
`),
		Entry("Truncated prematurely", `1
{"LHS":"xyz.com","RHS":"bob.xyz.com","Expiry":"2019-04-16T12:58:07Z","Type":"name"}
{"LHS":"server-5.xyz.com","RHS":"172.17.0.3","Expiry":"2019-04-16T1`),
		Entry("Extra fields present", `1
{"LHS":"xyz.com","RHS":"bob.xyz.com","Expiry":"2019-04-16T12:58:07Z","Type":"name","Bonus":"hey!"}
{"LHS":"server-5.xyz.com","Bonus":"hey!","RHS":"172.17.0.3","Expiry":"2019-04-16T12:58:07Z","Type":"ip"}
`),
		Entry("Mixed JSON and garbage", `1
{"LHS":"xyz.com","RHS":"bob.xyz.com","Expiry":"2019-04-16T12:58:07Z","Type":"name"}
      garbage
{"LHS":"server-5.xyz.com","RHS":"172.17.0.3","Expiry":"2019-04-16T12:58:07Z","Type":"ip"}
`),
	)
})
