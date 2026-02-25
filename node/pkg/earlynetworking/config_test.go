package earlynetworking_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/node/pkg/earlynetworking"
)

var _ = DescribeTable("Read EarlyNetworkConfiguration",
	func(configString string, expectedConfigSpec earlynetworking.EarlyNetworkConfigurationSpec) {
		cfg, err := os.CreateTemp("/tmp", "earlynetworkcfg*.yaml")
		Expect(err).NotTo(HaveOccurred(), "Couldn't create a temp file. Test is invalidated.")

		_, err = cfg.WriteString(configString)
		Expect(err).NotTo(HaveOccurred(), "Couldn't write YAML to test-file. Test is invalidated.")

		err = cfg.Close()
		Expect(err).NotTo(HaveOccurred(), "Couldn't close YAML file after encoding. Test is invalidated.")

		enc, err := earlynetworking.GetEarlyNetworkConfig(cfg.Name())
		Expect(err).NotTo(HaveOccurred(), "Failed to read the expected EarlyNetworkConfiguration")
		Expect(enc.Spec).To(BeEquivalentTo(expectedConfigSpec), "The EarlyNetworkConfiguration we read differs from the expected EarlyNetworkConfiguration")
	},
	Entry("Legacy flags set to true, misc. node-configs",
		`apiVersion: projectcalico.org/v3
kind: EarlyNetworkConfiguration
spec:
  legacy:
    nodeIPFromDefaultRoute: true
    unconditionalDefaultRouteProgramming: true
  platform: openshift
  nodes:
    # Rack A
    - interfaceAddresses:
        - 172.31.11.2
        - 172.31.12.2
      stableAddress:
        address: 172.31.10.2
      asNumber: 65001
      peerings:
        - peerIP: 172.31.11.1
        - peerIP: 172.31.12.1
    - interfaceAddresses:
        - 172.31.11.3
        - 172.31.12.3
      stableAddress:
        address: 172.31.10.3
      asNumber: 65001
      peerings:
        - peerIP: 172.31.11.1
        - peerIP: 172.31.12.1

`,
		earlynetworking.EarlyNetworkConfigurationSpec{
			Legacy: earlynetworking.LegacyConfig{
				NodeIPFromDefaultRoute:               true,
				UnconditionalDefaultRouteProgramming: true,
			},
			Platform: "openshift",
			Nodes: []earlynetworking.ConfigNode{
				{
					InterfaceAddresses: []string{"172.31.11.2", "172.31.12.2"},
					StableAddress:      earlynetworking.ConfigStableAddress{Address: "172.31.10.2"},
					ASNumber:           65001,
					Peerings: []earlynetworking.ConfigPeering{
						{PeerIP: "172.31.11.1"},
						{PeerIP: "172.31.12.1"},
					},
				},
				{
					InterfaceAddresses: []string{"172.31.11.3", "172.31.12.3"},
					StableAddress:      earlynetworking.ConfigStableAddress{Address: "172.31.10.3"},
					ASNumber:           65001,
					Peerings: []earlynetworking.ConfigPeering{
						{PeerIP: "172.31.11.1"},
						{PeerIP: "172.31.12.1"},
					},
				},
			},
		},
	),

	Entry("Legacy field present but inner fields unset, and misc. node-configs",
		`apiVersion: projectcalico.org/v3
kind: EarlyNetworkConfiguration
spec:
  legacy:
  platform: openshift
  nodes:
    # Rack A
    - interfaceAddresses:
        - 172.31.11.2
        - 172.31.12.2
      stableAddress:
        address: 172.31.10.2
      asNumber: 65001
      peerings:
        - peerIP: 172.31.11.1
        - peerIP: 172.31.12.1
    - interfaceAddresses:
        - 172.31.11.3
        - 172.31.12.3
      stableAddress:
        address: 172.31.10.3
      asNumber: 65001
      peerings:
        - peerIP: 172.31.11.1
        - peerIP: 172.31.12.1

`,
		earlynetworking.EarlyNetworkConfigurationSpec{
			Legacy: earlynetworking.LegacyConfig{
				NodeIPFromDefaultRoute:               false,
				UnconditionalDefaultRouteProgramming: false,
			},
			Platform: "openshift",
			Nodes: []earlynetworking.ConfigNode{
				{
					InterfaceAddresses: []string{"172.31.11.2", "172.31.12.2"},
					StableAddress:      earlynetworking.ConfigStableAddress{Address: "172.31.10.2"},
					ASNumber:           65001,
					Peerings: []earlynetworking.ConfigPeering{
						{PeerIP: "172.31.11.1"},
						{PeerIP: "172.31.12.1"},
					},
				},
				{
					InterfaceAddresses: []string{"172.31.11.3", "172.31.12.3"},
					StableAddress:      earlynetworking.ConfigStableAddress{Address: "172.31.10.3"},
					ASNumber:           65001,
					Peerings: []earlynetworking.ConfigPeering{
						{PeerIP: "172.31.11.1"},
						{PeerIP: "172.31.12.1"},
					},
				},
			},
		},
	),
)
