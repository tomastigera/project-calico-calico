// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/dns"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const nameserverPrefix = "nameserver "

var localNameservers []string

func GetLocalNameservers() (nameservers []string) {
	if localNameservers == nil {
		// Find out what Docker puts in a container's /etc/resolv.conf.
		resolvConf, err := utils.GetCommandOutput("docker", "run", "--rm", utils.Config.FelixImage, "cat", "/etc/resolv.conf")
		Expect(err).NotTo(HaveOccurred())
		for resolvConfLine := range strings.SplitSeq(resolvConf, "\n") {
			if strings.HasPrefix(resolvConfLine, nameserverPrefix) {
				localNameservers = append(localNameservers, strings.TrimSpace(resolvConfLine[len(nameserverPrefix):]))
			}
		}
		log.Infof("Discovered nameservers: %v", localNameservers)
	}
	return localNameservers
}

func getDNSLogs(logFile string) ([]string, error) {
	fileExists, err := BeARegularFile().Match(logFile)
	if err != nil {
		return nil, err
	}
	if !fileExists {
		return nil, fmt.Errorf("Expected DNS log file %v does not exist", logFile)
	}
	logBytes, err := os.ReadFile(logFile)
	if err != nil {
		return nil, err
	}
	var logs []string
	for log := range strings.SplitSeq(string(logBytes), "\n") {
		// Filter out empty strings returned by strings.Split.
		if log != "" {
			logs = append(logs, log)
		}
	}
	return logs, nil
}

var _ = infrastructure.DatastoreDescribe("DNS Policy", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	defineDNSPolicyTests(getInfra, false, false)
})

// These tests rely solely on BPF making the updates to the policy iptables.
// Domainstore keep processing the packet, so that it maintains its mappings,
// ipsets manager can query which domains belong to which ipsets (which is
// necessary to build the bpf structures, but it does not receive ip updates and
// thus does not write the IPs in the sets.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Zero latency DNS Policy with no updates from felix to ipsets", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	if NFTMode() {
		return
	}
	defineDNSPolicyTests(getInfra, true, false)
})

// This is the new default for BPF, precessing in BPF, with fixups from Felix
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Zero latency DNS Policy", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	if NFTMode() {
		return
	}
	defineDNSPolicyTests(getInfra, true, true)
})

func defineDNSPolicyTests(getInfra infrastructure.InfraFactory, zeroLatency, setsUpdateFromFelix bool) {
	var (
		dnsServer        *containers.Container
		externalWorkload *containers.Container
		tc               infrastructure.TopologyContainers
		client           client.Interface
		infra            infrastructure.DatastoreInfra
		w                [1]*workload.Workload
		dnsDir           string
		dnsServerIP      string
		// Path to the save file from the point of view inside the Felix container.
		// (Whereas dnsDir is the directory outside the container.)
		saveFile                       string
		saveFileMappedOutsideContainer bool

		enableLogs    bool
		enableLatency bool
		dnsMode       string
	)

	msWildcards := []string{"fake-microsoft.*.com", "*.fake-microsoft.test"}
	if zeroLatency {
		msWildcards = []string{"*.fake-microsoft.test"}
		dnsMode = string(v3.BPFDNSPolicyModeInline)
		if !BPFMode() {
			dnsMode = string(v3.DNSPolicyModeInline)
		}
	}

	logAndReport := func(out string, err error) error {
		log.WithError(err).Infof("test-dns said:\n%v", out)
		return err
	}

	wgetMicrosoftErr := func() error {
		out, err := w[0].ExecCombinedOutput("test-dns", "-", "www.fake-microsoft.test", fmt.Sprintf("--dns-server=%s:%d", dnsServerIP, 53))
		return logAndReport(out, err)
	}

	canWgetMicrosoft := func() {
		Eventually(wgetMicrosoftErr, "10s", "1s").ShouldNot(HaveOccurred())
		Consistently(wgetMicrosoftErr, "4s", "1s").ShouldNot(HaveOccurred())
	}

	cannotWgetMicrosoft := func() {
		Eventually(wgetMicrosoftErr, "10s", "1s").Should(HaveOccurred())
		Consistently(wgetMicrosoftErr, "4s", "1s").Should(HaveOccurred())
	}

	hostWgetMicrosoftErr := func() error {
		out, err := tc.Felixes[0].ExecCombinedOutput("test-dns", "-", "www.fake-microsoft.test", fmt.Sprintf("--dns-server=%s:%d", dnsServerIP, 53))
		return logAndReport(out, err)
	}

	hostCanWgetMicrosoft := func() {
		Eventually(hostWgetMicrosoftErr, "10s", "1s").ShouldNot(HaveOccurred())
		Consistently(hostWgetMicrosoftErr, "4s", "1s").ShouldNot(HaveOccurred())
	}

	hostCannotWgetMicrosoft := func() {
		Eventually(hostWgetMicrosoftErr, "10s", "1s").Should(HaveOccurred())
		Consistently(hostWgetMicrosoftErr, "4s", "1s").Should(HaveOccurred())
	}

	getLastMicrosoftALog := func() (lastLog string) {
		dnsLogs, err := getDNSLogs(path.Join(dnsDir, "dns.log"))
		if err != nil {
			log.Infof("Error getting DNS logs: %v", err)
			return // empty string, so won't match anything that higher levels are looking for
		}
		for _, log := range dnsLogs {
			if strings.Contains(log, `"qname":"www.fake-microsoft.test"`) && strings.Contains(log, `"qtype":"A"`) {
				lastLog = log
			}
		}
		return
	}

	BeforeEach(func() {
		infra = getInfra()
		saveFile = "/dnsinfo/dnsinfo.txt"
		saveFileMappedOutsideContainer = true
		enableLogs = true
		enableLatency = true
	})

	JustBeforeEach(func() {
		opts := infrastructure.DefaultTopologyOptions()
		var err error
		dnsDir, err = os.MkdirTemp("", "dnsinfo")
		Expect(err).NotTo(HaveOccurred())

		// Instead of relying on external websites for DNS tests, we use an internally hosted HTTP service,
		// and internal dns server, making functional validation tests more self-contained and reliable.
		externalWorkload = infrastructure.StartExternalWorkloads(infra, "dns-external-workload", 1)[0]
		dnsRecords := map[string][]dns.RecordIP{
			"www.fake-microsoft.test": {{TTL: 20, IP: externalWorkload.IP}},
		}
		dnsServer = dns.StartServer(infra, dnsRecords)
		dnsServerIP = dnsServer.IP

		opts.FelixLogSeverity = "Debug"
		opts.ExtraVolumes[dnsDir] = "/dnsinfo"
		opts.ExtraEnvVars["FELIX_DNSCACHEFILE"] = saveFile
		// For this test file, configure DNSCacheSaveInterval to be much longer than any
		// test duration, so we can be sure that the writing of the dnsinfo.txt file is
		// triggered by shutdown instead of by a periodic timer.
		opts.ExtraEnvVars["FELIX_DNSCACHESAVEINTERVAL"] = "3600"
		opts.ExtraEnvVars["FELIX_DNSTRUSTEDSERVERS"] = dnsServerIP
		opts.ExtraEnvVars["FELIX_PolicySyncPathPrefix"] = "/var/run/calico/policysync"
		opts.ExtraEnvVars["FELIX_DNSLOGSFILEDIRECTORY"] = "/dnsinfo"
		opts.ExtraEnvVars["FELIX_DNSLOGSFLUSHINTERVAL"] = "1"
		opts.ExtraEnvVars["FELIX_BPFLOGLEVEL"] = "Debug"
		if dnsMode != "" {
			if !BPFMode() {
				if NFTMode() {
					opts.ExtraEnvVars["FELIX_NFTABLESDNSPOLICYMODE"] = dnsMode
				} else {
					opts.ExtraEnvVars["FELIX_DNSPOLICYMODE"] = dnsMode
				}
			} else {
				opts.ExtraEnvVars["FELIX_BPFDNSPOLICYMODE"] = dnsMode
			}
		}
		if enableLogs {
			// Default for this is false.  Set "true" to enable.
			opts.ExtraEnvVars["FELIX_DNSLOGSFILEENABLED"] = "true"
		}
		if !enableLatency {
			// Default for this is true.  Set "false" to disable.
			opts.ExtraEnvVars["FELIX_DNSLOGSLATENCY"] = "false"
		}
		// This file tests that Felix writes out its DNS mappings file on shutdown, so we
		// need to stop Felix gracefully.
		opts.FelixStopGraceful = true
		// Tests in this file require a node IP, so that Felix can attach a BPF program to
		// host interfaces.
		opts.NeedNodeIP = true
		if zeroLatency && !setsUpdateFromFelix {
			opts.ExtraEnvVars["FELIX_DEBUGDNSDONOTWRITEIPSETS"] = "true"
		}
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "")

		if zeroLatency && !BPFMode() {
			infra.RunBPFLog()
		}
		// Create a workload, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(tc.Felixes[0], "w"+iiStr, "default", "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].Configure(client)
		}

		// Allow workloads to connect out to the Internet.
		tc.Felixes[0].Exec(
			"iptables", "-w", "-t", "nat",
			"-A", "POSTROUTING",
			"-o", "eth0",
			"-j", "MASQUERADE", "--random-fully",
		)
	})

	// Stop etcd and workloads, collecting some state if anything failed.
	AfterEach(func() {
		if saveFileMappedOutsideContainer {
			tc.Felixes[0].Stop() // Trigger felix to write out the file.
			Eventually(path.Join(dnsDir, "dnsinfo.txt"), "10s", "1s").Should(BeARegularFile())
		}
	})

	Context("with save file in initially non-existent directory", func() {
		BeforeEach(func() {
			saveFile = "/a/b/c/d/e/dnsinfo.txt"
			saveFileMappedOutsideContainer = false
		})

		It("can wget www.fake-microsoft.test", func() {
			canWgetMicrosoft()
		})
	})

	Context("after wget www.fake-microsoft.test", func() {
		JustBeforeEach(func() {
			time.Sleep(time.Second)
			canWgetMicrosoft()
		})

		It("should emit www.fake-microsoft.test DNS log with latency", func() {
			Eventually(getLastMicrosoftALog, "10s", "1s").Should(MatchRegexp(`"latency_count":[1-9]`))
		})

		Context("with a preceding DNS request that went unresponded", func() {
			JustBeforeEach(func() {
				hep := v3.NewHostEndpoint()
				hep.Name = "felix-eth0"
				hep.Labels = map[string]string{"host-endpoint": "yes"}
				hep.Spec.Node = tc.Felixes[0].Hostname
				hep.Spec.InterfaceName = "eth0"
				_, err := client.HostEndpoints().Create(utils.Ctx, hep, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				udp := numorstring.ProtocolFromString("udp")
				policy := v3.NewGlobalNetworkPolicy()
				policy.Name = "deny-dns"
				policy.Spec.Selector = "host-endpoint == 'yes'"
				policy.Spec.Egress = []v3.Rule{
					{
						Action:   v3.Deny,
						Protocol: &udp,
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{numorstring.SinglePort(53)},
						},
					},
					{
						Action: v3.Allow,
					},
				}
				policy.Spec.ApplyOnForward = true
				_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				// DNS should now fail, leaving at least one unresponded DNS
				// request.
				cannotWgetMicrosoft()

				// Delete the policy again.
				_, err = client.GlobalNetworkPolicies().Delete(utils.Ctx, "deny-dns", options.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Delete the host endpoint again.
				_, err = client.HostEndpoints().Delete(utils.Ctx, "felix-eth0", options.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Wait 11 seconds so that the unresponded request timestamp is
				// eligible for cleanup.
				time.Sleep(11 * time.Second)

				// Now DNS and outbound connection should work.
				canWgetMicrosoft()
			})

			It("should emit www.fake-microsoft.test DNS log with latency", func() {
				Eventually(getLastMicrosoftALog, "10s", "1s").Should(MatchRegexp(`"latency_count":[1-9]`))
			})
		})

		Context("with DNS latency disabled", func() {
			BeforeEach(func() {
				enableLatency = false
			})

			It("should emit www.fake-microsoft.test DNS log without latency", func() {
				Eventually(getLastMicrosoftALog, "10s", "1s").Should(MatchRegexp(`"latency_count":0`))
			})
		})

		Context("with DNS logs disabled", func() {
			BeforeEach(func() {
				enableLogs = false
			})

			It("should not emit DNS logs", func() {
				Consistently(path.Join(dnsDir, "dns.log"), "5s", "1s").ShouldNot(BeARegularFile())
			})
		})
	})

	Context("after host wget www.fake-microsoft.test", func() {
		JustBeforeEach(func() {
			time.Sleep(time.Second)
			hostCanWgetMicrosoft()
		})

		It("should emit DNS logs", func() {
			Eventually(getLastMicrosoftALog, "10s", "1s").ShouldNot(BeEmpty())
		})

		Context("with DNS logs disabled", func() {
			BeforeEach(func() {
				enableLogs = false
			})

			It("should not emit DNS logs", func() {
				Consistently(path.Join(dnsDir, "dns.log"), "5s", "1s").ShouldNot(BeARegularFile())
			})
		})
	})

	It("can wget www.fake-microsoft.test", func() {
		canWgetMicrosoft()
	})

	It("host can wget www.fake-microsoft.test", func() {
		hostCanWgetMicrosoft()
	})

	Context("with default-deny egress policy", func() {
		JustBeforeEach(func() {
			policy := v3.NewGlobalNetworkPolicy()
			policy.Name = "default-deny-egress"
			policy.Spec.Selector = "all()"
			policy.Spec.Egress = []v3.Rule{{
				Action: v3.Deny,
			}}
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("cannot wget www.fake-microsoft.test", func() {
			cannotWgetMicrosoft()
		})

		// There's no HostEndpoint yet, so the policy doesn't affect the host.
		It("host can wget www.fake-microsoft.test", func() {
			hostCanWgetMicrosoft()
		})

		configureGNPAllowToMicrosoft := func() {
			policy := v3.NewGlobalNetworkPolicy()
			policy.Name = "allow-microsoft"
			order := float64(20)
			policy.Spec.Order = &order
			policy.Spec.Selector = "all()"
			udp := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
			policy.Spec.Egress = []v3.Rule{
				{
					Action:      v3.Allow,
					Destination: v3.EntityRule{Domains: []string{"fake-microsoft.test", "www.fake-microsoft.test"}},
				},
				{
					Action:   v3.Allow,
					Protocol: &udp,
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(53)},
					},
				},
			}
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			if zeroLatency {
				Eventually(func() []string {
					m := dumpDNSPfxMap(tc.Felixes[0])
					pfxs := []string{}
					for k := range m {
						pfxs = append(pfxs, k.Domain())
					}
					return pfxs
				}, "1m", "1s").Should(And(ContainElement("fake-microsoft.test"), ContainElement("www.fake-microsoft.test")))
			}
		}

		Context("with HostEndpoint", func() {
			JustBeforeEach(func() {
				hep := v3.NewHostEndpoint()
				hep.Name = "hep-1"
				hep.Spec.Node = tc.Felixes[0].Hostname
				hep.Spec.InterfaceName = "eth0"
				_, err := client.HostEndpoints().Create(utils.Ctx, hep, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			It("host cannot wget www.fake-microsoft.test", func() {
				hostCannotWgetMicrosoft()
			})

			Context("with domain-allow egress policy", func() {
				JustBeforeEach(configureGNPAllowToMicrosoft)

				It("host can wget www.fake-microsoft.test", func() {
					hostCanWgetMicrosoft()
				})
			})
		})

		// For a smallish subset of tests try running using the different policy modes.
		for _, m := range []v3.DNSPolicyMode{
			v3.DNSPolicyModeNoDelay,
			v3.DNSPolicyModeDelayDNSResponse,
			v3.DNSPolicyModeDelayDeniedPacket,
		} {
			localMode := m
			Context("with DNSPolicyMode explicitly set to "+string(localMode), func() {
				if zeroLatency {
					return
				}
				if BPFMode() && localMode != v3.DNSPolicyModeNoDelay {
					return
				}
				BeforeEach(func() {
					dnsMode = string(localMode)
				})

				// Helper used to check table contains the correct entries based on DNSPolicyMode and eBPF.
				checkIPTablesFunc := func(nfq100, nfq101 bool) func() error {
					return func() error {
						var foundReq, foundResp, found100, found101 bool

						var out string
						var err error
						if NFTMode() {
							out, err = tc.Felixes[0].ExecCombinedOutput("nft", "list", "ruleset")
							if err != nil {
								return err
							}
							for line := range strings.SplitSeq(out, "\n") {
								if strings.Contains(line, "jump filter-cali-log-dns") {
									if strings.Contains(line, "new") {
										foundReq = true
									}
									if strings.Contains(line, "established") {
										foundResp = true
									}
								} else if strings.Contains(line, "queue to 100") {
									found100 = true
								} else if strings.Contains(line, "queue flags bypass to 101") && strings.Contains(line, "established") {
									found101 = true
								}
							}
						} else {
							out, err = tc.Felixes[0].ExecCombinedOutput("iptables-save", "-c")
							if err != nil {
								return err
							}

							for line := range strings.SplitSeq(out, "\n") {
								if strings.Contains(line, "-j cali-log-dns") {
									if strings.Contains(line, "NEW") {
										foundReq = true
									}
									if strings.Contains(line, "ESTABLISHED") {
										foundResp = true
									}
								} else if strings.Contains(line, "--queue-num 100") {
									found100 = true
								} else if strings.Contains(line, "--queue-num 101") && strings.Contains(line, "ESTABLISHED") {
									found101 = true
								}
							}
						}

						if !foundReq {
							return fmt.Errorf("table does not contain the NFLOG DNS request snooping rule\n%s", out)
						}
						if !nfq101 && !foundResp {
							return fmt.Errorf("table does not contain the NFLOG DNS response snooping rule\n%s", out)
						}
						if nfq100 && !found100 {
							return fmt.Errorf("table does not contain the NFQUEUE id 100 rule\n%s", out)
						}
						if nfq101 && !found101 {
							return fmt.Errorf("table does not contain the NFQUEUE id 101 rule\n%s", out)
						}
						if found100 && found101 {
							return fmt.Errorf("table contains NFQUEUE id 100 and 101 rules\n%s", out)
						}

						return nil
					}
				}

				if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" && localMode == v3.DNSPolicyModeNoDelay {
					It("has ingress and egress NFLOG DNS snooping rules and no NFQUEUE rules", func() {
						// Should be 6 snooping NFLOG rules (ingress/egress for forward,output,input).
						// Should be no nfqueue rules.
						Eventually(checkIPTablesFunc(false, false), "10s", "1s").ShouldNot(HaveOccurred())
					})
				}

				if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" && localMode == v3.DNSPolicyModeDelayDNSResponse {
					It("has ingress NFLOG and egress NFQUEUE DNS snooping rules", func() {
						// Should be 3 snooping NFLOG rules (egress for forward,output,input).
						// Should be 3 snooping NFQUEUE 101 rules (ingress for forward,output,input).
						// Should be no nfqueue 100 rules.
						Eventually(checkIPTablesFunc(false, true), "10s", "1s").ShouldNot(HaveOccurred())
					})
				}

				if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" && localMode == v3.DNSPolicyModeDelayDeniedPacket {
					It("has ingress and egress NFLOG rules and NFQUEUEd deny packets", func() {
						// Should be 6 snooping NFLOG rules (ingress/egress for forward,output,input).
						// Should only be nfqueue 100 rules.
						Eventually(checkIPTablesFunc(true, false), "10s", "1s").ShouldNot(HaveOccurred())
					})
				}

				Context("with domain-allow egress policy", func() {
					JustBeforeEach(configureGNPAllowToMicrosoft)

					It("can wget www.fake-microsoft.test", func() {
						canWgetMicrosoft()
					})
				})

				Context("with namespaced domain-allow egress policy", func() {
					JustBeforeEach(func() {
						policy := v3.NewNetworkPolicy()
						policy.Name = "allow-microsoft"
						policy.Namespace = "fv"
						order := float64(20)
						policy.Spec.Order = &order
						policy.Spec.Selector = "all()"
						udp := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
						policy.Spec.Egress = []v3.Rule{
							{
								Action:      v3.Allow,
								Destination: v3.EntityRule{Domains: []string{"fake-microsoft.test", "www.fake-microsoft.test"}},
							},
							{
								Action:   v3.Allow,
								Protocol: &udp,
								Destination: v3.EntityRule{
									Ports: []numorstring.Port{numorstring.SinglePort(53)},
								},
							},
						}
						_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())

						if zeroLatency {
							Eventually(func() []string {
								m := dumpDNSPfxMap(tc.Felixes[0])
								pfxs := []string{}
								for k := range m {
									pfxs = append(pfxs, k.Domain())
								}
								return pfxs
							}, "1m", "1s").Should(And(ContainElement("fake-microsoft.test"), ContainElement("www.fake-microsoft.test")))
						}
					})

					It("can wget www.fake-microsoft.test", func() {
						canWgetMicrosoft()
					})
				})
			})
		}

		Context("with namespaced domain-allow egress policy in wrong namespace", func() {
			JustBeforeEach(func() {
				policy := v3.NewNetworkPolicy()
				policy.Name = "allow-microsoft"
				policy.Namespace = "wibbly-woo"
				order := float64(20)
				policy.Spec.Order = &order
				policy.Spec.Selector = "all()"
				udp := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
				policy.Spec.Egress = []v3.Rule{
					{
						Action:      v3.Allow,
						Destination: v3.EntityRule{Domains: []string{"fake-microsoft.test", "www.fake-microsoft.test"}},
					},
					{
						Action:   v3.Allow,
						Protocol: &udp,
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{numorstring.SinglePort(53)},
						},
					},
				}
				_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			It("cannot wget www.fake-microsoft.test", func() {
				// XXX hard to say whether you cannot get it because the policy
				// is not in place yet or because it is a wrong namespace.
				cannotWgetMicrosoft()
			})
		})

		Context("with wildcard domain-allow egress policy", func() {
			JustBeforeEach(func() {
				policy := v3.NewGlobalNetworkPolicy()
				policy.Name = "allow-microsoft-wild"
				order := float64(20)
				policy.Spec.Order = &order
				policy.Spec.Selector = "all()"
				udp := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
				policy.Spec.Egress = []v3.Rule{
					{
						Action:      v3.Allow,
						Destination: v3.EntityRule{Domains: msWildcards},
					},
					{
						Action:   v3.Allow,
						Protocol: &udp,
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{numorstring.SinglePort(53)},
						},
					},
				}
				_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				if zeroLatency {
					Eventually(func() []string {
						m := dumpDNSPfxMap(tc.Felixes[0])
						pfxs := []string{}
						for k := range m {
							pfxs = append(pfxs, k.Domain())
						}
						return pfxs
					}, "1m", "1s").Should(Or(ContainElement("fake-microsoft.test"), ContainElement("*.fake-microsoft.test")))
				}
			})

			It("can wget www.fake-microsoft.test", func() {
				canWgetMicrosoft()
			})
		})

		Context("with global networkset with allowed egress wildcard domains", func() {
			JustBeforeEach(func() {
				gns := v3.NewGlobalNetworkSet()
				gns.Name = "allow-microsoft"
				gns.Labels = map[string]string{"founder": "billg"}
				gns.Spec.AllowedEgressDomains = msWildcards
				_, err := client.GlobalNetworkSets().Create(utils.Ctx, gns, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				policy := v3.NewGlobalNetworkPolicy()
				policy.Name = "allow-microsoft"
				order := float64(20)
				policy.Spec.Order = &order
				policy.Spec.Selector = "all()"
				udp := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
				policy.Spec.Egress = []v3.Rule{
					{
						Action: v3.Allow,
						Destination: v3.EntityRule{
							Selector: "founder == 'billg'",
						},
					},
					{
						Action:   v3.Allow,
						Protocol: &udp,
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{numorstring.SinglePort(53)},
						},
					},
				}
				_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				if zeroLatency {
					Eventually(func() []string {
						m := dumpDNSPfxMap(tc.Felixes[0])
						pfxs := []string{}
						for k := range m {
							pfxs = append(pfxs, k.Domain())
						}
						return pfxs
					}, "1m", "1s").Should(Or(ContainElement("fake-microsoft.test"), ContainElement("*.fake-microsoft.test")))
				}
			})

			It("can wget www.fake-microsoft.test", func() {
				canWgetMicrosoft()
			})

			It("handles a domain set update", func() {
				// Create another GNS with same labels as the previous one, so that
				// the destination selector will now match this one as well, and so
				// the domain set membership will change.
				gns := v3.NewGlobalNetworkSet()
				gns.Name = "allow-microsoft-2"
				gns.Labels = map[string]string{"founder": "billg"}
				gns.Spec.AllowedEgressDomains = []string{"port25.fake-microsoft.test"}
				_, err := client.GlobalNetworkSets().Create(utils.Ctx, gns, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				time.Sleep(2 * time.Second)
				canWgetMicrosoft()
			})
		})

		Context("with networkset with allowed egress domains", func() {
			JustBeforeEach(func() {
				ns := v3.NewNetworkSet()
				ns.Name = "allow-microsoft"
				ns.Namespace = "fv"
				ns.Labels = map[string]string{"founder": "billg"}
				ns.Spec.AllowedEgressDomains = []string{"fake-microsoft.test", "www.fake-microsoft.test"}
				_, err := client.NetworkSets().Create(utils.Ctx, ns, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				policy := v3.NewNetworkPolicy()
				policy.Name = "allow-microsoft"
				policy.Namespace = "fv"
				order := float64(20)
				policy.Spec.Order = &order
				policy.Spec.Selector = "all()"
				udp := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
				policy.Spec.Egress = []v3.Rule{
					{
						Action: v3.Allow,
						Destination: v3.EntityRule{
							Selector: "founder == 'billg'",
						},
					},
					{
						Action:   v3.Allow,
						Protocol: &udp,
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{numorstring.SinglePort(53)},
						},
					},
				}
				_, err = client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				if zeroLatency {
					Eventually(func() []string {
						m := dumpDNSPfxMap(tc.Felixes[0])
						pfxs := []string{}
						for k := range m {
							pfxs = append(pfxs, k.Domain())
						}
						return pfxs
					}, "1m", "1s").Should(ContainElements("fake-microsoft.test", "www.fake-microsoft.test"))
				}
			})

			It("can wget www.fake-microsoft.test", func() {
				canWgetMicrosoft()
			})

			It("handles a domain set update", func() {
				// Create another NetworkSet with same labels as the previous one, so that
				// the destination selector will now match this one as well, and so
				// the domain set membership will change.
				ns := v3.NewNetworkSet()
				ns.Name = "allow-microsoft-2"
				ns.Namespace = "fv"
				ns.Labels = map[string]string{"founder": "billg"}
				ns.Spec.AllowedEgressDomains = []string{"port25.fake-microsoft.test"}
				_, err := client.NetworkSets().Create(utils.Ctx, ns, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				time.Sleep(2 * time.Second)
				canWgetMicrosoft()
			})
		})

		Context("with networkset with allowed egress wildcard domains", func() {
			JustBeforeEach(func() {
				ns := v3.NewNetworkSet()
				ns.Name = "allow-microsoft"
				ns.Namespace = "fv"
				ns.Labels = map[string]string{"founder": "billg"}
				ns.Spec.AllowedEgressDomains = msWildcards
				_, err := client.NetworkSets().Create(utils.Ctx, ns, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				policy := v3.NewNetworkPolicy()
				policy.Name = "allow-microsoft"
				policy.Namespace = "fv"
				order := float64(20)
				policy.Spec.Order = &order
				policy.Spec.Selector = "all()"
				udp := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
				policy.Spec.Egress = []v3.Rule{
					{
						Action: v3.Allow,
						Destination: v3.EntityRule{
							Selector: "founder == 'billg'",
						},
					},
					{
						Action:   v3.Allow,
						Protocol: &udp,
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{numorstring.SinglePort(53)},
						},
					},
				}
				_, err = client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				if zeroLatency {
					Eventually(func() []string {
						m := dumpDNSPfxMap(tc.Felixes[0])
						pfxs := []string{}
						for k := range m {
							pfxs = append(pfxs, k.Domain())
						}
						return pfxs
					}, "1m", "1s").Should(Or(ContainElement("fake-microsoft.test"), ContainElement("*.fake-microsoft.test")))
				}
			})

			It("can wget www.fake-microsoft.test", func() {
				canWgetMicrosoft()
			})

			It("handles a domain set update", func() {
				// Create another NetworkSet with same labels as the previous one, so that
				// the destination selector will now match this one as well, and so
				// the domain set membership will change.
				ns := v3.NewNetworkSet()
				ns.Name = "allow-microsoft-2"
				ns.Namespace = "fv"
				ns.Labels = map[string]string{"founder": "billg"}
				ns.Spec.AllowedEgressDomains = []string{"port25.fake-microsoft.test"}
				_, err := client.NetworkSets().Create(utils.Ctx, ns, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				time.Sleep(2 * time.Second)
				canWgetMicrosoft()
			})
		})
	})
}

var _ = infrastructure.DatastoreDescribe("DNS Policy Mode: DelayDeniedPacket", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		dnsserver       *containers.Container
		tc              infrastructure.TopologyContainers
		client          client.Interface
		infra           infrastructure.DatastoreInfra
		workload1       *workload.Workload
		workload2       *workload.Workload
		workload3       *workload.Workload
		workloads       []*workload.Workload
		policy          *v3.NetworkPolicy
		policyChainName string
		cc              *connectivity.Checker

		queueDropMatch       string
		dnsPolicyAllowMatch1 string
		dnsPolicyAllowMatch2 string
	)

	const (
		workload1Name = "w1"
		workload2Name = "w2"
		workload3Name = "w3"
		workload1IP   = "10.65.0.1"
		workload2IP   = "10.65.0.2"
		workload3IP   = "10.65.0.3"
		serviceIP     = "10.96.0.123"
	)
	BeforeEach(func() {
		infra = getInfra()
		var err error

		opts := infrastructure.DefaultTopologyOptions()

		cc = &connectivity.Checker{Protocol: "udp"}

		dnsRecords := map[string][]dns.RecordIP{
			"foobar.com":  {{TTL: 20, IP: workload2IP}},
			"bazbiff.com": {{TTL: 20, IP: serviceIP}},
		}

		dnsserver = dns.StartServer(infra, dnsRecords)

		opts.ExtraEnvVars["FELIX_DNSTRUSTEDSERVERS"] = dnsserver.IP
		opts.ExtraEnvVars["FELIX_PolicySyncPathPrefix"] = "/var/run/calico/policysync"
		opts.ExtraEnvVars["FELIX_DEBUGDNSRESPONSEDELAY"] = "200"
		opts.ExtraEnvVars["FELIX_DebugConsoleEnabled"] = "true"
		opts.ExtraEnvVars["FELIX_DNSPOLICYMODE"] = "delayDeniedPacket"
		opts.ExtraEnvVars["FELIX_NFTablesDNSPOLICYMODE"] = "delayDeniedPacket"
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "")

		workload1 = workload.Run(tc.Felixes[0], workload1Name, "default", workload1IP, "8055", "tcp")
		workload1.ConfigureInInfra(infra)
		workloads = append(workloads, workload1)

		workload2 = workload.Run(tc.Felixes[0], workload2Name, "default", workload2IP, "8055", "udp")
		workload2.ConfigureInInfra(infra)
		workloads = append(workloads, workload2)

		workload3 = workload.Run(tc.Felixes[0], workload3Name, "default", workload3IP, "8055", "udp")
		workload3.ConfigureInInfra(infra)
		workloads = append(workloads, workload3)

		udp := numorstring.ProtocolFromString(numorstring.ProtocolUDP)

		policy = v3.NewNetworkPolicy()
		policy.Name = "default.allow-foobar"
		policy.Namespace = "default"
		order := float64(20)
		policy.Spec.Order = &order
		policy.Spec.Selector = workload1.NameSelector()
		policy.Spec.Egress = []v3.Rule{
			{
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						"rule-name": "allow-foobar",
					},
				},
				Action:      v3.Allow,
				Destination: v3.EntityRule{Domains: []string{"foobar.com"}},
			},
			{
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						"rule-name": "allow-bazbiff",
					},
				},
				Action:      v3.Allow,
				Destination: v3.EntityRule{Domains: []string{"bazbiff.com"}},
			},
			{
				Action:   v3.Allow,
				Protocol: &udp,
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(53)},
				},
			},
		}

		policy, err = client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		policyChainName = rules.PolicyChainName(rules.PolicyOutboundPfx, &types.PolicyID{
			Name:      policy.Name,
			Namespace: policy.Namespace,
			Kind:      v3.KindNetworkPolicy,
		},
			NFTMode(),
		)

		// Allow workloads to connect out to the Internet.
		tc.Felixes[0].Exec(
			"iptables", "-w", "-t", "nat",
			"-A", "POSTROUTING",
			"-o", "eth0",
			"-j", "MASQUERADE", "--random-fully",
		)

		// Ensure that Felix is connected to nfqueue
		_, err = tc.Felixes[0].ExecCombinedOutput("cat", "/proc/net/netfilter/nfnetlink_queue")
		Expect(err).ShouldNot(HaveOccurred())

		// Define rule matches used in the test.
		queueDropMatch = "Drop if no policies passed packet[^\n]*NFQUEUE.*"
		dnsPolicyAllowMatch1 = "rule-name=allow-bazbiff[^\n]*cali40d"
		dnsPolicyAllowMatch2 = "rule-name=allow-foobar[^\n]*cali40d"
		if NFTMode() {
			queueDropMatch = "queue to 100 comment .*Drop if no policies passed packet"
			dnsPolicyAllowMatch1 = "cali40d-8FX6lj5QBNTr5qeMZJwks6E.*rule-name=allow-bazbiff"
			dnsPolicyAllowMatch2 = "cali40d-c19ArGfvjwU6D6ljIxk2xsA.*rule-name=allow-foobar"
		}
	})

	When("when the dns response isn't programmed before the packet reaches the dns policy rule", func() {
		It("nf repeats the packet and the packet is eventually accepted by the dns policy rule", func() {
			waitForChain(tc.Felixes[0], policyChainName)

			output, err := checkSingleShotDNSConnectivity(workload1, "foobar.com", dnsserver.IP)
			Expect(err).ShouldNot(HaveOccurred(), output)

			// Check that we hit the NFQUEUE rule at least once, to prove the packet was NF_REPEATED at least once before
			// being accepted.
			nfqueuedPacketsCount := getPacketCount(tc.Felixes[0], fmt.Sprintf("cali-fw-%s", workload1.InterfaceName), queueDropMatch)
			Expect(nfqueuedPacketsCount).Should(BeNumerically(">", 0))

			dnsPolicyRulePacketsAllowed := getPacketCount(tc.Felixes[0], policyChainName, dnsPolicyAllowMatch2)
			Expect(dnsPolicyRulePacketsAllowed).Should(Equal(1))

			cc.ExpectNone(workload1, workload3)
			cc.CheckConnectivity()
		})

		// Shared code for checking DNS policy interaction with IPVS/iptables NAT.
		checkDNSPolicyDNATInteraction := func() {
			waitForChain(tc.Felixes[0], policyChainName)

			_, err := checkSingleShotDNSConnectivity(workload1, "bazbiff.com", dnsserver.IP)
			Expect(err).Should(HaveOccurred(), "Unexpectedly had connectivity via DNS entry that maps to service IP")

			// Check that we hit the NFQUEUE rule at least once, to prove the packet was NF_REPEATED at least once before
			// being dropped.
			nfqueuedPacketsCount := getPacketCount(tc.Felixes[0], fmt.Sprintf("cali-fw-%s", workload1.InterfaceName), queueDropMatch)
			Expect(nfqueuedPacketsCount).Should(BeNumerically(">", 0))

			dnsPolicyRulePacketsAllowed := getPacketCount(tc.Felixes[0], policyChainName, dnsPolicyAllowMatch1)
			Expect(dnsPolicyRulePacketsAllowed).Should(Equal(0))

			// Now, to rule out a bug in our IPVS set-up, add the backing pod
			// to the policy.
			policy.Spec.Egress = append(policy.Spec.Egress, v3.Rule{
				Action: v3.Allow,
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						"rule-name": "allow-wl2",
					},
				},
				Destination: v3.EntityRule{
					Selector: workload2.NameSelector(),
				},
			})
			policy, err = client.NetworkPolicies().Update(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Wait for the new rule to show up so we know we're testing the
			// right thing.
			Eventually(func() string {
				if NFTMode() {
					out, err := tc.Felixes[0].ExecOutput("nft", "list", "table", "ip", "calico")
					if err != nil {
						return fmt.Sprintf("Error running iptables-save: %v", err)
					}
					return out
				} else {
					out, err := tc.Felixes[0].ExecOutput("iptables-save", "-c")
					if err != nil {
						return fmt.Sprintf("Error running iptables-save: %v", err)
					}
					return out
				}
			}, "5s", "200ms").Should(ContainSubstring("allow-wl2"))

			// Now, the packet should get through, but it should hit the
			// new rule, not the old one.
			output, err := checkSingleShotDNSConnectivity(workload1, "bazbiff.com", dnsserver.IP)
			Expect(err).ShouldNot(HaveOccurred(), "Unexpectedly had no connectivity via DNS entry that maps to service IP:"+output)

			// Check expected pod-to-pod connectivity.
			cc.ExpectSome(workload1, workload2)
			cc.ExpectNone(workload1, workload3)
			cc.CheckConnectivity()
		}

		Describe("with an IPVS IP service behind DNS", func() {
			// This scenario checks for an interaction between IPVS and DNS
			// policy.  IPVS breaks the connection into two legs, one of
			// which goes through the INPUT chain and one of which goes
			// through the OUTPUT chain.  We use mark bits to track the
			// packet through IPVS.  So, we need to make sure that, if
			// we queue a packet that went through IPVS, we don't lose
			// its mark bits.

			BeforeEach(func() {
				if NFTMode() {
					Skip("IPVS not supported in NFT mode")
				}
				tc.Felixes[0].Exec("ip", "link", "add", "dev", kubeIPVSInterface, "type", "dummy")
				tc.Felixes[0].Exec("ip", "link", "set", kubeIPVSInterface, "up")
				tc.Felixes[0].Exec("ip", "addr", "add", "dev", kubeIPVSInterface, serviceIP)
				// sudo ipvsadm -A -t 10.1.0.6:8085
				// sudo ipvsadm -a -t 10.1.0.6:8085 -r 10.1.0.50 -m
				tc.Felixes[0].Exec("ipvsadm", "-A", "-u", serviceIP+":8055")
				tc.Felixes[0].Exec("ipvsadm", "-a", "-u", serviceIP+":8055", "-r", workload2IP, "-m")
			})
			It("the packet should not match DNS policy (due to the DNAT)", checkDNSPolicyDNATInteraction)
		})

		if !BPFMode() {
			Describe("with an iptables NAT IP service behind DNS", func() {
				BeforeEach(func() {
					if NFTMode() {
						tc.Felixes[0].Exec("nft", "add", "table", "ip", "services")
						tc.Felixes[0].Exec("nft", "add", "chain", "ip", "services", "PREROUTING", "{ type nat hook prerouting priority -100; }")
						tc.Felixes[0].Exec("nft", "add", "rule", "ip", "services", "PREROUTING", "ip daddr", serviceIP, "dnat", "to", workload2IP)
					} else {
						tc.Felixes[0].Exec("iptables", "-t", "nat", "-A", "PREROUTING", "-d", serviceIP, "-j", "DNAT", "--to-destination", workload2IP)
					}
				})
				It("the packet should not match DNS policy (due to the DNAT)", checkDNSPolicyDNATInteraction)
			})
		}

		It("nf repeats the packet and the packet is eventually accepted by the dns policy rule", func() {
			waitForChain(tc.Felixes[0], policyChainName)

			output, err := checkSingleShotDNSConnectivity(workload1, "foobar.com", dnsserver.IP)
			Expect(err).ShouldNot(HaveOccurred(), output)

			// Check that we hit the NFQUEUE rule at least once, to prove the packet was NF_REPEATED at least once before
			// being accepted.
			nfqueuedPacketsCount := getPacketCount(tc.Felixes[0],
				fmt.Sprintf("cali-fw-%s", workload1.InterfaceName), queueDropMatch)
			Expect(nfqueuedPacketsCount).Should(BeNumerically(">", 0))

			dnsPolicyRulePacketsAllowed := getPacketCount(tc.Felixes[0], policyChainName, dnsPolicyAllowMatch2)
			Expect(dnsPolicyRulePacketsAllowed).Should(Equal(1))
		})

		When("the connection to nfqueue is terminated", func() {
			It("restarts the connection and nf repeats the packet and the packet is eventually accepted by the dns policy rule", func() {
				waitForChain(tc.Felixes[0], policyChainName)

				output, err := tc.Felixes[0].RunDebugConsoleCommand("close-nfqueue-conn")
				Expect(err).ShouldNot(HaveOccurred(), output)

				output = ""
				Eventually(func() error {
					output, err = checkSingleShotDNSConnectivity(workload1, "foobar.com", dnsserver.IP)
					return err
				}, "10s", "1s").ShouldNot(HaveOccurred(), output)

				// Check that we hit the NFQUEUE rule at least once, to prove the packet was NF_REPEATED at least once before
				// being accepted.
				nfqueuedPacketsCount := getPacketCount(tc.Felixes[0],
					fmt.Sprintf("cali-fw-%s", workload1.InterfaceName), queueDropMatch)
				Expect(nfqueuedPacketsCount).Should(BeNumerically(">", 0))

				dnsPolicyRulePacketsAllowed := getPacketCount(tc.Felixes[0], policyChainName, dnsPolicyAllowMatch2)
				Expect(dnsPolicyRulePacketsAllowed).Should(Equal(1))
			})
		})
	})
})

// waitForChain waits for the chain to be programmed on the felix instance. It eventually times out if it waits
// too long.
func waitForChain(felix *infrastructure.Felix, chainName string) {
	if NFTMode() {
		EventuallyWithOffset(1, func() error {
			out, err := felix.ExecOutput("nft", "list", "ruleset")
			if err != nil {
				return nil
			}
			if !strings.Contains(out, fmt.Sprintf("chain filter-%s {", chainName)) {
				return fmt.Errorf("chain %s not found in nft ruleset:\n%s", chainName, out)
			}
			return nil
		}, "10s", "1s").ShouldNot(HaveOccurred())
	} else {
		EventuallyWithOffset(1, felix.IPTablesChainsFn("filter"), "10s", "1s").Should(HaveKey(chainName))
	}
}

// checkSingleShotDNSConnectivity sends a single udp request to the domain name from the given workload on port 8055.
// The dnsServerIP is used to tell the test-connection script what dns server to use to resolve the IP for the domain.
func checkSingleShotDNSConnectivity(w *workload.Workload, domainName, dnsServerIP string) (string, error) {
	output, err := w.ExecCombinedOutput("test-connection", "-", domainName, "8055", "--protocol=udp", fmt.Sprintf("--dns-server=%s:%d", dnsServerIP, 53))
	return output, err
}

// getPacketCount searches for the rule identified by the chain and rule identifier given, and returns the packet
// count for that rule. If the rule isn't found in the output this function fails the test.
//
// The ruleIdentifier is a regex that targets the text in the rule, and varies based on the dataplane mode.
func getPacketCount(felix *infrastructure.Felix, chainName, ruleIdentifier string) int {
	if NFTMode() {
		return getNFTPacketCount(felix, chainName, ruleIdentifier)
	}
	return getIptablesSavePacketCount(felix, chainName, ruleIdentifier)
}

func getNFTPacketCount(felix *infrastructure.Felix, chainName, ruleIdentifier string) int {
	var count int

	EventuallyWithOffset(2, func() error {
		out, err := felix.ExecCombinedOutput("nft", "list", "chain", "ip", "calico", fmt.Sprintf("filter-%s", chainName))
		if err != nil {
			return err
		}

		// Find the rule containing the identifier and extract the entire rule text from the chain.
		ruleFinder := regexp.MustCompile(fmt.Sprintf(`.*(%s).*`, ruleIdentifier))
		matches := ruleFinder.FindStringSubmatch(out)
		if len(matches) < 1 {
			return fmt.Errorf("no rule found for identifier \"%s\" using regex %s", ruleIdentifier, ruleFinder.String())
		}
		if len(matches) > 2 {
			return fmt.Errorf("more than one rule found for identifier \"%s\"", ruleIdentifier)
		}
		rule := matches[0]

		// Extract packet count from the rule.
		packetCountFinder := regexp.MustCompile(`packets\s+(\d+)`)
		matches = packetCountFinder.FindStringSubmatch(rule)
		if len(matches) < 1 {
			return fmt.Errorf("no packets found in rule \"%s\" using %s", rule, packetCountFinder.String())
		}

		count, err = strconv.Atoi(matches[1])
		return err
	}, "10s", "1s").ShouldNot(HaveOccurred())

	return count
}

// getIptablesSavePacketCount searches the given iptables-save output for the iptables rule identified by the chain and
// rule identifier given, and returns the packet count for that rule. If the rule isn't found, in the output and this function
// fails the test.
//
// The ruleIdentifier is a regex that targets the text in the rule AFTER the chain name.
func getIptablesSavePacketCount(felix *infrastructure.Felix, chainName, ruleIdentifier string) int {
	var count int
	regex := fmt.Sprintf(`\[(\d*):\d*\]\s-A %s[^\n]*%s.*`, chainName, ruleIdentifier)

	Eventually(func() error {
		iptablesSaveOutput, err := felix.ExecCombinedOutput("iptables-save", "-c")
		if err != nil {
			return err
		}

		re := regexp.MustCompile(regex)
		matches := re.FindStringSubmatch(iptablesSaveOutput)
		if len(matches) < 1 {
			return fmt.Errorf("no rule found for chain \"%s\" and identifier \"%s\"", chainName, ruleIdentifier)
		}

		count, err = strconv.Atoi(matches[1])
		return err
	}, "10s", "1s").ShouldNot(HaveOccurred())

	return count
}
