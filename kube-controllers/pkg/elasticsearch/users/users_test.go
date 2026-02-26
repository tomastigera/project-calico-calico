// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package users_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch/users"
)

var _ = Describe("ElasticseachUsers", func() {
	var privateUsers, publicUsers, expectedPrivateUsers, expectedPublicUsers map[users.ElasticsearchUserName]elasticsearch.User
	Context("management flag set to false", func() {
		BeforeEach(func() {
			privateUsers, publicUsers = users.ElasticsearchUsers("managed-cluster", false)
			expectedPrivateUsers = map[users.ElasticsearchUserName]elasticsearch.User{
				"tigera-fluentd": {
					Username: "tigera-fluentd-managed-cluster-secure",
					FullName: "system:serviceaccount",
					Roles: []elasticsearch.Role{{
						Name: "tigera-fluentd-managed-cluster-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates", "manage_ilm"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_*.managed-cluster.*"},
								Privileges: []string{"create_index", "write", "manage"},
							}},
						},
					}},
				},
				"tigera-eks-log-forwarder": {
					Username: "tigera-eks-log-forwarder-managed-cluster-secure",
					FullName: "system:serviceaccount",
					Roles: []elasticsearch.Role{{
						Name: "tigera-eks-log-forwarder-managed-cluster-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates", "manage_ilm"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_audit_kube.managed-cluster.*"},
								Privileges: []string{"create_index", "read", "write", "manage"},
							}},
						},
					}},
				},
				"tigera-ee-compliance-benchmarker": {
					Username: "tigera-ee-compliance-benchmarker-managed-cluster-secure",
					FullName: "system:serviceaccount",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-compliance-benchmarker-managed-cluster-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_benchmark_results.managed-cluster.*"},
								Privileges: []string{"create_index", "write", "view_index_metadata", "read", "manage"},
							}},
						},
					}},
				},
				"tigera-ee-compliance-controller": {
					Username: "tigera-ee-compliance-controller-managed-cluster-secure",
					FullName: "system:serviceaccount",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-compliance-controller-managed-cluster-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_compliance_reports.managed-cluster.*"},
								Privileges: []string{"read"},
							}},
						},
					}},
				},
				"tigera-ee-compliance-reporter": {
					Username: "tigera-ee-compliance-reporter-managed-cluster-secure",
					FullName: "system:serviceaccount",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-compliance-reporter-managed-cluster-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{
								{
									Names:      []string{"tigera_secure_ee_audit_*.managed-cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_snapshots.managed-cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_benchmark_results.managed-cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_flows.managed-cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_compliance_reports.managed-cluster.*"},
									Privileges: []string{"create_index", "write", "view_index_metadata", "read", "manage"},
								},
							},
						},
					}},
				},
				"tigera-ee-compliance-snapshotter": {
					Username: "tigera-ee-compliance-snapshotter-managed-cluster-secure",
					FullName: "system:serviceaccount",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-compliance-snapshotter-managed-cluster-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_snapshots.managed-cluster.*"},
								Privileges: []string{"create_index", "write", "view_index_metadata", "read", "manage"},
							}},
						},
					}},
				},
				"tigera-ee-intrusion-detection": {
					Username: "tigera-ee-intrusion-detection-managed-cluster-secure",
					FullName: "system:serviceaccount",
					Roles: []elasticsearch.Role{
						{
							Name: "tigera-ee-intrusion-detection-managed-cluster-secure",
							Definition: &elasticsearch.RoleDefinition{
								Cluster: []string{"monitor", "manage_index_templates"},
								Indices: []elasticsearch.RoleIndex{
									{
										Names:      []string{"tigera_secure_ee_*.managed-cluster.*"},
										Privileges: []string{"read"},
									},
									{
										Names: []string{
											".tigera.ipset.managed-cluster",
											".tigera.domainnameset.managed-cluster",
											".tigera.forwarderconfig.managed-cluster",
											"tigera_secure_ee_events.managed-cluster*",
										},
										Privileges: []string{"all"},
									},
								},
							},
						},
						{
							Name: "watcher_admin",
						},
					},
				},
				"tigera-ee-performance-hotspots": {
					Username: "tigera-ee-performance-hotspots-managed-cluster-secure",
					FullName: "system:serviceaccount",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-performance-hotspots-managed-cluster-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{
								{
									Names:      []string{"tigera_secure_ee_flows.managed-cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_dns.managed-cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_l7.managed-cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_events.managed-cluster.*"},
									Privileges: []string{"read", "write"},
								},
							},
						},
					}},
				},
				"tigera-ee-policy-recommendation": {
					Username: "tigera-ee-policy-recommendation-managed-cluster-secure",
					FullName: "system:serviceaccount",
					Roles: []elasticsearch.Role{
						{
							Name: "tigera-ee-policy-recommendation-managed-cluster-secure",
							Definition: &elasticsearch.RoleDefinition{
								Cluster: []string{"monitor", "manage_index_templates"},
								Indices: []elasticsearch.RoleIndex{
									{
										Names:      []string{"tigera_secure_ee_flows.managed-cluster.*"},
										Privileges: []string{"read"},
									},
								},
							},
						},
					},
				},
			}
			expectedPublicUsers = map[users.ElasticsearchUserName]elasticsearch.User{
				"tigera-fluentd": {
					Username: "tigera-fluentd-managed-cluster",
					FullName: "system:serviceaccount",
				},
				"tigera-eks-log-forwarder": {
					Username: "tigera-eks-log-forwarder-managed-cluster",
					FullName: "system:serviceaccount",
				},
				"tigera-ee-compliance-benchmarker": {
					Username: "tigera-ee-compliance-benchmarker-managed-cluster",
					FullName: "system:serviceaccount",
				},
				"tigera-ee-compliance-controller": {
					Username: "tigera-ee-compliance-controller-managed-cluster",
					FullName: "system:serviceaccount",
				},
				"tigera-ee-compliance-reporter": {
					Username: "tigera-ee-compliance-reporter-managed-cluster",
					FullName: "system:serviceaccount",
				},
				"tigera-ee-compliance-snapshotter": {
					Username: "tigera-ee-compliance-snapshotter-managed-cluster",
					FullName: "system:serviceaccount",
				},
				"tigera-ee-intrusion-detection": {
					Username: "tigera-ee-intrusion-detection-managed-cluster",
					FullName: "system:serviceaccount",
				},
				"tigera-ee-ad-job": {
					Username: "tigera-ee-ad-job-managed-cluster",
					FullName: "system:serviceaccount",
				},
				"tigera-ee-performance-hotspots": {
					Username: "tigera-ee-performance-hotspots-managed-cluster",
					FullName: "system:serviceaccount",
				},
				"tigera-ee-policy-recommendation": {
					Username: "tigera-ee-policy-recommendation-managed-cluster",
					FullName: "system:serviceaccount",
				},
			}
		})
		It("the expected users and roles are available", func() {
			testElasticsearchUsers(privateUsers, publicUsers, expectedPrivateUsers, expectedPublicUsers)
		})
		It("the expected decommissioned users and roles are returned with no overlap with the active users", func() {
			decommissionedUsers := users.DecommissionedElasticsearchUsers("managed-cluster")

			expectedDecommissionedUsers := map[users.ElasticsearchUserName]elasticsearch.User{
				"tigera-ee-curator": {
					Username: "tigera-ee-curator-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-curator-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_*.*.*", "tigera_secure_ee_events.*"},
								Privileges: []string{"all"},
							}},
						},
					}},
				},
			}

			testDecommissionedElasticsearchUsers(decommissionedUsers, expectedDecommissionedUsers, privateUsers, publicUsers)
		})
	})
	Context("management flag set to true", func() {
		BeforeEach(func() {
			privateUsers, publicUsers = users.ElasticsearchUsers("cluster", true)
			expectedPrivateUsers = map[users.ElasticsearchUserName]elasticsearch.User{
				"tigera-fluentd": {
					Username: "tigera-fluentd-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-fluentd-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates", "manage_ilm"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_*.cluster.*"},
								Privileges: []string{"create_index", "write", "manage"},
							}},
						},
					}},
				},
				"tigera-eks-log-forwarder": {
					Username: "tigera-eks-log-forwarder-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-eks-log-forwarder-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates", "manage_ilm"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_audit_kube.cluster.*"},
								Privileges: []string{"create_index", "read", "write", "manage"},
							}},
						},
					}},
				},
				"tigera-ee-compliance-benchmarker": {
					Username: "tigera-ee-compliance-benchmarker-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-compliance-benchmarker-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_benchmark_results.cluster.*"},
								Privileges: []string{"create_index", "write", "view_index_metadata", "read", "manage"},
							}},
						},
					}},
				},
				"tigera-ee-compliance-controller": {
					Username: "tigera-ee-compliance-controller-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-compliance-controller-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_compliance_reports.cluster.*"},
								Privileges: []string{"read"},
							}},
						},
					}},
				},
				"tigera-ee-compliance-reporter": {
					Username: "tigera-ee-compliance-reporter-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-compliance-reporter-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{
								{
									Names:      []string{"tigera_secure_ee_audit_*.cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_snapshots.cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_benchmark_results.cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_flows.cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_compliance_reports.cluster.*"},
									Privileges: []string{"create_index", "write", "view_index_metadata", "read", "manage"},
								},
							},
						},
					}},
				},
				"tigera-ee-compliance-snapshotter": {
					Username: "tigera-ee-compliance-snapshotter-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-compliance-snapshotter-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_snapshots.cluster.*"},
								Privileges: []string{"create_index", "write", "view_index_metadata", "read", "manage"},
							}},
						},
					}},
				},
				"tigera-ee-intrusion-detection": {
					Username: "tigera-ee-intrusion-detection-secure",
					Roles: []elasticsearch.Role{
						{
							Name: "tigera-ee-intrusion-detection-secure",
							Definition: &elasticsearch.RoleDefinition{
								Cluster: []string{"monitor", "manage_index_templates"},
								Indices: []elasticsearch.RoleIndex{
									{
										Names:      []string{"tigera_secure_ee_*.cluster.*"},
										Privileges: []string{"read"},
									},
									{
										Names:      []string{"tigera_secure_ee_flows.*.*"},
										Privileges: []string{"read"},
									},
									{
										Names:      []string{"tigera_secure_ee_audit_*.*.*"},
										Privileges: []string{"read"},
									},
									{
										Names:      []string{"tigera_secure_ee_dns.*.*"},
										Privileges: []string{"read"},
									},
									{
										Names:      []string{"tigera_secure_ee_waf.*.*"},
										Privileges: []string{"read"},
									},
									{
										Names: []string{
											".tigera.ipset.cluster",
											".tigera.domainnameset.cluster",
											".tigera.forwarderconfig.cluster",
											"tigera_secure_ee_events.*",
										},
										Privileges: []string{"all"},
									},
								},
							},
						},
						{
							Name: "watcher_admin",
						},
					},
				},
				"tigera-ee-installer": {
					Username: "tigera-ee-installer-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-installer-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"manage_watcher", "manage"},
							Indices: []elasticsearch.RoleIndex{
								{
									Names:      []string{"tigera_secure_ee_*.cluster.*", "tigera_secure_ee_events.cluster.*"},
									Privileges: []string{"read", "write"},
								},
							},
							Applications: []elasticsearch.Application{{
								Application: "kibana-.kibana",
								Privileges:  []string{"all"},
								Resources:   []string{"*"},
							}},
						},
					}},
				},
				"tigera-ee-sasha": {
					Username: "tigera-ee-sasha-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-sasha-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{
								{
									Names:      []string{"tigera_secure_ee_runtime.*.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_events.*.*"},
									Privileges: []string{"read", "write"},
								},
							},
						},
					}},
				},
				"tigera-ee-performance-hotspots": {
					Username: "tigera-ee-performance-hotspots-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-performance-hotspots-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{
								{
									Names:      []string{"tigera_secure_ee_flows.cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_dns.cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_l7.cluster.*"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_events.cluster.*"},
									Privileges: []string{"read", "write"},
								},
							},
						},
					}},
				},
				"tigera-ee-policy-recommendation": {
					Username: "tigera-ee-policy-recommendation-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-policy-recommendation-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{
								{
									Names:      []string{"tigera_secure_ee_flows.cluster.*"},
									Privileges: []string{"read"},
								},
							},
						},
					}},
				},
				"tigera-ee-compliance-server": {
					Username: "tigera-ee-compliance-server-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-compliance-server-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_compliance_reports.*.*"},
								Privileges: []string{"read"},
							}},
						},
					}},
				},
				"tigera-ee-manager": {
					Username: "tigera-ee-manager-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-manager-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor"},
							Indices: []elasticsearch.RoleIndex{
								{
									Names:      []string{"tigera_secure_ee_*.*.*", ".kibana"},
									Privileges: []string{"read"},
								},
								{
									Names:      []string{"tigera_secure_ee_events.*"},
									Privileges: []string{"read", "write"},
								},
							},
						},
					}},
				},
				"tigera-ee-operator": {
					Username: "tigera-ee-operator-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-operator-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates", "manage_ilm", "read_ilm"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_*"},
								Privileges: []string{"all"},
							}},
						},
					}},
				},
				"tigera-ee-elasticsearch-metrics": {
					Username: "tigera-ee-elasticsearch-metrics-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-elasticsearch-metrics-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"*"},
								Privileges: []string{"monitor", "view_index_metadata"},
							}},
						},
					}},
				},
				"tigera-ee-linseed": {
					Username: "tigera-ee-linseed-secure",
					Roles: []elasticsearch.Role{
						{
							Name: "tigera-ee-linseed-secure",
							Definition: &elasticsearch.RoleDefinition{
								Cluster: []string{"monitor", "manage_index_templates", "manage_ilm"},
								Indices: []elasticsearch.RoleIndex{
									{
										Names:      []string{"tigera_secure_ee_*.*.*", "calico_policy_activity.*"},
										Privileges: []string{"create_index", "write", "manage", "read"},
									},
								},
							},
						},
					},
				},
				"tigera-ee-dashboards-installer": {
					Username: "tigera-ee-dashboards-installer-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-dashboards-installer-secure",
						Definition: &elasticsearch.RoleDefinition{
							Indices: make([]elasticsearch.RoleIndex, 0),
							Applications: []elasticsearch.Application{{
								Application: "kibana-.kibana",
								Privileges:  []string{"all"},
								Resources:   []string{"*"},
							}},
						},
					}},
				},
			}

			expectedPublicUsers = map[users.ElasticsearchUserName]elasticsearch.User{
				"tigera-fluentd": {
					Username: "tigera-fluentd",
				},
				"tigera-eks-log-forwarder": {
					Username: "tigera-eks-log-forwarder",
				},
				"tigera-ee-compliance-benchmarker": {
					Username: "tigera-ee-compliance-benchmarker",
				},
				"tigera-ee-compliance-controller": {
					Username: "tigera-ee-compliance-controller",
				},
				"tigera-ee-compliance-reporter": {
					Username: "tigera-ee-compliance-reporter",
				},
				"tigera-ee-compliance-snapshotter": {
					Username: "tigera-ee-compliance-snapshotter",
				},
				"tigera-ee-intrusion-detection": {
					Username: "tigera-ee-intrusion-detection",
				},
				"tigera-ee-installer": {
					Username: "tigera-ee-installer",
				},
				"tigera-ee-ad-job": {
					Username: "tigera-ee-ad-job",
				},
				"tigera-ee-sasha": {
					Username: "tigera-ee-sasha",
				},
				"tigera-ee-performance-hotspots": {
					Username: "tigera-ee-performance-hotspots",
				},
				"tigera-ee-policy-recommendation": {
					Username: "tigera-ee-policy-recommendation",
				},
				"tigera-ee-compliance-server": {
					Username: "tigera-ee-compliance-server",
				},
				"tigera-ee-manager": {
					Username: "tigera-ee-manager",
				},
				"tigera-ee-operator": {
					Username: "tigera-ee-operator",
				},
				"tigera-ee-elasticsearch-metrics": {
					Username: "tigera-ee-elasticsearch-metrics",
				},
			}
		})
		It("the expected users and roles are available", func() {
			testElasticsearchUsers(privateUsers, publicUsers, expectedPrivateUsers, expectedPublicUsers)
		})
		It("the expected decommissioned users and roles are returned with no overlap with the active users", func() {
			decommissionedUsers := users.DecommissionedElasticsearchUsers("cluster")

			expectedDecommissionedUsers := map[users.ElasticsearchUserName]elasticsearch.User{
				"tigera-ee-curator": {
					Username: "tigera-ee-curator-secure",
					Roles: []elasticsearch.Role{{
						Name: "tigera-ee-curator-secure",
						Definition: &elasticsearch.RoleDefinition{
							Cluster: []string{"monitor", "manage_index_templates"},
							Indices: []elasticsearch.RoleIndex{{
								Names:      []string{"tigera_secure_ee_*.*.*", "tigera_secure_ee_events.*"},
								Privileges: []string{"all"},
							}},
						},
					}},
				},
			}

			testDecommissionedElasticsearchUsers(decommissionedUsers, expectedDecommissionedUsers, privateUsers, publicUsers)

		})
	})
})

func testDecommissionedElasticsearchUsers(decommissionedUsers, expectedDecommissionedUsers, privateUsers, publicUsers map[users.ElasticsearchUserName]elasticsearch.User) {

	// First check that expected decommissioned users match the actual decommissioned users
	Expect(len(decommissionedUsers)).Should(Equal(len(expectedDecommissionedUsers)))
	for expectedName, expectedUser := range expectedDecommissionedUsers {
		esUser, exists := decommissionedUsers[expectedName]
		Expect(exists).Should(BeTrue())
		Expect(esUser.Username).Should(Equal(expectedUser.Username))
		Expect(len(esUser.Roles)).Should(Equal(len(expectedUser.Roles)))

		for _, expectedRole := range expectedUser.Roles {
			foundRole := false
			for _, role := range esUser.Roles {
				if expectedRole.Name == role.Name {
					foundRole = true
					Expect(expectedRole.Definition).Should(Equal(role.Definition))
				}
			}
			Expect(foundRole).Should(BeTrue())
		}
	}

	// Now check that the decommissioned users are not in the active users
	for name := range decommissionedUsers {
		_, exists := privateUsers[name]
		Expect(exists).To(BeFalse())
		_, exists = publicUsers[name]
		Expect(exists).To(BeFalse())
	}
}

func testElasticsearchUsers(privateUsers, publicUsers, expectedprivateUsers, expectedpublicUsers map[users.ElasticsearchUserName]elasticsearch.User) {
	Expect(len(privateUsers)).Should(Equal(len(expectedprivateUsers)))
	Expect(len(publicUsers)).Should(Equal(len(expectedpublicUsers)))
	for expectedName, expectedUser := range expectedprivateUsers {
		esUser, exists := privateUsers[expectedName]
		Expect(exists).Should(BeTrue(), fmt.Sprintf("User %s does not exist", esUser.Username))
		Expect(esUser.Username).Should(Equal(expectedUser.Username))
		Expect(esUser.FullName).Should(Equal("system:serviceaccount"))

		Expect(len(esUser.Roles)).Should(Equal(len(expectedUser.Roles)))

		for _, expectedRole := range expectedUser.Roles {
			foundRole := false
			for _, role := range esUser.Roles {
				if expectedRole.Name == role.Name {
					foundRole = true
					Expect(expectedRole.Definition).Should(Equal(role.Definition))
				}
			}
			Expect(foundRole).Should(BeTrue())
		}
	}
	for expectedName, expectedUser := range publicUsers {
		esUser, exists := publicUsers[expectedName]
		Expect(exists).Should(BeTrue())
		Expect(esUser.Username).Should(Equal(expectedUser.Username))
		Expect(esUser.FullName).Should(Equal(expectedUser.FullName))

		Expect(len(esUser.Roles)).Should(Equal(len(expectedUser.Roles)))

		for _, expectedRole := range expectedUser.Roles {
			foundRole := false
			for _, role := range esUser.Roles {
				if expectedRole.Name == role.Name {
					foundRole = true
					Expect(expectedRole.Definition).Should(Equal(role.Definition))
				}
			}
			Expect(foundRole).Should(BeTrue())
		}
	}
}
