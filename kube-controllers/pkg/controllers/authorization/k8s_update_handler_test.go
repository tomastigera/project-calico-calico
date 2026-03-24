// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package authorization

import (
	"context"
	"fmt"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch/userscache"
	"github.com/projectcalico/calico/kube-controllers/pkg/rbaccache"
	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
)

var _ = Describe("role mapping listenAndSynchronize", func() {
	Context("Update ClusterRole", func() {
		DescribeTable(
			"ClusterRole rule conversion to elasticsearch role mapping",
			func(rules []rbacv1.PolicyRule, expectedRoleMapping elasticsearch.RoleMapping) {
				clusterRole := &rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-resource",
					},
				}

				mockESCLI := elasticsearch.NewMockClient()
				// Verify that the correct role mapping is created given whats returned from the cache
				mockESCLI.On("CreateRoleMapping", expectedRoleMapping).Return(nil)

				mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
				mockClusterRoleCache.On("AddClusterRole", clusterRole).Return(true)
				mockClusterRoleCache.On("ClusterRoleSubjects", clusterRole.Name, rbacv1.UserKind).Return([]rbacv1.Subject{{
					Kind: rbacv1.UserKind,
					Name: "user@test.com",
				}})
				mockClusterRoleCache.On("ClusterRoleSubjects", clusterRole.Name, rbacv1.GroupKind).Return([]rbacv1.Subject{{
					Kind: rbacv1.GroupKind,
					Name: "testgroup",
				}})
				// Return all the valid resource names so we can test the conversion or resource names to elasticsearch role names
				mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return(rules)

				resourceUpdates := make(chan resourceUpdate)
				synchronizer := createRoleMappingSynchronizer(mockClusterRoleCache, mockESCLI, "", "")
				updateHandler := k8sUpdateHandler{
					resourceUpdates: resourceUpdates,
					synchronizer:    synchronizer,
				}

				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					updateHandler.listenAndSynchronize()
				}()

				resourceUpdates <- resourceUpdate{
					typ:      resourceUpdated,
					name:     clusterRole.Name,
					resource: clusterRole,
				}

				close(resourceUpdates)

				wg.Wait()

				mockESCLI.AssertExpectations(GinkgoT())
			},
			Entry("The ClusterRole resource is *",
				[]rbacv1.PolicyRule{{
					APIGroups:     []string{"lma.tigera.io"},
					ResourceNames: []string{"flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7", "waf", "runtime", "kibana_login", "kibana_admin", "elasticsearch_superuser"},
					Resources:     []string{"*"},
				}},
				elasticsearch.RoleMapping{
					Name: "tigera-k8s-test-resource",
					Roles: []string{"flows_viewer", "audit_viewer", "audit_ee_viewer",
						"audit_kube_viewer", "events_viewer", "dns_viewer", "l7_viewer", "waf_viewer", "runtime_viewer", "kibana_viewer", "kibana_admin", "superuser",
					},
					Rules: map[string][]elasticsearch.Rule{
						"any": {
							{
								Field: map[string]string{
									"username": "user@test.com",
								},
							},
							{
								Field: map[string]string{
									"groups": "testgroup",
								},
							},
						},
					},
					Enabled: true,
				},
			),
			Entry("The ClusterRole resource is a specific list of clusters",
				[]rbacv1.PolicyRule{{
					APIGroups:     []string{"lma.tigera.io"},
					ResourceNames: []string{"flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7", "waf", "runtime", "kibana_login", "kibana_admin", "elasticsearch_superuser"},
					Resources:     []string{"cluster_1", "cluster_2"},
				}},
				elasticsearch.RoleMapping{
					Name: "tigera-k8s-test-resource",
					Roles: []string{
						"flows_viewer_cluster_1", "audit_viewer_cluster_1", "audit_ee_viewer_cluster_1", "audit_kube_viewer_cluster_1",
						"events_viewer_cluster_1", "dns_viewer_cluster_1", "l7_viewer_cluster_1", "waf_viewer_cluster_1", "runtime_viewer_cluster_1", "flows_viewer_cluster_2", "audit_viewer_cluster_2",
						"audit_ee_viewer_cluster_2", "audit_kube_viewer_cluster_2", "events_viewer_cluster_2", "dns_viewer_cluster_2",
						"l7_viewer_cluster_2", "waf_viewer_cluster_2", "runtime_viewer_cluster_2", "kibana_viewer", "kibana_admin", "superuser",
					},
					Rules: map[string][]elasticsearch.Rule{
						"any": {
							{
								Field: map[string]string{
									"username": "user@test.com",
								},
							},
							{
								Field: map[string]string{
									"groups": "testgroup",
								},
							},
						},
					},
					Enabled: true,
				},
			),
			Entry("The ClusterRole has no resource names",
				[]rbacv1.PolicyRule{{
					APIGroups: []string{"lma.tigera.io"},
					Resources: []string{"*"},
				}},
				elasticsearch.RoleMapping{
					Name:  "tigera-k8s-test-resource",
					Roles: []string{"flows_viewer", "audit_viewer", "events_viewer", "dns_viewer", "l7_viewer", "waf_viewer", "runtime_viewer"},
					Rules: map[string][]elasticsearch.Rule{
						"any": {
							{
								Field: map[string]string{
									"username": "user@test.com",
								},
							},
							{
								Field: map[string]string{
									"groups": "testgroup",
								},
							},
						},
					},
					Enabled: true,
				},
			),
		)
	})

	Context("Update ClusterRoleBinding", func() {
		It("Triggers a role synchronization when the ClusterRoleBinding is added", func() {
			clusterRoleBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-binding",
				},
				RoleRef: rbacv1.RoleRef{
					Name: "test-role",
				},
			}

			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("CreateRoleMapping", mock.Anything).Return(nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("AddClusterRoleBinding", clusterRoleBinding).Return(true)
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleBinding.RoleRef.Name, rbacv1.UserKind).Return([]rbacv1.Subject{{
				Kind: rbacv1.UserKind,
				Name: "user@test.com",
			}})
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleBinding.RoleRef.Name, rbacv1.GroupKind).Return([]rbacv1.Subject{{
				Kind: rbacv1.GroupKind,
				Name: "testgroup",
			}})
			// Return all the valid resource names so we can test the conversion or resource names to elasticsearch role names
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "waf", "runtime", "kibana_login", "elasticsearch_superuser"},
				Resources:     []string{"*"},
			}})

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createRoleMappingSynchronizer(mockClusterRoleCache, mockESCLI, "", "")

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			resourceUpdates <- resourceUpdate{
				typ:      resourceUpdated,
				name:     clusterRoleBinding.Name,
				resource: clusterRoleBinding,
			}

			close(resourceUpdates)

			wg.Wait()

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})

	Context("Delete ClusterRole", func() {
		clusterRoleName := "test-cluster-role"
		mockESCLI := elasticsearch.NewMockClient()
		// Verify that the correct role mapping is created given whats returned from the cache
		mockESCLI.On("DeleteRoleMapping", "tigera-k8s-test-cluster-role").Return(true, nil)

		mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
		mockClusterRoleCache.On("RemoveClusterRole", clusterRoleName).Return(true)

		mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.UserKind).Return([]rbacv1.Subject{})
		mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.GroupKind).Return([]rbacv1.Subject{})
		// Return all the valid resource names so we can test the conversion or resource names to elasticsearch role names
		mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{})
		mockClusterRoleCache.On("ClusterRoleBindingsForClusterRole", mock.Anything).Return([]string{})

		resourceUpdates := make(chan resourceUpdate)
		synchronizer := createRoleMappingSynchronizer(mockClusterRoleCache, mockESCLI, "", "")

		updateHandler := k8sUpdateHandler{
			resourceUpdates: resourceUpdates,
			synchronizer:    synchronizer,
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			updateHandler.listenAndSynchronize()
		}()

		var clusterRole *rbacv1.ClusterRole
		resourceUpdates <- resourceUpdate{
			typ:      resourceDeleted,
			name:     clusterRoleName,
			resource: clusterRole,
		}

		close(resourceUpdates)

		wg.Wait()

		mockESCLI.AssertExpectations(GinkgoT())
	})

	Context("Delete ClusterRoleBinding", func() {
		clusterRoleBindingName := "test-cluster-role-binding"
		clusterRoleName := "test-cluster-role"

		mockESCLI := elasticsearch.NewMockClient()
		// Verify that the correct role mapping is created given whats returned from the cache
		mockESCLI.On("DeleteRoleMapping", "tigera-k8s-test-cluster-role").Return(true, nil)

		mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
		mockClusterRoleCache.On("RemoveClusterRoleBinding", clusterRoleBindingName).Return(true)
		mockClusterRoleCache.On("ClusterRoleNameForBinding", clusterRoleBindingName).Return(clusterRoleName)

		mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.UserKind).Return([]rbacv1.Subject{})
		mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.GroupKind).Return([]rbacv1.Subject{})
		// Return all the valid resource names so we can test the conversion or resource names to elasticsearch role names
		mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{})

		resourceUpdates := make(chan resourceUpdate)
		synchronizer := createRoleMappingSynchronizer(mockClusterRoleCache, mockESCLI, "", "")

		updateHandler := k8sUpdateHandler{
			resourceUpdates: resourceUpdates,
			synchronizer:    synchronizer,
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			updateHandler.listenAndSynchronize()
		}()

		var clusterRoleBinding *rbacv1.ClusterRoleBinding
		resourceUpdates <- resourceUpdate{
			typ:      resourceDeleted,
			name:     clusterRoleBindingName,
			resource: clusterRoleBinding,
		}

		close(resourceUpdates)

		wg.Wait()

		mockESCLI.AssertExpectations(GinkgoT())
	})

	Context("claim prefixes", func() {
		It("usernamePrefix and groupPrefix are stripped from user and group names before mappings are created for them", func() {
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-resource",
				},
			}

			mockESCLI := elasticsearch.NewMockClient()
			// Verify that the correct role mapping is created given whats returned from the cache
			mockESCLI.On("CreateRoleMapping", elasticsearch.RoleMapping{
				Name:  "tigera-k8s-test-resource",
				Roles: []string{"flows_viewer", "audit_viewer", "events_viewer", "dns_viewer", "l7_viewer", "waf_viewer", "runtime_viewer"},
				Rules: map[string][]elasticsearch.Rule{
					"any": {
						{
							Field: map[string]string{
								"username": "user@test.com",
							},
						},
						{
							Field: map[string]string{
								"groups": "testgroup",
							},
						},
					},
				},
				Enabled: true,
			}).Return(nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("AddClusterRole", clusterRole).Return(true)
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRole.Name, rbacv1.UserKind).Return([]rbacv1.Subject{{
				Kind: rbacv1.UserKind,
				Name: "oidc:user@test.com",
			}})
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRole.Name, rbacv1.GroupKind).Return([]rbacv1.Subject{{
				Kind: rbacv1.GroupKind,
				Name: "oidc:testgroup",
			}})
			// Return all the valid resource names so we can test the conversion or resource names to elasticsearch role names
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{{
				APIGroups: []string{"lma.tigera.io"},
				Resources: []string{"*"},
			}})

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createRoleMappingSynchronizer(mockClusterRoleCache, mockESCLI, "oidc:", "oidc:")

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			resourceUpdates <- resourceUpdate{
				typ:      resourceUpdated,
				name:     clusterRole.Name,
				resource: clusterRole,
			}

			close(resourceUpdates)

			wg.Wait()

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})

	Context("resync", func() {
		It("Deletes an Elasticsearch role mapping with a proper associated ClusterRole", func() {
			mockESCLI := elasticsearch.NewMockClient()
			// Verify that the correct role mapping is created given whats returned from the cache
			mockESCLI.On("GetRoleMappings").Return([]elasticsearch.RoleMapping{
				{Name: "tigera-k8s-test-1-cluster-role"},
				{Name: "tigera-k8s-test-2-cluster-role"},
			}, nil)
			mockESCLI.On("DeleteRoleMapping", "tigera-k8s-test-1-cluster-role").Return(true, nil)
			mockESCLI.On("CreateRoleMapping", mock.Anything).Return(nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("ClusterRoleNamesWithBindings").Return([]string{"test-2-cluster-role"})
			mockClusterRoleCache.On("ClusterRoleSubjects", "test-2-cluster-role", rbacv1.UserKind).Return([]rbacv1.Subject{{
				Kind: rbacv1.UserKind,
				Name: "oidc:user@test.com",
			}})
			mockClusterRoleCache.On("ClusterRoleSubjects", "test-2-cluster-role", rbacv1.GroupKind).Return([]rbacv1.Subject{{
				Kind: rbacv1.GroupKind,
				Name: "oidc:testgroup",
			}})
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{{
				APIGroups: []string{"lma.tigera.io"},
				Resources: []string{"*"},
			}})

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createRoleMappingSynchronizer(mockClusterRoleCache, mockESCLI, "", "")

			k8sUpdateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			Expect(k8sUpdateHandler.synchronizer.resync()).ShouldNot(HaveOccurred())

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})
})

var _ = Describe("native user listenAndSynchronize", func() {
	BeforeEach(func() {
		esUserPrefix = "tigera-k8s-"
	})
	Context("Update ConfigMap", func() {
		It("deletes elasticsearch native users if ClusterRole doesn't exist", func() {
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersConfigMapName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string]string{
					"randomSubjectId1": "{\"username\":\"testuser1\", \"groups\":[\"group1\",\"group2\"]}",
				},
			}
			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("DeleteUser", mock.Anything).Return(nil)
			mockESCLI.On("UserExists", "tigera-k8s-randomSubjectId1").Return(false, fmt.Errorf("random error"))

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", mock.Anything).Return([]string{})
			mockUserCache := userscache.NewMockOIDCUserCache()
			data, err := configMapDataToOIDCUsers(configMap.Data)
			Expect(err).ShouldNot(HaveOccurred())
			mockUserCache.On("UpdateOIDCUsers", data).Return([]string{"randomSubjectId1"})
			mockUserCache.On("Exists", "randomSubjectId1").Return(true)
			mockUserCache.On("SubjectIDToUserOrGroups", "randomSubjectId1").Return([]string{"group1", "group2", "testuser1"})
			mockUserCache.On("DeleteOIDCUser", mock.Anything).Return(true)

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string][]byte{
					"randomSubjectId1": []byte("Hello"),
				},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			resourceUpdates <- resourceUpdate{
				typ:      resourceUpdated,
				name:     resource.OIDCUsersConfigMapName,
				resource: configMap,
			}

			close(resourceUpdates)

			wg.Wait()

			actualOidcSecret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(actualOidcSecret.Data["randomSubjectId1"]).Should(BeNil())

			mockESCLI.AssertExpectations(GinkgoT())

		})

		It("creates/updates elasticsearch native users", func() {
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersConfigMapName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string]string{
					"randomSubjectId1": "{\"username\":\"testuser1\", \"groups\":[\"group1\",\"group2\"]}",
				},
			}

			rules := []rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7", "waf", "runtime", "kibana_login", "kibana_admin", "elasticsearch_superuser"},
				Resources:     []string{"*"},
			}}
			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("UserExists", "tigera-k8s-randomSubjectId1").Return(false, fmt.Errorf("random error"))
			mockESCLI.On("UpdateUser", mock.Anything).Return(nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group2").Return([]string{"test-cluster-role-1"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "testuser1").Return([]string{"test-cluster-role-2"})
			mockClusterRoleCache.On("ClusterRoleRules", "test-cluster-role-1").Return(rules)
			mockClusterRoleCache.On("ClusterRoleRules", "test-cluster-role-2").Return([]rbacv1.PolicyRule{})

			mockUserCache := userscache.NewMockOIDCUserCache()
			data, err := configMapDataToOIDCUsers(configMap.Data)
			Expect(err).ShouldNot(HaveOccurred())
			mockUserCache.On("UpdateOIDCUsers", data).Return([]string{"randomSubjectId1"})
			mockUserCache.On("Exists", "randomSubjectId1").Return(true)
			mockUserCache.On("SubjectIDToUserOrGroups", "randomSubjectId1").Return([]string{"group1", "group2", "testuser1"})

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			resourceUpdates <- resourceUpdate{
				typ:      resourceUpdated,
				name:     resource.OIDCUsersConfigMapName,
				resource: configMap,
			}

			close(resourceUpdates)

			wg.Wait()

			secret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(secret.Data["randomSubjectId1"]).ShouldNot(BeNil())

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})

	Context("Update ClusterRole", func() {
		It("creates/updates elasticsearch native users", func() {
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersConfigMapName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string]string{
					"randomSubjectId1": "{\"username\":\"user@test.com\", \"groups\":[\"testgroup\",\"group2\"]}",
				},
			}
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
			}
			rules := []rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7", "waf", "runtime", "kibana_login", "kibana_admin", "elasticsearch_superuser"},
				Resources:     []string{"cluster_1", "cluster_2"},
			}}

			mockESCLI := elasticsearch.NewMockClient()
			expectedEsRoles := []elasticsearch.Role{
				{Name: "flows_viewer_cluster_1"}, {Name: "audit_viewer_cluster_1"}, {Name: "audit_ee_viewer_cluster_1"},
				{Name: "audit_kube_viewer_cluster_1"}, {Name: "events_viewer_cluster_1"}, {Name: "dns_viewer_cluster_1"},
				{Name: "l7_viewer_cluster_1"}, {Name: "flows_viewer_cluster_2"}, {Name: "audit_viewer_cluster_2"},
				{Name: "audit_ee_viewer_cluster_2"}, {Name: "audit_kube_viewer_cluster_2"}, {Name: "events_viewer_cluster_2"},
				{Name: "dns_viewer_cluster_2"}, {Name: "l7_viewer_cluster_2"}, {Name: "kibana_viewer"},
				{Name: "kibana_admin"}, {Name: "superuser"},
			}

			mockESCLI.On("UserExists", "tigera-k8s-randomSubjectId1").Return(false, fmt.Errorf("random error"))
			mockESCLI.On("UpdateUser", mock.Anything).Run(func(args mock.Arguments) {
				arg := args.Get(0).(elasticsearch.User)
				for _, c := range mockESCLI.ExpectedCalls {
					if c.Method == "UpdateUser" {
						Expect(arg.Roles).Should(ContainElements(expectedEsRoles))
						c.ReturnArguments = mock.Arguments{nil}
					}
				}
			})

			//mockESCLI.On("UpdateUser", mock.Anything).Return(nil)
			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("AddClusterRole", clusterRole).Return(true)
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRole.Name, rbacv1.UserKind).Return([]rbacv1.Subject{{
				Kind: rbacv1.UserKind,
				Name: "user@test.com",
			}})
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRole.Name, rbacv1.GroupKind).Return([]rbacv1.Subject{{
				Kind: rbacv1.GroupKind,
				Name: "testgroup",
			}})

			// Return all the valid resource names so we can test the conversion or resource names to elasticsearch role names
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return(rules)
			mockClusterRoleCache.On("SubjectNamesForBinding", "test-cluster-role-binding").Return([]string{"user@test.com"})
			mockClusterRoleCache.On("ClusterRoleBindingsForClusterRole", "test-cluster-role").Return([]string{"test-cluster-role-binding"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "user@test.com").Return([]string{"test-cluster-role"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "testgroup").Return([]string{"test-cluster-role"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group2").Return([]string{})

			mockUserCache := userscache.NewMockOIDCUserCache()
			data, err := configMapDataToOIDCUsers(configMap.Data)
			Expect(err).ShouldNot(HaveOccurred())

			mockUserCache.On("UpdateOIDCUsers", data).Return([]string{"randomSubjectId1"})
			mockUserCache.On("Exists", "randomSubjectId1").Return(true)
			mockUserCache.On("SubjectIDToUserOrGroups", "randomSubjectId1").Return([]string{"user@test.com", "testgroup", "group2"})
			mockUserCache.On("UserOrGroupToSubjectIDs", "user@test.com").Return([]string{"randomSubjectId1"})
			mockUserCache.On("UserOrGroupToSubjectIDs", "testgroup").Return([]string{"randomSubjectId1"})
			mockUserCache.On("UserOrGroupToSubjectIDs", "group2").Return([]string{})

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			resourceUpdates <- resourceUpdate{
				typ:      resourceUpdated,
				name:     clusterRole.Name,
				resource: clusterRole,
			}

			close(resourceUpdates)

			wg.Wait()

			secret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(secret.Data["randomSubjectId1"]).ShouldNot(BeNil())

			actualOidcSecret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(actualOidcSecret.Data).ShouldNot(BeNil())

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})

	Context("Update ClusterRoleBinding", func() {
		It("creates/updates elasticsearch native users", func() {
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersConfigMapName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string]string{
					"randomSubjectId1": "{\"username\":\"user@test.com\", \"groups\":[\"testgroup\",\"group2\"]}",
				},
			}
			clusterRoleBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-binding",
				},
				RoleRef: rbacv1.RoleRef{
					Name: "test-role",
				},
			}

			mockESCLI := elasticsearch.NewMockClient()

			expectedEsRoles := []elasticsearch.Role{
				{Name: "events_viewer"}, {Name: "dns_viewer"}, {Name: "kibana_viewer"}, {Name: "superuser"},
				{Name: "flows_viewer"}, {Name: "audit_viewer"}, {Name: "audit_ee_viewer"},
				{Name: "audit_kube_viewer"},
			}

			mockESCLI.On("UserExists", "tigera-k8s-randomSubjectId1").Return(false, nil)
			mockESCLI.On("UpdateUser", mock.Anything).Run(func(args mock.Arguments) {
				arg := args.Get(0).(elasticsearch.User)
				for _, c := range mockESCLI.ExpectedCalls {
					if c.Method == "UpdateUser" {
						Expect(arg.Roles).Should(ContainElements(expectedEsRoles))
						c.ReturnArguments = mock.Arguments{nil}
					}
				}
			})

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("AddClusterRoleBinding", clusterRoleBinding).Return(true)
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleBinding.RoleRef.Name, rbacv1.UserKind).Return([]rbacv1.Subject{{
				Kind: rbacv1.UserKind,
				Name: "user@test.com",
			}})
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleBinding.RoleRef.Name, rbacv1.GroupKind).Return([]rbacv1.Subject{{
				Kind: rbacv1.GroupKind,
				Name: "testgroup",
			}})
			// Return all the valid resource names so we can test the conversion or resource names to elasticsearch role names
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "kibana_login", "elasticsearch_superuser"},
				Resources:     []string{"*"},
			}})
			mockClusterRoleCache.On("ClusterRoleBindingsForClusterRole", mock.Anything).Return([]string{clusterRoleBinding.Name})
			mockClusterRoleCache.On("SubjectNamesForBinding", clusterRoleBinding.Name).Return([]string{"user@test.com", "testgroup"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "user@test.com").Return([]string{"test-cluster-role"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "testgroup").Return([]string{"test-cluster-role"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group2").Return([]string{})

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			mockUserCache := userscache.NewMockOIDCUserCache()
			data, err := configMapDataToOIDCUsers(configMap.Data)
			Expect(err).ShouldNot(HaveOccurred())
			mockUserCache.On("UpdateOIDCUsers", data).Return([]string{"randomSubjectId1"})
			mockUserCache.On("Exists", "randomSubjectId1").Return(true)
			mockUserCache.On("UserOrGroupToSubjectIDs", "user@test.com").Return([]string{"randomSubjectId1"})
			mockUserCache.On("UserOrGroupToSubjectIDs", "testgroup").Return([]string{"randomSubjectId1"})
			mockUserCache.On("SubjectIDToUserOrGroups", "randomSubjectId1").Return([]string{"user@test.com", "testgroup", "group2"})

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			resourceUpdates <- resourceUpdate{
				typ:      resourceUpdated,
				name:     clusterRoleBinding.Name,
				resource: clusterRoleBinding,
			}

			close(resourceUpdates)

			wg.Wait()

			secret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(secret.Data["randomSubjectId1"]).ShouldNot(BeNil())

			actualOidcSecret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(actualOidcSecret.Data).ShouldNot(BeNil())

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})

	Context("Delete ConfigMap", func() {
		It("deletes user from elasticsearch and also deletes k8s Secret", func() {
			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("DeleteUser", elasticsearch.User{Username: "tigera-k8s-subId1"}).Return(nil)
			mockESCLI.On("DeleteUser", elasticsearch.User{Username: "tigera-k8s-subId2"}).Return(nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("SubjectIDs").Return([]string{"subId1", "subId2"})
			mockUserCache.On("Exists", mock.Anything).Return(false)

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string][]byte{
					"subId1": []byte("Hello"),
				},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			resourceUpdates <- resourceUpdate{
				typ:  resourceDeleted,
				name: resource.OIDCUsersConfigMapName,
				resource: &corev1.ConfigMap{
					TypeMeta: metav1.TypeMeta{Kind: "ConfigMap"},
				},
			}

			close(resourceUpdates)
			wg.Wait()

			_, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).Should(HaveOccurred())

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})

	Context("Delete Secret", func() {
		It("re-creates the Secret and populates the password for users in cache", func() {
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersConfigMapName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string]string{
					"randomSubjectId1": "{\"username\":\"testuser1\", \"groups\":[\"group1\",\"group2\"]}",
				},
			}

			rules := []rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7", "kibana_login", "kibana_admin", "elasticsearch_superuser"},
				Resources:     []string{"*"},
			}}
			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("UpdateUser", mock.Anything).Return(nil)
			mockESCLI.On("UserExists", "tigera-k8s-randomSubjectId1").Return(false, nil)
			mockESCLI.On("GetUsers").Return([]elasticsearch.User{
				{Username: "tigera-k8s-randomSubjectId1"},
			}, nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group2").Return([]string{"test-cluster-role-1"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "testuser1").Return([]string{"test-cluster-role-2"})
			mockClusterRoleCache.On("ClusterRoleRules", "test-cluster-role-1").Return(rules)
			mockClusterRoleCache.On("ClusterRoleRules", "test-cluster-role-2").Return([]rbacv1.PolicyRule{})

			mockUserCache := userscache.NewMockOIDCUserCache()
			data, err := configMapDataToOIDCUsers(configMap.Data)
			Expect(err).ShouldNot(HaveOccurred())
			mockUserCache.On("UpdateOIDCUsers", data).Return([]string{"randomSubjectId1"})
			mockUserCache.On("Exists", "randomSubjectId1").Return(true)
			mockUserCache.On("SubjectIDs").Return([]string{"randomSubjectId1"})
			mockUserCache.On("SubjectIDToUserOrGroups", "randomSubjectId1").Return([]string{"group1", "group2", "testuser1"})

			fakeK8CLI := k8sfake.NewClientset()

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			resourceUpdates <- resourceUpdate{
				typ:  resourceDeleted,
				name: resource.OIDCUsersEsSecreteName,
				resource: &corev1.Secret{
					TypeMeta: metav1.TypeMeta{Kind: "Secret"},
				},
			}

			close(resourceUpdates)
			wg.Wait()

			secret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(secret.Data["randomSubjectId1"]).ShouldNot(BeNil())

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})

	Context("Delete ClusterRole", func() {
		It("delete user from elasticsearch if no clusterrole is left for the user", func() {
			clusterRoleName := "test-cluster-role"

			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("DeleteUser", mock.Anything).Return(nil)
			mockESCLI.On("UserExists", "tigera-k8s-subId1").Return(false, fmt.Errorf("random error"))

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("RemoveClusterRole", clusterRoleName).Return(true)
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.UserKind).Return([]rbacv1.Subject{})
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.GroupKind).Return([]rbacv1.Subject{})
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{})
			mockClusterRoleCache.On("ClusterRoleBindingsForClusterRole", clusterRoleName).Return([]string{"test-cluster-role-binding"})
			mockClusterRoleCache.On("SubjectNamesForBinding", "test-cluster-role-binding").Return([]string{"group1"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{})

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("Exists", mock.Anything).Return(true)
			mockUserCache.On("UserOrGroupToSubjectIDs", "group1").Return([]string{"subId1"})
			mockUserCache.On("SubjectIDToUserOrGroups", "subId1").Return([]string{"group1"})
			mockUserCache.On("DeleteOIDCUser", "subId1").Return(true)

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string][]byte{
					"subId1": []byte("Hello"),
				},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			var clusterRole *rbacv1.ClusterRole
			resourceUpdates <- resourceUpdate{
				typ:      resourceDeleted,
				name:     clusterRoleName,
				resource: clusterRole,
			}

			close(resourceUpdates)
			wg.Wait()

			actualOidcSecret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(actualOidcSecret.Data["subId1"]).Should(BeNil())

			mockESCLI.AssertExpectations(GinkgoT())
		})

		It("updates elasticsearch user", func() {
			clusterRoleName := "test-cluster-role"

			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("UserExists", mock.Anything).Return(false, nil)
			mockESCLI.On("UpdateUser", mock.Anything).Return(nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("RemoveClusterRole", clusterRoleName).Return(true)
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.UserKind).Return([]rbacv1.Subject{})
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.GroupKind).Return([]rbacv1.Subject{})
			mockClusterRoleCache.On("ClusterRoleRules", clusterRoleName).Return([]rbacv1.PolicyRule{})
			mockClusterRoleCache.On("ClusterRoleRules", "test-cluster-role-2").Return([]rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "kibana_login", "elasticsearch_superuser"},
				Resources:     []string{"*"},
			}})
			mockClusterRoleCache.On("ClusterRoleBindingsForClusterRole", clusterRoleName).Return([]string{"test-cluster-role-binding"})
			mockClusterRoleCache.On("SubjectNamesForBinding", "test-cluster-role-binding").Return([]string{"group1"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{"test-cluster-role-2"})

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("Exists", mock.Anything).Return(true)
			mockUserCache.On("UserOrGroupToSubjectIDs", "group1").Return([]string{"subId1"})
			mockUserCache.On("SubjectIDToUserOrGroups", "subId1").Return([]string{"group1"})

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			var clusterRole *rbacv1.ClusterRole
			resourceUpdates <- resourceUpdate{
				typ:      resourceDeleted,
				name:     clusterRoleName,
				resource: clusterRole,
			}

			close(resourceUpdates)
			wg.Wait()

			secret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(secret.Data["subId1"]).ShouldNot(BeNil())

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})

	Context("Delete ClusterRoleBinding", func() {
		It("deletes elsticserach native users if there are no roles and deletes password from Secret", func() {
			clusterRoleBindingName := "test-cluster-role-binding"
			clusterRoleName := "test-cluster-role"

			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("DeleteUser", mock.Anything).Return(nil)
			mockESCLI.On("UserExists", mock.Anything).Return(false, nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("RemoveClusterRoleBinding", clusterRoleBindingName).Return(true)
			mockClusterRoleCache.On("ClusterRoleNameForBinding", clusterRoleBindingName).Return(clusterRoleName)
			mockClusterRoleCache.On("ClusterRoleBindingsForClusterRole", clusterRoleName).Return([]string{clusterRoleBindingName})
			mockClusterRoleCache.On("SubjectNamesForBinding", clusterRoleBindingName).Return([]string{"group1"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{})

			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.UserKind).Return([]rbacv1.Subject{})
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.GroupKind).Return([]rbacv1.Subject{})
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{})

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("Exists", mock.Anything).Return(true)
			mockUserCache.On("UserOrGroupToSubjectIDs", "group1").Return([]string{"subId1"})
			mockUserCache.On("SubjectIDToUserOrGroups", "subId1").Return([]string{"group1"})
			mockUserCache.On("DeleteOIDCUser", "subId1").Return(true)

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string][]byte{
					"subId1": []byte("Hello"),
				},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			var clusterRoleBinding *rbacv1.ClusterRoleBinding
			resourceUpdates <- resourceUpdate{
				typ:      resourceDeleted,
				name:     clusterRoleBindingName,
				resource: clusterRoleBinding,
			}

			close(resourceUpdates)
			wg.Wait()

			secret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(secret.Data["subId1"]).Should(BeNil())

			mockESCLI.AssertExpectations(GinkgoT())
		})

		It("deletes elsticserach native users if there are no roles and ignore deleting password if Secret doesn't exist", func() {
			clusterRoleBindingName := "test-cluster-role-binding"
			clusterRoleName := "test-cluster-role"

			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("DeleteUser", mock.Anything).Return(nil)
			mockESCLI.On("UserExists", mock.Anything).Return(false, nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("RemoveClusterRoleBinding", clusterRoleBindingName).Return(true)
			mockClusterRoleCache.On("ClusterRoleNameForBinding", clusterRoleBindingName).Return(clusterRoleName)
			mockClusterRoleCache.On("ClusterRoleBindingsForClusterRole", clusterRoleName).Return([]string{clusterRoleBindingName})
			mockClusterRoleCache.On("SubjectNamesForBinding", clusterRoleBindingName).Return([]string{"group1"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{})

			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.UserKind).Return([]rbacv1.Subject{})
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.GroupKind).Return([]rbacv1.Subject{})
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{})

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("Exists", mock.Anything).Return(true)
			mockUserCache.On("UserOrGroupToSubjectIDs", "group1").Return([]string{"subId1"})
			mockUserCache.On("SubjectIDToUserOrGroups", "subId1").Return([]string{"group1"})
			mockUserCache.On("DeleteOIDCUser", "subId1").Return(true)

			fakeK8CLI := k8sfake.NewClientset()

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			var clusterRoleBinding *rbacv1.ClusterRoleBinding
			resourceUpdates <- resourceUpdate{
				typ:      resourceDeleted,
				name:     clusterRoleBindingName,
				resource: clusterRoleBinding,
			}

			close(resourceUpdates)
			wg.Wait()

			_, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).Should(HaveOccurred())

			mockESCLI.AssertExpectations(GinkgoT())
		})

		It("updates elsticserach native users", func() {
			clusterRoleBindingName := "test-cluster-role-binding"
			clusterRoleName := "test-cluster-role"

			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("UserExists", mock.Anything).Return(false, nil)
			mockESCLI.On("UpdateUser", mock.Anything).Return(nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("RemoveClusterRoleBinding", clusterRoleBindingName).Return(true)
			mockClusterRoleCache.On("ClusterRoleNameForBinding", clusterRoleBindingName).Return(clusterRoleName)
			mockClusterRoleCache.On("ClusterRoleBindingsForClusterRole", clusterRoleName).Return([]string{clusterRoleBindingName})
			mockClusterRoleCache.On("SubjectNamesForBinding", clusterRoleBindingName).Return([]string{"group1"})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{})
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group2").Return([]string{"test-role-2"})

			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.UserKind).Return([]rbacv1.Subject{})
			mockClusterRoleCache.On("ClusterRoleSubjects", clusterRoleName, rbacv1.GroupKind).Return([]rbacv1.Subject{})
			mockClusterRoleCache.On("ClusterRoleRules", clusterRoleName).Return([]rbacv1.PolicyRule{})
			mockClusterRoleCache.On("ClusterRoleRules", "test-role-2").Return([]rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows"},
				Resources:     []string{"*"},
			}})

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("Exists", mock.Anything).Return(true)
			mockUserCache.On("UserOrGroupToSubjectIDs", "group1").Return([]string{"subId1"})
			mockUserCache.On("SubjectIDToUserOrGroups", "subId1").Return([]string{"group1", "group2"})

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				updateHandler.listenAndSynchronize()
			}()

			var clusterRoleBinding *rbacv1.ClusterRoleBinding
			resourceUpdates <- resourceUpdate{
				typ:      resourceDeleted,
				name:     clusterRoleBindingName,
				resource: clusterRoleBinding,
			}

			close(resourceUpdates)
			wg.Wait()

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})

	Context("resync", func() {
		It("Delete Elasticsearch native users that are not in ConfigMap and creates missing native users", func() {
			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("GetUsers").Return([]elasticsearch.User{
				{Username: "tigera-k8s-xyz-1"},
				{Username: "tigera-k8s-xyz-2"},
			}, nil)
			mockESCLI.On("DeleteUser", elasticsearch.User{Username: "tigera-k8s-xyz-1"}).Return(nil)
			mockESCLI.On("UserExists", mock.Anything).Return(false, nil)
			mockESCLI.On("UpdateUser", mock.Anything).Run(func(args mock.Arguments) {
				arg := args.Get(0).(elasticsearch.User)
				for _, c := range mockESCLI.ExpectedCalls {
					if c.Method == "UpdateUser" {
						if arg.Username == "tigera-k8s-xyz-2" || arg.Username == "tigera-k8s-xyz-3" {
							c.ReturnArguments = mock.Arguments{nil}
						} else {
							c.ReturnArguments = mock.Arguments{fmt.Errorf("unxpected test input")}
						}
					}
				}
			})

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{"role-1"})
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "kibana_login", "elasticsearch_superuser"},
				Resources:     []string{"*"},
			}})

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("Exists", "xyz-1").Return(false)
			mockUserCache.On("Exists", "xyz-2").Return(true)
			mockUserCache.On("Exists", "xyz-3").Return(true)
			mockUserCache.On("SubjectIDs").Return([]string{"xyz-2", "xyz-3"})
			mockUserCache.On("SubjectIDToUserOrGroups", mock.Anything).Return([]string{"group1"})

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			Expect(updateHandler.synchronizer.resync()).ShouldNot(HaveOccurred())
			actualOidcSecret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(actualOidcSecret.Data["xyz-2"]).ShouldNot(BeNil())
			Expect(actualOidcSecret.Data["xyz-3"]).ShouldNot(BeNil())

			mockESCLI.AssertExpectations(GinkgoT())
		})

		It("If user exists in elasticsearch and password exists in k8s Secret, do not recreate password", func() {
			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("GetUsers").Return([]elasticsearch.User{
				{Username: "tigera-k8s-xyz-1", Roles: []elasticsearch.Role{{Name: "kibana_viewer"}, {Name: "superuser"}, {Name: "flows_viewer"}}},
			}, nil)
			mockESCLI.On("UserExists", "tigera-k8s-xyz-1").Return(true, nil)
			mockESCLI.On("UpdateUser", mock.Anything).Run(func(args mock.Arguments) {
				arg := args.Get(0).(elasticsearch.User)
				for _, c := range mockESCLI.ExpectedCalls {
					if c.Method == "UpdateUser" {
						Expect(arg.Password).Should(BeEmpty())
						c.ReturnArguments = mock.Arguments{nil}
					}
				}
			})

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{"role-1"})
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "kibana_login", "elasticsearch_superuser"},
				Resources:     []string{"*"},
			}})

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("Exists", "xyz-1").Return(true)
			mockUserCache.On("SubjectIDs").Return([]string{"xyz-1"})
			mockUserCache.On("SubjectIDToUserOrGroups", mock.Anything).Return([]string{"group1"})

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string][]byte{
					"xyz-1": []byte("Hello"),
				},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			Expect(updateHandler.synchronizer.resync()).ShouldNot(HaveOccurred())

			actualOidcSecret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(actualOidcSecret.Data).Should(BeEquivalentTo(oidcSecret.Data))
			mockESCLI.AssertExpectations(GinkgoT())
		})

		It("If user exists in elasticsearch and password does not exist in k8s Secret, recreate password", func() {
			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("GetUsers").Return([]elasticsearch.User{
				{Username: "tigera-k8s-xyz-1", Roles: []elasticsearch.Role{{Name: "kibana_viewer"}, {Name: "superuser"}, {Name: "flows_viewer"}}},
			}, nil)
			mockESCLI.On("UserExists", "tigera-k8s-xyz-1").Return(true, nil)
			mockESCLI.On("UpdateUser", mock.Anything).Run(func(args mock.Arguments) {
				arg := args.Get(0).(elasticsearch.User)
				for _, c := range mockESCLI.ExpectedCalls {
					if c.Method == "UpdateUser" {
						Expect(arg.Password).Should(BeEmpty())
						c.ReturnArguments = mock.Arguments{nil}
					}
				}
			})
			mockESCLI.On("SetUserPassword", mock.Anything).Return(nil)

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{"role-1"})
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "kibana_login", "elasticsearch_superuser"},
				Resources:     []string{"*"},
			}})

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("Exists", "xyz-1").Return(true)
			mockUserCache.On("SubjectIDs").Return([]string{"xyz-1"})
			mockUserCache.On("SubjectIDToUserOrGroups", mock.Anything).Return([]string{"group1"})

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			Expect(updateHandler.synchronizer.resync()).ShouldNot(HaveOccurred())

			actualOidcSecret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(actualOidcSecret.Data["xyz-1"]).ShouldNot(BeNil())
			mockESCLI.AssertExpectations(GinkgoT())
		})

		It("If user does not exists in elasticsearch and password does not exist in k8s Secret, recreate password", func() {
			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("GetUsers").Return([]elasticsearch.User{}, nil)
			mockESCLI.On("UserExists", "tigera-k8s-xyz-1").Return(false, nil)
			mockESCLI.On("UpdateUser", mock.Anything).Run(func(args mock.Arguments) {
				arg := args.Get(0).(elasticsearch.User)
				for _, c := range mockESCLI.ExpectedCalls {
					if c.Method == "UpdateUser" {
						Expect(arg.Password).ShouldNot(BeEmpty())
						c.ReturnArguments = mock.Arguments{nil}
					}
				}
			})

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{"role-1"})
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "kibana_login", "elasticsearch_superuser"},
				Resources:     []string{"*"},
			}})

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("Exists", "xyz-1").Return(true)
			mockUserCache.On("SubjectIDs").Return([]string{"xyz-1"})
			mockUserCache.On("SubjectIDToUserOrGroups", mock.Anything).Return([]string{"group1"})

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			Expect(updateHandler.synchronizer.resync()).ShouldNot(HaveOccurred())

			actualOidcSecret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(actualOidcSecret.Data["xyz-1"]).ShouldNot(BeNil())
			mockESCLI.AssertExpectations(GinkgoT())
		})

		It("If user does not exists in elasticsearch and password exist in k8s Secret, recreate password", func() {
			mockESCLI := elasticsearch.NewMockClient()
			mockESCLI.On("GetUsers").Return([]elasticsearch.User{}, nil)
			mockESCLI.On("UserExists", "tigera-k8s-xyz-1").Return(false, nil)
			mockESCLI.On("UpdateUser", mock.Anything).Run(func(args mock.Arguments) {
				arg := args.Get(0).(elasticsearch.User)
				for _, c := range mockESCLI.ExpectedCalls {
					if c.Method == "UpdateUser" {
						Expect(arg.Password).ShouldNot(BeEmpty())
						c.ReturnArguments = mock.Arguments{nil}
					}
				}
			})

			mockClusterRoleCache := rbaccache.NewMockClusterRoleCache()
			mockClusterRoleCache.On("ClusterRoleNamesForSubjectName", "group1").Return([]string{"role-1"})
			mockClusterRoleCache.On("ClusterRoleRules", mock.Anything).Return([]rbacv1.PolicyRule{{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"flows", "kibana_login", "elasticsearch_superuser"},
				Resources:     []string{"*"},
			}})

			mockUserCache := userscache.NewMockOIDCUserCache()
			mockUserCache.On("Exists", "xyz-1").Return(true)
			mockUserCache.On("SubjectIDs").Return([]string{"xyz-1"})
			mockUserCache.On("SubjectIDToUserOrGroups", mock.Anything).Return([]string{"group1"})

			oidcSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: resource.OIDCUsersEsSecreteName, Namespace: resource.TigeraElasticsearchNamespace},
				Data: map[string][]byte{
					"xyz-1": []byte("Hello"),
				},
			}
			fakeK8CLI := k8sfake.NewClientset(oidcSecret)

			resourceUpdates := make(chan resourceUpdate)
			synchronizer := createNativeUserSynchronizer(mockClusterRoleCache, mockUserCache, fakeK8CLI, mockESCLI)

			updateHandler := k8sUpdateHandler{
				resourceUpdates: resourceUpdates,
				synchronizer:    synchronizer,
			}

			Expect(updateHandler.synchronizer.resync()).ShouldNot(HaveOccurred())

			actualOidcSecret, err := fakeK8CLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(context.Background(), resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(actualOidcSecret.Data["xyz-1"]).ShouldNot(BeEquivalentTo(oidcSecret.Data["xyz-1"]))

			mockESCLI.AssertExpectations(GinkgoT())
		})
	})
})
