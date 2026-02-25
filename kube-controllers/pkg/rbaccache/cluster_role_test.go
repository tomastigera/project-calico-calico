// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package rbaccache

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("ClusterRoleCache", func() {
	var emptyStrArray []string

	Context("AddClusterRole", func() {
		It("Adds the ClusterRole to the cache", func() {
			rule := rbacv1.PolicyRule{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"kibana_login", "elasticsearch_superuser", "flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7"},
				Resources:     []string{"*"},
			}

			roleCache := NewClusterRoleCache([]string{}, []string{})
			Expect(roleCache.AddClusterRole(&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{rule},
			})).Should(BeTrue())

			Expect(roleCache.ClusterRoleRules("test-cluster-role")).Should(Equal([]rbacv1.PolicyRule{rule}))
		})
		It("Doesn't cache rules that aren't in the accept API groups list", func() {
			rule1 := rbacv1.PolicyRule{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"kibana_login", "elasticsearch_superuser", "flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7"},
				Resources:     []string{"*"},
			}

			rule2 := rbacv1.PolicyRule{
				APIGroups:     []string{"somegroup"},
				ResourceNames: []string{"value"},
				Resources:     []string{"*"},
			}

			roleCache := NewClusterRoleCache([]string{}, []string{"lma.tigera.io"})
			Expect(roleCache.AddClusterRole(&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{rule1, rule2},
			})).Should(BeTrue())

			Expect(roleCache.ClusterRoleRules("test-cluster-role")).Should(Equal([]rbacv1.PolicyRule{rule1}))
		})
		It("Doesn't cache ClusterRoles that don't have any rules in the accepted API groups", func() {
			rule1 := rbacv1.PolicyRule{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"kibana_login", "elasticsearch_superuser", "flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7"},
				Resources:     []string{"*"},
			}

			rule2 := rbacv1.PolicyRule{
				APIGroups:     []string{"somegroup"},
				ResourceNames: []string{"value"},
				Resources:     []string{"*"},
			}

			roleCache := NewClusterRoleCache([]string{}, []string{"lma.tigera.io"})
			Expect(roleCache.AddClusterRole(&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-1",
				},
				Rules: []rbacv1.PolicyRule{rule1},
			})).Should(BeTrue())

			Expect(roleCache.AddClusterRole(&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-2",
				},
				Rules: []rbacv1.PolicyRule{rule2},
			})).Should(BeFalse())

			Expect(roleCache.ClusterRoleRules("test-cluster-role-1")).Should(Equal([]rbacv1.PolicyRule{rule1}))
			Expect(roleCache.ClusterRoleRules("test-cluster-role-2")).Should(Equal([]rbacv1.PolicyRule{}))
		})
	})

	Context("AddClusterRoleBinding", func() {
		It("Adds the ClusterRoleBinding to the cache", func() {
			subject1 := rbacv1.Subject{
				Kind: rbacv1.ServiceAccountKind,
				Name: "test-service-account",
			}

			subject2 := rbacv1.Subject{
				Kind: rbacv1.UserKind,
				Name: "test-user",
			}

			roleCache := NewClusterRoleCache([]string{}, []string{})
			Expect(roleCache.AddClusterRoleBinding(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-binding",
				},
				Subjects: []rbacv1.Subject{subject1, subject2},
				RoleRef:  rbacv1.RoleRef{Name: "test-cluster-role"},
			})).Should(BeTrue())

			Expect(roleCache.ClusterRoleSubjects("test-cluster-role", rbacv1.ServiceAccountKind)).Should(Equal([]rbacv1.Subject{subject1}))
			Expect(roleCache.ClusterRoleSubjects("test-cluster-role", rbacv1.UserKind)).Should(Equal([]rbacv1.Subject{subject2}))
			Expect(roleCache.ClusterRoleNameForBinding("test-cluster-role-binding")).Should(Equal("test-cluster-role"))
			Expect(roleCache.SubjectNamesForBinding("test-cluster-role-binding")).Should(BeEquivalentTo([]string{"test-service-account", "test-user"}))
			Expect(roleCache.ClusterRoleNamesForSubjectName("test-service-account")).Should(Equal([]string{"test-cluster-role"}))
		})

		It("Filters ClusterRoleBinding subjects not in the allowed list of subjects", func() {
			subject1 := rbacv1.Subject{
				Kind: rbacv1.ServiceAccountKind,
				Name: "test-service-account",
			}

			subject2 := rbacv1.Subject{
				Kind: rbacv1.UserKind,
				Name: "test-user",
			}

			roleCache := NewClusterRoleCache([]string{rbacv1.UserKind}, []string{})
			Expect(roleCache.AddClusterRoleBinding(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-binding",
				},
				Subjects: []rbacv1.Subject{subject1, subject2},
				RoleRef:  rbacv1.RoleRef{Name: "test-cluster-role"},
			})).Should(BeTrue())

			Expect(roleCache.ClusterRoleSubjects("test-cluster-role", rbacv1.ServiceAccountKind)).Should(Equal([]rbacv1.Subject(nil)))
			Expect(roleCache.ClusterRoleSubjects("test-cluster-role", rbacv1.UserKind)).Should(Equal([]rbacv1.Subject{subject2}))
			Expect(roleCache.ClusterRoleNameForBinding("test-cluster-role-binding")).Should(Equal("test-cluster-role"))
		})

		It("Filters ClusterRoleBinding that don't have any subjects with the allowed kind", func() {
			subject1 := rbacv1.Subject{
				Kind: rbacv1.ServiceAccountKind,
				Name: "test-service-account",
			}

			subject2 := rbacv1.Subject{
				Kind: rbacv1.UserKind,
				Name: "test-user",
			}

			roleCache := NewClusterRoleCache([]string{rbacv1.UserKind}, []string{})
			Expect(roleCache.AddClusterRoleBinding(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-binding-1",
				},
				Subjects: []rbacv1.Subject{subject1},
				RoleRef:  rbacv1.RoleRef{Name: "test-cluster-role-1"},
			})).Should(BeFalse())

			Expect(roleCache.AddClusterRoleBinding(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-binding-2",
				},
				Subjects: []rbacv1.Subject{subject2},
				RoleRef:  rbacv1.RoleRef{Name: "test-cluster-role-2"},
			})).Should(BeTrue())

			Expect(roleCache.ClusterRoleSubjects("test-cluster-role-1", rbacv1.ServiceAccountKind)).Should(Equal([]rbacv1.Subject(nil)))
			Expect(roleCache.ClusterRoleSubjects("test-cluster-role-2", rbacv1.UserKind)).Should(Equal([]rbacv1.Subject{subject2}))
			Expect(roleCache.ClusterRoleNameForBinding("test-cluster-role-binding-1")).Should(Equal(""))
			Expect(roleCache.ClusterRoleNameForBinding("test-cluster-role-binding-2")).Should(Equal("test-cluster-role-2"))
		})
	})

	Context("RemoveClusterRole", func() {
		It("Removes the ClusterRole from the cache", func() {
			rule := rbacv1.PolicyRule{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"kibana_login", "elasticsearch_superuser", "flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7"},
				Resources:     []string{"*"},
			}

			roleCache := NewClusterRoleCache([]string{}, []string{})
			Expect(roleCache.AddClusterRole(&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{rule},
			})).Should(BeTrue())

			Expect(roleCache.RemoveClusterRole("test-cluster-role")).Should(BeTrue())
			Expect(roleCache.ClusterRoleRules("test-cluster-role")).Should(Equal([]rbacv1.PolicyRule{}))
			Expect(roleCache.ClusterRoleBindingsForClusterRole("test-cluster-role")).Should(Equal(emptyStrArray))
		})

		It("Returns false when the ClusterRole isn't in the cache", func() {
			roleCache := NewClusterRoleCache([]string{}, []string{})

			Expect(roleCache.RemoveClusterRole("test-cluster-role")).Should(BeFalse())
		})
	})

	Context("RemoveClusterRoleBinding", func() {
		It("Removes the ClusterRoleBinding from the cache", func() {
			subject1 := rbacv1.Subject{
				Kind: rbacv1.ServiceAccountKind,
				Name: "test-service-account",
			}

			subject2 := rbacv1.Subject{
				Kind: rbacv1.UserKind,
				Name: "test-user",
			}

			roleCache := NewClusterRoleCache([]string{}, []string{})
			Expect(roleCache.AddClusterRoleBinding(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-binding",
				},
				Subjects: []rbacv1.Subject{subject1, subject2},
				RoleRef:  rbacv1.RoleRef{Name: "test-cluster-role"},
			})).Should(BeTrue())
			Expect(roleCache.RemoveClusterRoleBinding("test-cluster-role-binding")).Should(BeTrue())
			Expect(roleCache.ClusterRoleSubjects("test-cluster-role", rbacv1.ServiceAccountKind)).Should(Equal([]rbacv1.Subject(nil)))
			Expect(roleCache.ClusterRoleSubjects("test-cluster-role", rbacv1.UserKind)).Should(Equal([]rbacv1.Subject(nil)))
			Expect(roleCache.ClusterRoleNameForBinding("test-cluster-role-binding")).Should(Equal(""))
			Expect(roleCache.SubjectNamesForBinding("test-cluster-role-binding")).Should(BeEquivalentTo(emptyStrArray))
			Expect(roleCache.ClusterRoleNamesForSubjectName("test-service-account")).Should(BeEquivalentTo(emptyStrArray))
			Expect(roleCache.ClusterRoleNamesForSubjectName("test-user")).Should(BeEquivalentTo(emptyStrArray))
		})

		It("Handles removing the cluster role before the cluster role binding", func() {
			subject1 := rbacv1.Subject{
				Kind: rbacv1.ServiceAccountKind,
				Name: "test-service-account",
			}

			roleCache := NewClusterRoleCache([]string{}, []string{})
			Expect(roleCache.AddClusterRoleBinding(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-binding",
				},
				Subjects: []rbacv1.Subject{subject1},
				RoleRef:  rbacv1.RoleRef{Name: "test-cluster-role"},
			})).Should(BeTrue())
			Expect(roleCache.AddClusterRole(&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role",
				},
				Rules: []rbacv1.PolicyRule{{
					APIGroups:     []string{"lma.tigera.io"},
					ResourceNames: []string{"kibana_login", "elasticsearch_superuser", "flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7"},
					Resources:     []string{"*"},
				}},
			})).Should(BeTrue())

			Expect(roleCache.RemoveClusterRole("test-cluster-role")).Should(BeTrue())

			// Test that the subjects are still mapped to the cluster role even if it doesn't exist. This is important
			// because we map the cluster role binding subjects to cluster role in case it exists again.
			Expect(roleCache.ClusterRoleSubjects("test-cluster-role", rbacv1.ServiceAccountKind)).Should(HaveLen(1))
			Expect(roleCache.RemoveClusterRoleBinding("test-cluster-role-binding")).Should(BeTrue())
			Expect(roleCache.ClusterRoleSubjects("test-cluster-role", rbacv1.ServiceAccountKind)).Should(HaveLen(0))
		})

		It("Returns false when the ClusterRoleBinding isn't in the cache", func() {
			roleCache := NewClusterRoleCache([]string{}, []string{})

			Expect(roleCache.RemoveClusterRoleBinding("test-cluster-role-binding")).Should(BeFalse())
		})
	})

	Context("ClusterRoleNamesWithBindings", func() {
		It("Returns only ClusterRole names with the appropriate bindings and rules", func() {
			subject := rbacv1.Subject{
				Kind: rbacv1.UserKind,
				Name: "test-user",
			}

			rule := rbacv1.PolicyRule{
				APIGroups:     []string{"lma.tigera.io"},
				ResourceNames: []string{"kibana_login", "elasticsearch_superuser", "flows", "audit*", "audit_ee", "audit_kube", "events", "dns", "l7"},
				Resources:     []string{"*"},
			}

			roleCache := NewClusterRoleCache([]string{}, []string{})
			Expect(roleCache.AddClusterRoleBinding(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-binding-1",
				},
				Subjects: []rbacv1.Subject{subject},
				RoleRef:  rbacv1.RoleRef{Name: "test-cluster-role-1"},
			})).Should(BeTrue())
			Expect(roleCache.AddClusterRoleBinding(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-binding-2",
				},
				Subjects: []rbacv1.Subject{subject},
				RoleRef:  rbacv1.RoleRef{Name: "test-cluster-role-2"},
			})).Should(BeTrue())
			Expect(roleCache.AddClusterRole(&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-2",
				},
				Rules: []rbacv1.PolicyRule{rule},
			})).Should(BeTrue())
			Expect(roleCache.AddClusterRole(&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cluster-role-3",
				},
				Rules: []rbacv1.PolicyRule{rule},
			})).Should(BeTrue())

			Expect(roleCache.ClusterRoleNamesWithBindings()).Should(Equal([]string{"test-cluster-role-2"}))
		})
	})
})
