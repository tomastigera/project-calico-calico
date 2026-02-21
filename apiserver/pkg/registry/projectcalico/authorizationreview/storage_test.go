// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
package authorizationreview_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	rbac_v1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	rbacmock "github.com/projectcalico/calico/apiserver/pkg/rbac/mock"
	. "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizationreview"
)

var _ = Describe("AuthorizationReview storage tests", func() {
	var calc rbac.Calculator
	var mock *rbacmock.MockClient
	var myUser user.Info
	var myContext context.Context
	var rest *REST

	BeforeEach(func() {
		mock = &rbacmock.MockClient{
			Roles:               map[string][]rbac_v1.PolicyRule{},
			RoleBindings:        map[string][]string{},
			ClusterRoles:        map[string][]rbac_v1.PolicyRule{},
			ClusterRoleBindings: []string{},
			Namespaces:          []string{"ns1", "ns2", "ns3", "ns4", "ns5"},
			Tiers:               []string{"default", "tier1", "tier2", "tier3", "tier4"},
		}
		calc = rbac.NewCalculator(mock, mock, mock, mock, mock, mock, mock, 0)
		myUser = &user.DefaultInfo{
			Name:   "my-user",
			UID:    "abcde",
			Groups: []string{},
			Extra:  map[string][]string{},
		}
		myContext = request.WithUser(context.Background(), myUser)
		rest = NewREST(calc)
	})

	It("handle getting user info from spec when passed in both the spec and the context", func() {
		mock.ClusterRoleBindings = []string{"get-namespaces"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-namespaces": {{Verbs: []string{"get"}, Resources: []string{"namespaces"}, APIGroups: []string{""}}},
		}

		res, err := rest.Create(context.Background(), &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"namespaces"},
						Verbs:     []string{"get"},
					},
				},
				User:   myUser.GetName(),
				Groups: myUser.GetGroups(),
				Extra:  myUser.GetExtra(),
			},
		}, nil, nil)

		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		ar := res.(*v3.AuthorizationReview)
		// get for namespace is expanded across configured namespaces.
		contextUser, ok := request.UserFrom(myContext)
		Expect(ok).NotTo(BeFalse())
		Expect(ar.Spec.User).To(Equal(contextUser.GetName()))
		Expect(ar.Status.AuthorizedResourceVerbs).To(Equal([]v3.AuthorizedResourceVerbs{
			{
				Resource: "namespaces",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "get",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Namespace: "ns1"}, {Namespace: "ns2"}, {Namespace: "ns3"}, {Namespace: "ns4"}, {Namespace: "ns5"},
						},
					},
				},
			},
		}))
	})

	It("return empty authorization review when user is neither passed in the context, nor in the spec", func() {
		mock.ClusterRoleBindings = []string{"get-namespaces"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-namespaces": {{Verbs: []string{"get"}, Resources: []string{"namespaces"}, APIGroups: []string{""}}},
		}

		res, err := rest.Create(context.Background(), &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"namespaces"},
						Verbs:     []string{"get"},
					},
				},
			},
		}, nil, nil)

		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		ar := res.(*v3.AuthorizationReview)
		// User should be empty since it's not passed in the context or spec
		Expect(ar.Spec.User).To(Equal(""))
		Expect(ar.Status.AuthorizedResourceVerbs).To(BeNil())
	})

	It("prioritize user info passed in the spec over the context user in calculating the permissions", func() {
		mock.ClusterRoleBindings = []string{"get-namespaces"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-namespaces": {{Verbs: []string{"get"}, Resources: []string{"namespaces"}, APIGroups: []string{""}}},
		}

		res, err := rest.Create(myContext, &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"namespaces"},
						Verbs:     []string{"get"},
					},
				},
				User:   "second-user",
				Groups: []string{""},
			},
		}, nil, nil)

		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		ar := res.(*v3.AuthorizationReview)
		Expect(ar.Spec.User).To(Equal("second-user"))
		Expect(ar.Status.AuthorizedResourceVerbs).To(Equal([]v3.AuthorizedResourceVerbs{
			{
				APIGroup: "",
				Resource: "namespaces",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb:           "get",
						ResourceGroups: []v3.AuthorizedResourceGroup{},
					},
				},
			},
		}))
	})

	It("handles errors in the Namespace enumeration", func() {
		// Set namespaces to nil to force an error in the mock client.
		mock.Namespaces = nil

		res, err := rest.Create(myContext, &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"namespaces"},
						Verbs:     []string{"get"},
					},
				},
			},
		}, nil, nil)
		Expect(err).To(HaveOccurred())
		Expect(res).To(BeNil())
	})

	It("handles namespace get auth evaluation with no v3.ions", func() {
		res, err := rest.Create(myContext, &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"namespaces"},
						Verbs:     []string{"get"},
					},
				},
			},
		}, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		ar := res.(*v3.AuthorizationReview)
		Expect(ar.Status.AuthorizedResourceVerbs).To(Equal([]v3.AuthorizedResourceVerbs{
			{
				Resource: "namespaces",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb:           "get",
						ResourceGroups: []v3.AuthorizedResourceGroup{},
					},
				},
			},
		}))
	})

	It("returns authorized namespaced managed clusters in a multi-tenant cluster", func() {
		// Configure a two managed clusters in different namespaces.
		mock.Namespaces = []string{"tenant-a", "tenant-b"}
		mock.ManagedClusters = []types.NamespacedName{
			{Name: "cluster1", Namespace: "tenant-a"},
			{Name: "cluster1", Namespace: "tenant-b"},
		}

		// Configure permissions to get managed clusters, but only in namespace "tenant-b".
		mock.RoleBindings = map[string][]string{"tenant-b": {"get-managed-clusters"}}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-managed-clusters": {{Verbs: []string{"get"}, Resources: []string{"managedclusters"}, APIGroups: []string{"projectcalico.org"}}},
		}

		// Send an authz review for managed clusters.
		authzReview := &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "projectcalico.org",
						Resources: []string{"managedclusters"},
						Verbs:     []string{"get"},
					},
				},
			},
		}
		res, err := rest.Create(myContext, authzReview, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())

		// Expect the managed cluster for tenant-b to show up, but not tenant-a.
		expected := []v3.AuthorizedResourceVerbs{
			{
				APIGroup: "projectcalico.org",
				Resource: "managedclusters",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "get",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{ManagedCluster: "cluster1", Namespace: "tenant-b"},
						},
					},
				},
			},
		}
		ar := res.(*v3.AuthorizationReview)
		Expect(ar.Status.AuthorizedResourceVerbs).To(Equal(expected))

		// Check that it also works with a namespaced Role instead of a ClusterRole.
		mock.ClusterRoles = nil
		mock.RoleBindings = map[string][]string{"tenant-b": {"/get-managed-clusters"}}
		mock.Roles = map[string][]rbac_v1.PolicyRule{
			"tenant-b/get-managed-clusters": {{Verbs: []string{"get"}, Resources: []string{"managedclusters"}, APIGroups: []string{"projectcalico.org"}}},
		}
		res, err = rest.Create(myContext, authzReview, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		ar = res.(*v3.AuthorizationReview)
		Expect(ar.Status.AuthorizedResourceVerbs).To(Equal(expected))
	})

	It("returns authorized managed clusters", func() {
		// Configure a single, cluster-scoped managed cluster.
		mock.ManagedClusters = []types.NamespacedName{{Name: "cluster1"}}

		// Configure permissions to get managed clusters.
		mock.ClusterRoleBindings = []string{"get-managed-clusters"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-managed-clusters": {{Verbs: []string{"get"}, Resources: []string{"managedclusters"}, APIGroups: []string{"projectcalico.org"}}},
		}

		// Send an authz review for managed clusters.
		res, err := rest.Create(myContext, &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "projectcalico.org",
						Resources: []string{"managedclusters"},
						Verbs:     []string{"get"},
					},
				},
			},
		}, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())

		// Expect the managed cluster to show up.
		ar := res.(*v3.AuthorizationReview)
		Expect(ar.Status.AuthorizedResourceVerbs).To(Equal([]v3.AuthorizedResourceVerbs{
			{
				APIGroup: "projectcalico.org",
				Resource: "managedclusters",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "get",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{ManagedCluster: "cluster1"},
						},
					},
				},
			},
		}))
	})

	It("handles namespace get auth evaluation", func() {
		mock.ClusterRoleBindings = []string{"get-namespaces"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"get-namespaces": {{Verbs: []string{"get"}, Resources: []string{"namespaces"}, APIGroups: []string{""}}},
		}

		res, err := rest.Create(myContext, &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"namespaces"},
						Verbs:     []string{"get"},
					},
				},
			},
		}, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		ar := res.(*v3.AuthorizationReview)
		// get for namespace is expanded across configured namespaces.
		Expect(ar.Status.AuthorizedResourceVerbs).To(Equal([]v3.AuthorizedResourceVerbs{
			{
				Resource: "namespaces",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "get",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Namespace: "ns1"}, {Namespace: "ns2"}, {Namespace: "ns3"}, {Namespace: "ns4"}, {Namespace: "ns5"},
						},
					},
				},
			},
		}))
	})

	It("handles namespace patch auth evaluation", func() {
		mock.ClusterRoleBindings = []string{"patch-namespaces"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"patch-namespaces": {{Verbs: []string{"patch"}, Resources: []string{"namespaces"}, APIGroups: []string{""}}},
		}

		res, err := rest.Create(myContext, &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"namespaces"},
						Verbs:     []string{"patch"},
					},
				},
			},
		}, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		ar := res.(*v3.AuthorizationReview)
		// Verbs other than get for namespace use cluster scoped if appropriate and will not expand across namespaces.
		Expect(ar.Status.AuthorizedResourceVerbs).To(Equal([]v3.AuthorizedResourceVerbs{
			{
				Resource: "namespaces",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "patch",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Namespace: ""},
						},
					},
				},
			},
		}))
	})

	It("has entries for each requested verb/resource combination", func() {
		mock.ClusterRoleBindings = []string{"allow-all"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"allow-all": {{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}}},
		}

		res, err := rest.Create(myContext, &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"namespaces", "pods"},
						Verbs:     []string{"create", "delete"},
					},
					{
						APIGroup:  "projectcalico.org",
						Resources: []string{"networkpolicies"},
						// Try some duplicates to make sure they are contracted.
						Verbs: []string{"patch", "create", "delete", "patch", "delete"},
					},
				},
			},
		}, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		ar := res.(*v3.AuthorizationReview)
		// Verbs other than get for namespace use cluster scoped if appropriate and will not expand across namespaces.
		Expect(ar.Status.AuthorizedResourceVerbs).To(HaveLen(3))
		Expect(ar.Status.AuthorizedResourceVerbs).To(Equal([]v3.AuthorizedResourceVerbs{
			{
				APIGroup: "",
				Resource: "namespaces",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "create",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "", Namespace: ""},
						},
					},
					{
						Verb: "delete",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "", Namespace: ""},
						},
					},
				},
			},
			{
				APIGroup: "",
				Resource: "pods",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "create",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "", Namespace: ""},
						},
					},
					{
						Verb: "delete",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "", Namespace: ""},
						},
					},
				},
			},
			{
				APIGroup: "projectcalico.org",
				Resource: "networkpolicies",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "create",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "default", Namespace: ""},
							{Tier: "tier1", Namespace: ""},
							{Tier: "tier2", Namespace: ""},
							{Tier: "tier3", Namespace: ""},
							{Tier: "tier4", Namespace: ""},
						},
					},
					{
						Verb: "delete",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "default", Namespace: ""},
							{Tier: "tier1", Namespace: ""},
							{Tier: "tier2", Namespace: ""},
							{Tier: "tier3", Namespace: ""},
							{Tier: "tier4", Namespace: ""},
						},
					},
					{
						Verb: "patch",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "default", Namespace: ""},
							{Tier: "tier1", Namespace: ""},
							{Tier: "tier2", Namespace: ""},
							{Tier: "tier3", Namespace: ""},
							{Tier: "tier4", Namespace: ""},
						},
					},
				},
			},
		}))
	})

	It("missing cluster role binding", func() {
		mock.ClusterRoleBindings = []string{"missing", "allow-all"}
		mock.ClusterRoles = map[string][]rbac_v1.PolicyRule{
			"allow-all": {{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}}},
		}

		res, err := rest.Create(myContext, &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"namespaces", "pods"},
						Verbs:     []string{"create", "delete"},
					},
					{
						APIGroup:  "projectcalico.org",
						Resources: []string{"networkpolicies"},
						// Try some duplicates to make sure they are contracted.
						Verbs: []string{"patch", "create", "delete", "patch", "delete"},
					},
				},
			},
		}, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		ar := res.(*v3.AuthorizationReview)
		// Verbs other than get for namespace use cluster scoped if appropriate and will not expand across namespaces.
		Expect(ar.Status.AuthorizedResourceVerbs).To(HaveLen(3))
		Expect(ar.Status.AuthorizedResourceVerbs).To(Equal([]v3.AuthorizedResourceVerbs{
			{
				APIGroup: "",
				Resource: "namespaces",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "create",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "", Namespace: ""},
						},
					},
					{
						Verb: "delete",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "", Namespace: ""},
						},
					},
				},
			},
			{
				APIGroup: "",
				Resource: "pods",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "create",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "", Namespace: ""},
						},
					},
					{
						Verb: "delete",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "", Namespace: ""},
						},
					},
				},
			},
			{
				APIGroup: "projectcalico.org",
				Resource: "networkpolicies",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb: "create",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "default", Namespace: ""},
							{Tier: "tier1", Namespace: ""},
							{Tier: "tier2", Namespace: ""},
							{Tier: "tier3", Namespace: ""},
							{Tier: "tier4", Namespace: ""},
						},
					},
					{
						Verb: "delete",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "default", Namespace: ""},
							{Tier: "tier1", Namespace: ""},
							{Tier: "tier2", Namespace: ""},
							{Tier: "tier3", Namespace: ""},
							{Tier: "tier4", Namespace: ""},
						},
					},
					{
						Verb: "patch",
						ResourceGroups: []v3.AuthorizedResourceGroup{
							{Tier: "default", Namespace: ""},
							{Tier: "tier1", Namespace: ""},
							{Tier: "tier2", Namespace: ""},
							{Tier: "tier3", Namespace: ""},
							{Tier: "tier4", Namespace: ""},
						},
					},
				},
			},
		}))
	})
})
