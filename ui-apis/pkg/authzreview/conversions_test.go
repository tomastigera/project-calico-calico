// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package authzreview

import (
	"testing"

	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
)

func TestRequestToResourceVerbs(t *testing.T) {
	t.Run("single attribute expands to one ResourceVerbs per resource", func(t *testing.T) {
		attrs := []v3.AuthorizationReviewResourceAttributes{
			{
				APIGroup:  "projectcalico.org",
				Resources: []string{"tiers", "networkpolicies"},
				Verbs:     []string{"get", "list"},
			},
		}
		rvs := requestToResourceVerbs(attrs)
		require.Len(t, rvs, 2)

		require.Equal(t, rbac.ResourceType{APIGroup: "projectcalico.org", Resource: "tiers"}, rvs[0].ResourceType)
		require.Equal(t, []rbac.Verb{rbac.Verb("get"), rbac.Verb("list")}, rvs[0].Verbs)

		require.Equal(t, rbac.ResourceType{APIGroup: "projectcalico.org", Resource: "networkpolicies"}, rvs[1].ResourceType)
		require.Equal(t, []rbac.Verb{rbac.Verb("get"), rbac.Verb("list")}, rvs[1].Verbs)
	})

	t.Run("multiple attributes from different API groups", func(t *testing.T) {
		attrs := []v3.AuthorizationReviewResourceAttributes{
			{
				APIGroup:  "projectcalico.org",
				Resources: []string{"tiers"},
				Verbs:     []string{"get"},
			},
			{
				APIGroup:  "",
				Resources: []string{"pods", "nodes"},
				Verbs:     []string{"list"},
			},
		}
		rvs := requestToResourceVerbs(attrs)
		require.Len(t, rvs, 3)
		require.Equal(t, "tiers", rvs[0].ResourceType.Resource)
		require.Equal(t, "projectcalico.org", rvs[0].ResourceType.APIGroup)
		require.Equal(t, "pods", rvs[1].ResourceType.Resource)
		require.Equal(t, "", rvs[1].ResourceType.APIGroup)
		require.Equal(t, "nodes", rvs[2].ResourceType.Resource)
	})

	t.Run("skips attributes with empty verbs", func(t *testing.T) {
		attrs := []v3.AuthorizationReviewResourceAttributes{
			{
				APIGroup:  "projectcalico.org",
				Resources: []string{"tiers"},
				Verbs:     []string{},
			},
		}
		rvs := requestToResourceVerbs(attrs)
		require.Empty(t, rvs)
	})

	t.Run("skips attributes with empty resources", func(t *testing.T) {
		attrs := []v3.AuthorizationReviewResourceAttributes{
			{
				APIGroup:  "projectcalico.org",
				Resources: []string{},
				Verbs:     []string{"get"},
			},
		}
		rvs := requestToResourceVerbs(attrs)
		require.Empty(t, rvs)
	})

	t.Run("nil input returns empty slice", func(t *testing.T) {
		rvs := requestToResourceVerbs(nil)
		require.Empty(t, rvs)
	})
}

func TestPermissionsToStatus(t *testing.T) {
	t.Run("empty permissions returns empty status", func(t *testing.T) {
		status := permissionsToStatus(rbac.Permissions{})
		require.Empty(t, status.AuthorizedResourceVerbs)
	})

	t.Run("nil permissions returns empty status", func(t *testing.T) {
		status := permissionsToStatus(nil)
		require.Empty(t, status.AuthorizedResourceVerbs)
	})

	t.Run("single resource with single verb", func(t *testing.T) {
		perms := rbac.Permissions{
			rbac.ResourceType{APIGroup: "projectcalico.org", Resource: "tiers"}: {
				rbac.VerbGet: []rbac.Match{{Tier: "default"}},
			},
		}
		status := permissionsToStatus(perms)
		require.Len(t, status.AuthorizedResourceVerbs, 1)
		require.Equal(t, "projectcalico.org", status.AuthorizedResourceVerbs[0].APIGroup)
		require.Equal(t, "tiers", status.AuthorizedResourceVerbs[0].Resource)
		require.Len(t, status.AuthorizedResourceVerbs[0].Verbs, 1)
		require.Equal(t, "get", status.AuthorizedResourceVerbs[0].Verbs[0].Verb)
		require.Len(t, status.AuthorizedResourceVerbs[0].Verbs[0].ResourceGroups, 1)
		require.Equal(t, "default", status.AuthorizedResourceVerbs[0].Verbs[0].ResourceGroups[0].Tier)
	})

	t.Run("results are sorted by API group then resource", func(t *testing.T) {
		perms := rbac.Permissions{
			rbac.ResourceType{APIGroup: "projectcalico.org", Resource: "tiers"}: {
				rbac.VerbGet: []rbac.Match{{}},
			},
			rbac.ResourceType{APIGroup: "", Resource: "pods"}: {
				rbac.VerbList: []rbac.Match{{}},
			},
			rbac.ResourceType{APIGroup: "projectcalico.org", Resource: "networkpolicies"}: {
				rbac.VerbGet: []rbac.Match{{}},
			},
		}
		status := permissionsToStatus(perms)
		require.Len(t, status.AuthorizedResourceVerbs, 3)
		// Empty string sorts before "projectcalico.org".
		require.Equal(t, "", status.AuthorizedResourceVerbs[0].APIGroup)
		require.Equal(t, "pods", status.AuthorizedResourceVerbs[0].Resource)
		// Within "projectcalico.org", networkpolicies < tiers.
		require.Equal(t, "networkpolicies", status.AuthorizedResourceVerbs[1].Resource)
		require.Equal(t, "tiers", status.AuthorizedResourceVerbs[2].Resource)
	})

	t.Run("verbs are sorted alphabetically", func(t *testing.T) {
		perms := rbac.Permissions{
			rbac.ResourceType{APIGroup: "projectcalico.org", Resource: "tiers"}: {
				rbac.VerbWatch: []rbac.Match{{}},
				rbac.VerbGet:   []rbac.Match{{}},
				rbac.VerbList:  []rbac.Match{{}},
			},
		}
		status := permissionsToStatus(perms)
		require.Len(t, status.AuthorizedResourceVerbs[0].Verbs, 3)
		require.Equal(t, "get", status.AuthorizedResourceVerbs[0].Verbs[0].Verb)
		require.Equal(t, "list", status.AuthorizedResourceVerbs[0].Verbs[1].Verb)
		require.Equal(t, "watch", status.AuthorizedResourceVerbs[0].Verbs[2].Verb)
	})

	t.Run("matches are sorted by namespace then tier then ui settings group", func(t *testing.T) {
		perms := rbac.Permissions{
			rbac.ResourceType{APIGroup: "projectcalico.org", Resource: "networkpolicies"}: {
				rbac.VerbGet: []rbac.Match{
					{Namespace: "kube-system", Tier: "default"},
					{Namespace: "default", Tier: "security"},
					{Namespace: "default", Tier: "default"},
				},
			},
		}
		status := permissionsToStatus(perms)
		rgs := status.AuthorizedResourceVerbs[0].Verbs[0].ResourceGroups
		require.Len(t, rgs, 3)
		require.Equal(t, "default", rgs[0].Namespace)
		require.Equal(t, "default", rgs[0].Tier)
		require.Equal(t, "default", rgs[1].Namespace)
		require.Equal(t, "security", rgs[1].Tier)
		require.Equal(t, "kube-system", rgs[2].Namespace)
		require.Equal(t, "default", rgs[2].Tier)
	})
}
