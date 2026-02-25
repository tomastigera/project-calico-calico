// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package rbac

import (
	"sort"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

// RequestToResourceVerbs expands the request resource attributes into a set of ResourceVerbs
// as input to the RBAC calculator.
func RequestToResourceVerbs(attributes []v3.AuthorizationReviewResourceAttributes) []ResourceVerbs {
	rvs := []ResourceVerbs{}
	for _, ra := range attributes {
		if len(ra.Verbs) == 0 || len(ra.Resources) == 0 {
			continue
		}

		verbs := make([]Verb, len(ra.Verbs))
		for i := range ra.Verbs {
			verbs[i] = Verb(ra.Verbs[i])
		}

		for _, r := range ra.Resources {
			rvs = append(rvs, ResourceVerbs{
				ResourceType: ResourceType{
					APIGroup: ra.APIGroup,
					Resource: r,
				},
				Verbs: verbs,
			})
		}
	}
	return rvs
}

// PermissionsToStatus transfers the results from the RBAC calculator to the AuthorizationReviewStatus.
// It sorts the results to ensure deterministic data.
func PermissionsToStatus(results Permissions) v3.AuthorizationReviewStatus {
	status := v3.AuthorizationReviewStatus{}

	// Transfer the results to the status. Sort the results to ensure deterministic data.
	// Start by ordering the resource type info.
	rts := make([]ResourceType, 0, len(results))
	for rt := range results {
		rts = append(rts, rt)
	}
	sort.Slice(rts, func(i, j int) bool {
		if rts[i].APIGroup < rts[j].APIGroup {
			return true
		} else if rts[i].APIGroup > rts[j].APIGroup {
			return false
		}
		return rts[i].Resource < rts[j].Resource
	})

	// Grab the results for each resource type.
	for _, rt := range rts {
		vms := results[rt]

		res := v3.AuthorizedResourceVerbs{
			APIGroup: rt.APIGroup,
			Resource: rt.Resource,
		}

		// Order the verbs.
		verbs := make([]string, 0, len(vms))
		for v := range vms {
			verbs = append(verbs, string(v))
		}
		sort.Strings(verbs)

		for _, v := range verbs {
			// Grab the authorization matches for the verb and order them before adding to the status.
			ms := vms[Verb(v)]
			rgs := []v3.AuthorizedResourceGroup{}

			sort.Slice(ms, func(i, j int) bool {
				if ms[i].Namespace < ms[j].Namespace {
					return true
				} else if ms[i].Namespace > ms[j].Namespace {
					return false
				}
				if ms[i].Tier < ms[j].Tier {
					return true
				} else if ms[i].Tier > ms[j].Tier {
					return false
				}
				return ms[i].UISettingsGroup < ms[j].UISettingsGroup
			})

			for _, m := range ms {
				rgs = append(rgs, v3.AuthorizedResourceGroup{
					Tier:            m.Tier,
					Namespace:       m.Namespace,
					UISettingsGroup: m.UISettingsGroup,
					ManagedCluster:  m.ManagedCluster,
				})
			}
			res.Verbs = append(res.Verbs, v3.AuthorizedResourceVerb{
				Verb:           v,
				ResourceGroups: rgs,
			})
		}

		status.AuthorizedResourceVerbs = append(status.AuthorizedResourceVerbs, res)
	}

	return status
}
