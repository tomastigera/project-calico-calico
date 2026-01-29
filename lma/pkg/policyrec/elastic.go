// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.
package policyrec

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/api"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/timeutils"
)

func BuildQuery(params *PolicyRecommendationParams) *lapi.L3FlowParams {
	// Parse the start and end times.
	now := time.Now()
	start, _, err := timeutils.ParseTime(now, &params.StartTime)
	if err != nil {
		logrus.WithError(err).Warning("Failed to parse start time")
	}

	end, _, err := timeutils.ParseTime(now, &params.EndTime)
	if err != nil {
		logrus.WithError(err).Warning("Failed to parse end time")
	}

	fp := lapi.L3FlowParams{}
	fp.TimeRange = &lmav1.TimeRange{}
	if start != nil {
		fp.TimeRange.From = *start
	}
	if end != nil {
		fp.TimeRange.To = *end
	}

	fp.SourceTypes = []lapi.EndpointType{lapi.Network, lapi.NetworkSet, lapi.WEP, lapi.HEP}
	fp.DestinationTypes = []lapi.EndpointType{lapi.Network, lapi.NetworkSet, lapi.WEP, lapi.HEP}
	if params.Namespace != "" {
		fp.NamespaceMatches = []lapi.NamespaceMatch{
			{Type: lapi.MatchTypeAny, Namespaces: []string{params.Namespace}},
		}
	}
	if params.EndpointName != "" {
		fp.NameAggrMatches = []lapi.NameMatch{
			{Type: lapi.MatchTypeAny, Names: []string{params.EndpointName}},
		}
	}

	// If the request is only for unprotected flows then return a query that will
	// specifically only pick flows that are allowed by a profile.
	allow := lapi.FlowActionAllow
	if params.Unprotected {
		fp.PendingPolicyMatches = []lapi.PolicyMatch{
			{
				Tier:   "__PROFILE__",
				Action: &allow,
			},
		}
	} else {
		// Otherwise, return any flows that are seen by the default tier
		// or allowed by a profile.
		fp.PendingPolicyMatches = []lapi.PolicyMatch{
			{
				Tier: "default",
			},
			{
				Tier:   "__PROFILE__",
				Action: &allow,
			},
		}
	}
	return &fp
}

func SearchFlows(ctx context.Context, listFn client.ListFunc[lapi.L3Flow], pager client.ListPager[lapi.L3Flow]) ([]*api.Flow, error) {
	// Search for the raw data in ES.
	pages, errors := pager.Stream(ctx, listFn)

	flows := []*api.Flow{}
	for page := range pages {
		for _, f := range page.Items {
			flow := api.FromLinseedFlow(f)
			if flow != nil {
				flows = append(flows, flow)
			}
		}
	}

	if err, ok := <-errors; ok {
		logrus.WithError(err).Warning("Hit error processing flow logs")
		return flows, err
	}

	return flows, nil
}
