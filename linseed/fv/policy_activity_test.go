// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package fv_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
)

func RunPolicyActivityTest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	// Policy activity always uses single-index backend regardless of the configured backend strategy
	// (see linseed/cmd/main.go), so we only test with single-index.
	t.Run(name, func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.PolicyActivityIndex())()
		testFn(t, index.PolicyActivityIndex())
	})
}

func TestFV_PolicyActivity(t *testing.T) {
	RunPolicyActivityTest(t, "should return empty items when no activity exists for queried policies", func(t *testing.T, idx bapi.Index) {
		from := time.Now().Add(-5 * time.Second)
		to := time.Now()
		req := &v1.PolicyActivityParams{
			From: &from,
			To:   &to,
			Policies: []v1.PolicyActivityQueryPolicy{
				{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns", Generation: 1},
			},
		}

		resp, err := cli.PolicyActivity(cluster1).GetPolicyActivities(ctx, req)
		require.NoError(t, err)
		require.Empty(t, resp.Items)
	})

	RunPolicyActivityTest(t, "should return aggregated activity for a queried policy", func(t *testing.T, idx bapi.Index) {
		now := time.Now().UTC().Truncate(time.Second)

		// Ingest two rule-level activity documents for the same policy.
		logs := []v1.PolicyActivity{
			{
				Policy:        v1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns"},
				Rule:          "1|ingress|0",
				LastEvaluated: now,
			},
			{
				Policy:        v1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns"},
				Rule:          "1|egress|0",
				LastEvaluated: now,
			},
		}

		bulk, err := cli.PolicyActivity(cluster1).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, 2, bulk.Succeeded, "expected both documents to be ingested")

		// Refresh so the documents are visible to search.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(cluster1Info))
		require.NoError(t, err)

		from := now.Add(-5 * time.Second)
		to := now.Add(5 * time.Second)
		req := &v1.PolicyActivityParams{
			From: &from,
			To:   &to,
			Policies: []v1.PolicyActivityQueryPolicy{
				{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns", Generation: 1},
			},
		}

		resp, err := cli.PolicyActivity(cluster1).GetPolicyActivities(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Items, 1)

		item := resp.Items[0]
		require.Equal(t, "NetworkPolicy", item.Policy.Kind)
		require.Equal(t, "default", item.Policy.Namespace)
		require.Equal(t, "allow-dns", item.Policy.Name)
		require.NotNil(t, item.LastEvaluated)
		require.Equal(t, now, item.LastEvaluated.UTC().Truncate(time.Second))
		require.Len(t, item.Rules, 2)
	})

	RunPolicyActivityTest(t, "should only return activity for queried policies", func(t *testing.T, idx bapi.Index) {
		now := time.Now().UTC().Truncate(time.Second)

		logs := []v1.PolicyActivity{
			{
				Policy:        v1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "default", Name: "policy-a"},
				Rule:          "1|ingress|0",
				LastEvaluated: now,
			},
			{
				Policy:        v1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "default", Name: "policy-b"},
				Rule:          "1|ingress|0",
				LastEvaluated: now,
			},
		}

		bulk, err := cli.PolicyActivity(cluster1).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, 2, bulk.Succeeded)

		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(cluster1Info))
		require.NoError(t, err)

		from := now.Add(-5 * time.Second)
		to := now.Add(5 * time.Second)
		req := &v1.PolicyActivityParams{
			From: &from,
			To:   &to,
			Policies: []v1.PolicyActivityQueryPolicy{
				{Kind: "NetworkPolicy", Namespace: "default", Name: "policy-a", Generation: 1},
			},
		}

		resp, err := cli.PolicyActivity(cluster1).GetPolicyActivities(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Items, 1)
		require.Equal(t, "policy-a", resp.Items[0].Policy.Name)
	})

	RunPolicyActivityTest(t, "should not return activity outside the requested time range", func(t *testing.T, idx bapi.Index) {
		now := time.Now().UTC().Truncate(time.Second)

		logs := []v1.PolicyActivity{
			{
				Policy:        v1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns"},
				Rule:          "1|ingress|0",
				LastEvaluated: now.Add(-2 * time.Hour),
			},
		}

		bulk, err := cli.PolicyActivity(cluster1).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, 1, bulk.Succeeded)

		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(cluster1Info))
		require.NoError(t, err)

		// Query a time window that does NOT include the document's last_evaluated.
		from := now.Add(-30 * time.Minute)
		to := now
		req := &v1.PolicyActivityParams{
			From: &from,
			To:   &to,
			Policies: []v1.PolicyActivityQueryPolicy{
				{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns", Generation: 1},
			},
		}

		resp, err := cli.PolicyActivity(cluster1).GetPolicyActivities(ctx, req)
		require.NoError(t, err)
		require.Empty(t, resp.Items)
	})

	RunPolicyActivityTest(t, "should return error when to is before from", func(t *testing.T, idx bapi.Index) {
		from := time.Now()
		to := from.Add(-1 * time.Hour)
		req := &v1.PolicyActivityParams{
			From: &from,
			To:   &to,
			Policies: []v1.PolicyActivityQueryPolicy{
				{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns", Generation: 1},
			},
		}

		_, err := cli.PolicyActivity(cluster1).GetPolicyActivities(ctx, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "status 400")
	})

	RunPolicyActivityTest(t, "should return error when policy kind is empty", func(t *testing.T, idx bapi.Index) {
		req := &v1.PolicyActivityParams{
			Policies: []v1.PolicyActivityQueryPolicy{
				{Kind: "", Namespace: "default", Name: "allow-dns", Generation: 1},
			},
		}

		_, err := cli.PolicyActivity(cluster1).GetPolicyActivities(ctx, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "status 400")
	})

	RunPolicyActivityTest(t, "should return error when generation is not positive", func(t *testing.T, idx bapi.Index) {
		req := &v1.PolicyActivityParams{
			Policies: []v1.PolicyActivityQueryPolicy{
				{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns", Generation: 0},
			},
		}

		_, err := cli.PolicyActivity(cluster1).GetPolicyActivities(ctx, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "status 400")
	})

	RunPolicyActivityTest(t, "should isolate activity by cluster", func(t *testing.T, idx bapi.Index) {
		now := time.Now().UTC().Truncate(time.Second)

		logs := []v1.PolicyActivity{
			{
				Policy:        v1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns"},
				Rule:          "1|ingress|0",
				LastEvaluated: now,
			},
		}

		// Ingest into cluster1 only.
		bulk, err := cli.PolicyActivity(cluster1).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, 1, bulk.Succeeded)

		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(cluster1Info))
		require.NoError(t, err)

		from := now.Add(-5 * time.Second)
		to := now.Add(5 * time.Second)
		req := &v1.PolicyActivityParams{
			From: &from,
			To:   &to,
			Policies: []v1.PolicyActivityQueryPolicy{
				{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns", Generation: 1},
			},
		}

		// cluster1 should see the data.
		resp, err := cli.PolicyActivity(cluster1).GetPolicyActivities(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Items, 1)

		// cluster2 should see nothing.
		resp, err = cli.PolicyActivity(cluster2).GetPolicyActivities(ctx, req)
		require.NoError(t, err)
		require.Empty(t, resp.Items)
	})
}
