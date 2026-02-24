// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/list"
)

func RunComplianceSnapshotTest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	t.Run(fmt.Sprintf("%s [MultiIndex]", name), func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.ComplianceSnapshotMultiIndex)()
		testFn(t, index.ComplianceSnapshotMultiIndex)
	})

	t.Run(fmt.Sprintf("%s [SingleIndex]", name), func(t *testing.T) {
		confArgs := &RunConfigureElasticArgs{
			ComplianceSnapshotsBaseIndexName: index.ComplianceSnapshotsIndex().Name(bapi.ClusterInfo{}),
			ComplianceSnapshotsPolicyName:    index.ComplianceSnapshotsIndex().ILMPolicyName(),
		}
		args := DefaultLinseedArgs()
		args.Backend = config.BackendTypeSingleIndex
		defer setupAndTeardown(t, args, confArgs, index.ComplianceSnapshotsIndex())()
		testFn(t, index.ComplianceSnapshotsIndex())
	})
}

func TestFV_Snapshots(t *testing.T) {
	RunComplianceSnapshotTest(t, "should return an empty list if there are no snapshots", func(t *testing.T, idx bapi.Index) {
		params := v1.SnapshotParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now(),
				},
			},
		}

		// Perform a query.
		snapshots, err := cli.Compliance(cluster1).Snapshots().List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, []v1.Snapshot{}, snapshots.Items)
	})

	RunComplianceSnapshotTest(t, "should create and list snapshots", func(t *testing.T, idx bapi.Index) {
		snapshots := v1.Snapshot{
			ResourceList: list.TimestampedResourceList{
				ResourceList: &apiv3.NetworkPolicyList{
					TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
					ListMeta: metav1.ListMeta{},
					Items: []apiv3.NetworkPolicy{
						{
							TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "np1",
								Namespace: "default",
							},
						},
					},
				},
				RequestStartedTimestamp:   metav1.Time{Time: time.Unix(1, 0)},
				RequestCompletedTimestamp: metav1.Time{Time: time.Unix(2, 0)},
			},
		}
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			bulk, err := cli.Compliance(clusterInfo.Cluster).Snapshots().Create(ctx, []v1.Snapshot{snapshots})
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
		}

		// Read it back.
		params := v1.SnapshotParams{}

		t.Run("should query single cluster", func(t *testing.T) {
			clusterInfo := cluster1Info
			cluster := clusterInfo.Cluster

			resp, err := cli.Compliance(cluster).Snapshots().List(ctx, &params)
			require.NoError(t, err)
			require.Len(t, resp.Items, 1)
			testutils.AssertSnapshotIDAndClusterAndReset(t, clusterInfo.Cluster, &resp.Items[0])
			testutils.AssertSnapshotGeneratedTimeAndReset(t, &resp.Items[0])
			require.Equal(t, snapshots, resp.Items[0])

			// Read it back, using a time range
			params = v1.SnapshotParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Unix(0, 0),
						To:   time.Unix(2, 0),
					},
				},
			}
			resp, err = cli.Compliance(cluster).Snapshots().List(ctx, &params)
			require.NoError(t, err)

			// The ID should be set.
			require.Len(t, resp.Items, 1)
			testutils.AssertSnapshotIDAndClusterAndReset(t, clusterInfo.Cluster, &resp.Items[0])
			testutils.AssertSnapshotGeneratedTimeAndReset(t, &resp.Items[0])
			require.Equal(t, snapshots, resp.Items[0])
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)

			_, err := cli.Compliance(v1.QueryMultipleClusters).Snapshots().List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.Compliance(v1.QueryMultipleClusters).Snapshots().List(ctx, &params)
			require.NoError(t, err)
			require.Len(t, resp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.SnapshotClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			_, err := cli.Compliance(v1.QueryMultipleClusters).Snapshots().List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.Compliance(v1.QueryMultipleClusters).Snapshots().List(ctx, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.SnapshotClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})
	})

	RunComplianceSnapshotTest(t, "should support pagination", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 5

		// Create 5 Snapshots.
		logTime := time.Unix(100, 0).UTC()
		for i := range totalItems {
			snapshots := []v1.Snapshot{
				{
					ResourceList: list.TimestampedResourceList{
						ResourceList: &apiv3.NetworkPolicyList{
							TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
							ListMeta: metav1.ListMeta{},
							Items: []apiv3.NetworkPolicy{
								{
									TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
									ObjectMeta: metav1.ObjectMeta{
										Name:      fmt.Sprintf("np-%d", i),
										Namespace: "default",
									},
								},
							},
						},
						RequestStartedTimestamp:   metav1.Time{Time: logTime.Add(time.Duration(i) * time.Second)},
						RequestCompletedTimestamp: metav1.Time{Time: logTime.Add(time.Duration(2*i) * time.Second)},
					},
				},
			}
			bulk, err := cli.Compliance(cluster).Snapshots().Create(ctx, snapshots)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create snapshots did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Iterate through the first 4 pages and check they are correct.
		var afterKey map[string]any
		for i := 0; i < totalItems-1; i++ {
			params := v1.SnapshotParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: logTime.Add(-20 * time.Second),
						To:   logTime.Add(20 * time.Second),
					},
					MaxPageSize: 1,
					AfterKey:    afterKey,
				},
				Sort: []v1.SearchRequestSortBy{
					{
						Field: "requestStartedTimestamp",
					},
				},
			}
			resp, err := cli.Compliance(cluster).Snapshots().List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, 1, len(resp.Items))
			expected := []v1.Snapshot{
				{
					ResourceList: list.TimestampedResourceList{
						ResourceList: &apiv3.NetworkPolicyList{
							TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
							ListMeta: metav1.ListMeta{},
							Items: []apiv3.NetworkPolicy{
								{
									TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
									ObjectMeta: metav1.ObjectMeta{
										Name:      fmt.Sprintf("np-%d", i),
										Namespace: "default",
									},
								},
							},
						},
						RequestStartedTimestamp:   metav1.Time{Time: logTime.Add(time.Duration(i) * time.Second)},
						RequestCompletedTimestamp: metav1.Time{Time: logTime.Add(time.Duration(2*i) * time.Second)},
					},
				},
			}
			actual := snapshotsWithUTCTime(resp)
			for j := range actual {
				testutils.AssertSnapshotClusterAndReset(t, clusterInfo.Cluster, &actual[j])
				testutils.AssertSnapshotGeneratedTimeAndReset(t, &resp.Items[j])
			}
			require.Equal(t, expected, actual, fmt.Sprintf("Snapshot #%d did not match", i))
			require.NotNil(t, resp.AfterKey)
			require.Contains(t, resp.AfterKey, "startFrom")
			require.Equal(t, resp.AfterKey["startFrom"], float64(i+1))
			require.Equal(t, resp.TotalHits, int64(totalItems))

			// Use the afterKey for the next query.
			afterKey = resp.AfterKey
		}

		// If we query once more, we should get the last page, and no afterkey, since
		// we have paged through all the items.
		lastItem := totalItems - 1
		params := v1.SnapshotParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-20 * time.Second),
					To:   logTime.Add(20 * time.Second),
				},
				MaxPageSize: 1,
				AfterKey:    afterKey,
			},
			Sort: []v1.SearchRequestSortBy{
				{
					Field: "requestStartedTimestamp",
				},
			},
		}
		resp, err := cli.Compliance(cluster).Snapshots().List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Items))
		expected := []v1.Snapshot{
			{
				ResourceList: list.TimestampedResourceList{
					ResourceList: &apiv3.NetworkPolicyList{
						TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
						ListMeta: metav1.ListMeta{},
						Items: []apiv3.NetworkPolicy{
							{
								TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
								ObjectMeta: metav1.ObjectMeta{
									Name:      fmt.Sprintf("np-%d", lastItem),
									Namespace: "default",
								},
							},
						},
					},
					RequestStartedTimestamp:   metav1.Time{Time: logTime.Add(time.Duration(lastItem) * time.Second)},
					RequestCompletedTimestamp: metav1.Time{Time: logTime.Add(time.Duration(2*lastItem) * time.Second)},
				},
			},
		}
		actual := snapshotsWithUTCTime(resp)
		for j := range actual {
			testutils.AssertSnapshotClusterAndReset(t, cluster, &actual[j])
			testutils.AssertSnapshotGeneratedTimeAndReset(t, &actual[j])
		}
		require.Equal(t, expected, actual, fmt.Sprintf("Snapshot #%d did not match", lastItem))
		require.Equal(t, resp.TotalHits, int64(totalItems))

		// Once we reach the end of the data, we should not receive
		// an afterKey
		require.Nil(t, resp.AfterKey)
	})

	RunComplianceSnapshotTest(t, "should support pagination for items >= 10000 for Snapshots", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 10001
		// Create > 10K snapshots.
		logTime := time.Unix(100, 0).UTC()
		var snapshots []v1.Snapshot
		for i := range totalItems {
			snapshots = append(snapshots,
				v1.Snapshot{
					ID: strconv.Itoa(i),
					ResourceList: list.TimestampedResourceList{
						ResourceList: &apiv3.NetworkPolicyList{
							TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
							ListMeta: metav1.ListMeta{},
							Items: []apiv3.NetworkPolicy{
								{
									TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
									ObjectMeta: metav1.ObjectMeta{
										Name:      fmt.Sprintf("np-%d", i),
										Namespace: "default",
									},
								},
							},
						},
						RequestStartedTimestamp:   metav1.Time{Time: logTime.Add(time.Duration(i) * time.Second)},
						RequestCompletedTimestamp: metav1.Time{Time: logTime.Add(time.Duration(2*i) * time.Second)},
					},
				},
			)
		}
		bulk, err := cli.Compliance(cluster).Snapshots().Create(ctx, snapshots)
		require.NoError(t, err)
		require.Equal(t, totalItems, bulk.Succeeded, "create snapshots did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Stream through all the items.
		params := v1.SnapshotParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(time.Duration(2*totalItems) * time.Second),
				},
				MaxPageSize: 1000,
			},
		}

		pager := client.NewListPager[v1.Snapshot](&params)
		pages, errors := pager.Stream(ctx, cli.Compliance(cluster).Snapshots().List)

		receivedItems := 0
		for page := range pages {
			receivedItems = receivedItems + len(page.Items)
		}

		if err, ok := <-errors; ok {
			require.NoError(t, err)
		}

		require.Equal(t, receivedItems, totalItems)
	})
}

func TestFV_SnapshotsTenancy(t *testing.T) {
	RunComplianceSnapshotTest(t, "should support tenancy restriction", func(t *testing.T, idx bapi.Index) {
		// Instantiate a client for an unexpected tenant.
		args := DefaultLinseedArgs()
		args.TenantID = "bad-tenant"
		tenantCLI, err := NewLinseedClient(args, TokenPath)
		require.NoError(t, err)

		// Create a basic entry. We expect this to fail, since we're using
		// an unexpected tenant ID on the request.
		snapshots := v1.Snapshot{
			ResourceList: list.TimestampedResourceList{
				ResourceList: &apiv3.NetworkPolicyList{
					TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
					ListMeta: metav1.ListMeta{},
					Items: []apiv3.NetworkPolicy{
						{
							TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "np1",
								Namespace: "default",
							},
						},
					},
				},
				RequestStartedTimestamp:   metav1.Time{Time: time.Unix(1, 0)},
				RequestCompletedTimestamp: metav1.Time{Time: time.Unix(2, 0)},
			},
		}
		bulk, err := tenantCLI.Compliance(cluster1).Snapshots().Create(ctx, []v1.Snapshot{snapshots})
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, bulk)

		// Try a read as well.
		params := v1.SnapshotParams{}
		resp, err := tenantCLI.Compliance(cluster1).Snapshots().List(ctx, &params)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, resp)
	})
}

func snapshotsWithUTCTime(resp *v1.List[v1.Snapshot]) []v1.Snapshot {
	for idx, snapshot := range resp.Items {
		utcStartTime := snapshot.ResourceList.RequestStartedTimestamp.UTC()
		utcEndTime := snapshot.ResourceList.RequestCompletedTimestamp.UTC()
		resp.Items[idx].ResourceList.RequestStartedTimestamp = metav1.Time{Time: utcStartTime}
		resp.Items[idx].ResourceList.RequestCompletedTimestamp = metav1.Time{Time: utcEndTime}
		resp.Items[idx].ID = ""
	}
	return resp.Items
}
