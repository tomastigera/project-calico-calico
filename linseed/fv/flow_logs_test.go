// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

// Run runs the given flow log test in all modes.
func RunFlowLogTest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	t.Run(fmt.Sprintf("%s [MultiIndex]", name), func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.FlowLogMultiIndex)()
		testFn(t, index.FlowLogMultiIndex)
	})

	t.Run(fmt.Sprintf("%s [SingleIndex]", name), func(t *testing.T) {
		confArgs := &RunConfigureElasticArgs{
			FlowBaseIndexName: index.FlowLogIndex().Name(bapi.ClusterInfo{}),
			FlowPolicyName:    index.FlowLogIndex().ILMPolicyName(),
		}
		args := DefaultLinseedArgs()
		args.Backend = config.BackendTypeSingleIndex
		defer setupAndTeardown(t, args, confArgs, index.FlowLogIndex())()
		testFn(t, index.FlowLogIndex())
	})
}

func TestFV_FlowLogs(t *testing.T) {
	RunFlowLogTest(t, "should return an empty list if there are no flow logs", func(t *testing.T, idx bapi.Index) {
		params := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now(),
				},
			},
		}

		// Perform a query.
		logs, err := cli.FlowLogs(cluster1).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, []v1.FlowLog{}, logs.Items)
	})

	RunFlowLogTest(t, "should create and list flow logs", func(t *testing.T, idx bapi.Index) {
		// Create a basic flow log.
		logs := []v1.FlowLog{
			{
				EndTime: time.Now().Unix(), // TODO- more fields.
			},
		}
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			bulk, err := cli.FlowLogs(clusterInfo.Cluster).Create(ctx, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create flow log did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
		}

		// Read it back.
		params := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
			},
		}

		t.Run("should query single cluster", func(t *testing.T) {
			cluster := cluster1
			resp, err := cli.FlowLogs(cluster).List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, logs, testutils.AssertFlowLogsIDAndClusterAndReset(t, cluster, resp))
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)

			_, err := cli.FlowLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.FlowLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			require.Len(t, resp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.FlowLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			_, err := cli.FlowLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.FlowLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.FlowLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})
	})

	RunFlowLogTest(t, "should support pagination", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 5

		// Create 5 flow logs.
		logTime := time.Now().UTC().Unix()
		for i := 0; i < totalItems; i++ {
			logs := []v1.FlowLog{
				{
					StartTime: logTime,
					EndTime:   logTime + int64(i), // Make sure logs are ordered.
					Host:      fmt.Sprintf("%d", i),
				},
			}
			bulk, err := cli.FlowLogs(cluster).Create(ctx, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create flow log did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Iterate through the first 4 pages and check they are correct.
		var afterKey map[string]interface{}
		for i := 0; i < totalItems-1; i++ {
			params := v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Second),
					},
					MaxPageSize: 1,
					AfterKey:    afterKey,
				},
			}
			resp, err := cli.FlowLogs(cluster).List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, 1, len(resp.Items))
			require.Equal(t, []v1.FlowLog{
				{
					StartTime: logTime,
					EndTime:   logTime + int64(i),
					Host:      fmt.Sprintf("%d", i),
				},
			}, testutils.AssertFlowLogsIDAndClusterAndReset(t, cluster, resp), fmt.Sprintf("Flow #%d did not match", i))
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
		params := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
				MaxPageSize: 1,
				AfterKey:    afterKey,
			},
		}
		resp, err := cli.FlowLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Items))
		require.Equal(t, []v1.FlowLog{
			{
				StartTime: logTime,
				EndTime:   logTime + int64(lastItem),
				Host:      fmt.Sprintf("%d", lastItem),
			},
		}, testutils.AssertFlowLogsIDAndClusterAndReset(t, cluster, resp), fmt.Sprintf("Flow #%d did not match", lastItem))
		require.Equal(t, resp.TotalHits, int64(totalItems))

		// Once we reach the end of the data, we should not receive
		// an afterKey
		require.Nil(t, resp.AfterKey)
	})

	RunFlowLogTest(t, "should support pagination for items >= 10000 for flows", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 10001
		// Create > 10K logs.
		logTime := time.Now().UTC().Unix()
		var logs []v1.FlowLog
		for i := 0; i < totalItems; i++ {
			logs = append(logs, v1.FlowLog{
				StartTime: logTime,
				EndTime:   logTime + int64(i), // Make sure logs are ordered.
				Host:      fmt.Sprintf("%d", i),
			},
			)
		}
		bulk, err := cli.FlowLogs(cluster).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, totalItems, bulk.Total, "create logs did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Stream through all the items.
		params := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(time.Duration(totalItems) * time.Second),
				},
				MaxPageSize: 1000,
			},
		}

		pager := client.NewListPager[v1.FlowLog](&params)
		pages, errors := pager.Stream(ctx, cli.FlowLogs(cluster).List)

		receivedItems := 0
		for page := range pages {
			receivedItems = receivedItems + len(page.Items)
		}

		if err, ok := <-errors; ok {
			require.NoError(t, err)
		}

		require.Equal(t, receivedItems, totalItems)
	})

	RunFlowLogTest(t, "should reject request with invalid policy_match values", func(t *testing.T, idx bapi.Index) {
		namespace := "wrong/namespace"
		name := "wrong:name"

		params := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
			},
			PolicyMatches: []v1.PolicyMatch{
				{
					Type:      "wrong_type",
					Tier:      "wrong.tier",
					Namespace: &namespace,
					Name:      &name,
				},
			},
		}
		_, err := cli.FlowLogs(cluster1).List(ctx, &params)
		require.ErrorContains(t, err, "error with the following fields")
		require.ErrorContains(t, err, "Type = 'wrong_type' (Reason: failed to validate Field: Type because of Tag: oneof )")
		require.ErrorContains(t, err, "Tier = 'wrong.tier' (Reason: failed to validate Field: Tier because of Tag: excludesall )")
		require.ErrorContains(t, err, "Namespace = 'wrong/namespace' (Reason: failed to validate Field: Namespace because of Tag: excludesall )")
		require.ErrorContains(t, err, "Name = 'wrong:name' (Reason: failed to validate Field: Name because of Tag: excludesall )")
	})
}

func TestFV_FlowLogsTenancy(t *testing.T) {
	RunFlowLogTest(t, "should reject requests with a bad tenant ID", func(t *testing.T, idx bapi.Index) {
		// Instantiate a client for an unexpected tenant.
		args := DefaultLinseedArgs()
		args.TenantID = "bad-tenant"
		tenantCLI, err := NewLinseedClient(args, TokenPath)
		require.NoError(t, err)

		cluster := cluster1
		// Create a basic flow log. We expect this to fail, since we're using
		// an unexpected tenant ID on the request.
		logs := []v1.FlowLog{
			{
				EndTime: time.Now().Unix(),
			},
		}
		bulk, err := tenantCLI.FlowLogs(cluster).Create(ctx, logs)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, bulk)

		// Try a read as well.
		params := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
			},
		}
		resp, err := tenantCLI.FlowLogs(cluster).List(ctx, &params)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, resp)
	})

	RunFlowLogTest(t, "should enforce tenancy boundaries with multiple linseed instances", func(t *testing.T, idx bapi.Index) {
		// In this test, we run a second instance of linseed configured with the tenant ID "tenant-b",
		// and then make sure that each instance only returns data for the tenant it is configured for.
		cluster := cluster1
		clusterInfo := cluster1Info

		// Create tenant-b Linseed instance, running on a different port.
		tenantBArgs := DefaultLinseedArgs()
		tenantBArgs.TenantID = "tenant-b"
		tenantBArgs.Port = tenantBArgs.Port + 1
		tenantBArgs.MetricsPort = 0
		tenantBArgs.HealthPort = 0
		lb := RunLinseed(t, tenantBArgs)
		defer lb.Stop()

		// Create a valid client for tenant-b.
		tenantBCLI, err := NewLinseedClient(tenantBArgs, TokenPath)
		require.NoError(t, err)

		// Create a client that uses tenant-b, but is configured to talk to tenant-a's Linseed instance.
		tenantBArgs.Port = DefaultLinseedArgs().Port
		tenantBWrongCLI, err := NewLinseedClient(tenantBArgs, TokenPath)
		require.NoError(t, err)

		// Create a flow log in tenant-a.
		logs := []v1.FlowLog{
			{
				EndTime: time.Now().Unix(), // TODO- more fields.
			},
		}
		bulk, err := cli.FlowLogs(cluster).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, bulk.Succeeded, 1, "create flow log did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Try to read the flow log from tenant-b's Linseed instance. This should return successfully, but with no results.
		params := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
			},
		}
		resp, err := tenantBCLI.FlowLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, len(resp.Items), 0, "expected no results")

		// Now try to read it with the wrong tenant ID. This should return an error.
		resp, err = tenantBWrongCLI.FlowLogs(cluster).List(ctx, &params)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, resp)

		// Tenant A should be able to read its own logs though.
		resp, err = cli.FlowLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, len(resp.Items), 1, "expected one result")
	})
}

func TestFV_FlowLogsRBAC(t *testing.T) {
	type filterTestCase struct {
		name        string
		permissions []v3.AuthorizedResourceVerbs

		sourceType      string
		sourceNamespace string
		destType        string
		destNamespace   string

		expectError bool
		expectMatch bool
	}

	testcases := []filterTestCase{
		// Create a request with no List permissions. It should return an error.
		{
			name: "should reject requests with no list permissions",
			permissions: []v3.AuthorizedResourceVerbs{
				{
					APIGroup: "projectcalico.org/v3",
					Resource: "workloadendpoints",
					Verbs: []v3.AuthorizedResourceVerb{
						{
							Verb: "create",
						},
					},
				},
			},
			expectError: true,
		},

		// Create a flow log with source type WEP, but only
		// provide permissions for HEP. We shouldn't get any results.
		{
			name:            "should filter out on source type",
			sourceType:      "wep",
			sourceNamespace: "default",
			permissions: []v3.AuthorizedResourceVerbs{
				{
					APIGroup: "projectcalico.org/v3",
					Resource: "hostendpoints",
					Verbs: []v3.AuthorizedResourceVerb{
						{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{
								{Namespace: ""},
							},
						},
					},
				},
			},
			expectError: false,
			expectMatch: false,
		},

		// Create a flow log with source type WEP, provide permissions for pods.
		// We should be able to query the log.
		{
			name:            "should select on source type",
			sourceType:      "wep",
			sourceNamespace: "default",
			permissions: []v3.AuthorizedResourceVerbs{
				{
					APIGroup: "projectcalico.org/v3",
					Resource: "pods",
					Verbs: []v3.AuthorizedResourceVerb{
						{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{
								{Namespace: ""},
							},
						},
					},
				},
			},
			expectError: false,
			expectMatch: true,
		},

		// Create a flow log with source type WEP, provide permissions for pods in
		// a different namespace, but not the flow log's namespace.
		// We should not see the log in the response.
		{
			name:            "should filter out based on source namespace",
			sourceType:      "wep",
			sourceNamespace: "default",
			permissions: []v3.AuthorizedResourceVerbs{
				{
					APIGroup: "projectcalico.org/v3",
					Resource: "pods",
					Verbs: []v3.AuthorizedResourceVerb{
						{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{
								{Namespace: "another-namespace"},
							},
						},
					},
				},
			},
			expectError: false,
			expectMatch: false,
		},

		// Create a flow log with destination of a global network set.
		// Allow permissions for network sets in all namespaces.
		// We should not see the log in the response.
		{
			name:            "should filter out based on source namespace",
			sourceType:      "wep",
			sourceNamespace: "default",
			destType:        "ns",
			destNamespace:   "-",
			permissions: []v3.AuthorizedResourceVerbs{
				{
					APIGroup: "projectcalico.org/v3",
					Resource: "networksets",
					Verbs: []v3.AuthorizedResourceVerb{
						{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{
								{Namespace: ""},
							},
						},
					},
				},
			},
			expectError: false,
			expectMatch: false,
		},

		// Create a flow log with destination of a global network set.
		// Allow permissions for global network sets.
		// We should see the log in the response.
		{
			name:            "should filter out based on source namespace",
			sourceType:      "wep",
			sourceNamespace: "default",
			destType:        "ns",
			destNamespace:   "-",
			permissions: []v3.AuthorizedResourceVerbs{
				{
					APIGroup: "projectcalico.org/v3",
					Resource: "globalnetworksets",
					Verbs: []v3.AuthorizedResourceVerb{
						{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{
								{Namespace: ""},
							},
						},
					},
				},
			},
			expectError: false,
			expectMatch: true,
		},
	}

	for _, testcase := range testcases {
		RunFlowLogTest(t, testcase.name, func(t *testing.T, idx bapi.Index) {
			clusterInfo := cluster1Info
			cluster := clusterInfo.Cluster

			// Create a flow log with the given parameters.
			logs := []v1.FlowLog{
				{
					SourceNamespace: testcase.sourceNamespace,
					SourceType:      testcase.sourceType,
					DestNamespace:   testcase.destNamespace,
					DestType:        testcase.destType,
					EndTime:         time.Now().Unix(),
				},
			}
			bulk, err := cli.FlowLogs(cluster).Create(ctx, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create flow log did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)

			// Perform a query using the testcase permissions.
			params := v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Second),
					},
					MaxPageSize: 1,
				},
				LogSelectionParams: v1.LogSelectionParams{Permissions: testcase.permissions},
			}
			resp, err := cli.FlowLogs(cluster).List(ctx, &params)

			if testcase.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if testcase.expectMatch {
				require.Equal(t, logs, testutils.AssertFlowLogsIDAndClusterAndReset(t, cluster, resp))
			}
		})
	}
}
