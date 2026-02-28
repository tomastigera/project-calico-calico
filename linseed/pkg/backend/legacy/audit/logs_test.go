// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package audit_test

import (
	"context"
	"encoding/json"
	gojson "encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kaudit "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/kubernetes/pkg/apis/apps"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/audit"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/templates"
	backendutils "github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

var (
	client          lmaelastic.Client
	b               bapi.AuditBackend
	migration       bapi.AuditBackend
	ctx             context.Context
	cluster1        string
	cluster2        string
	cluster3        string
	kubeIndexGetter bapi.Index
	eeIndexGetter   bapi.Index
)

// RunAllModes runs the given test function twice, once using the single-index backend, and once using
// the multi-index backend.
func RunAllModes(t *testing.T, name string, testFn func(t *testing.T)) {
	// Run using the multi-index backend.
	t.Run(fmt.Sprintf("%s [legacy]", name), func(t *testing.T) {
		defer setupTest(t, false)()
		testFn(t)
	})

	// Run using the single-index backend.
	t.Run(fmt.Sprintf("%s [singleindex]", name), func(t *testing.T) {
		defer setupTest(t, true)()
		testFn(t)
	})
}

// setupTest runs common logic before each test, and also returns a function to perform teardown
// after each test.
func setupTest(t *testing.T, singleIndex bool) func() {
	// Hook logrus into testing.T
	config.ConfigureLogging("TRACE")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	// Create an elasticsearch client to use for the test. For this suite, we use a real
	// elasticsearch instance created via "make run-elastic".
	esClient, err := elastic.NewSimpleClient(elastic.SetURL("http://localhost:9200"), elastic.SetInfoLog(logrus.StandardLogger()))
	require.NoError(t, err)
	client = lmaelastic.NewWithClient(esClient)
	cache := templates.NewCachedInitializer(client, 1, 0)

	// Instantiate a backend.
	if singleIndex {
		kubeIndexGetter = index.AuditLogIndex()
		eeIndexGetter = index.AuditLogIndex()
		b = audit.NewSingleIndexBackend(client, cache, 10000, false)
		migration = audit.NewSingleIndexBackend(client, cache, 10000, true)
	} else {
		b = audit.NewBackend(client, cache, 10000, false)
		migration = audit.NewBackend(client, cache, 10000, true)
		kubeIndexGetter = index.AuditLogKubeMultiIndex
		eeIndexGetter = index.AuditLogEEMultiIndex
	}

	// Create a random cluster name for each test to make sure we don't
	// interfere between tests.
	cluster1 = backendutils.RandomClusterName()
	cluster2 = backendutils.RandomClusterName()
	cluster3 = backendutils.RandomClusterName()

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)

	// Function contains teardown logic.
	return func() {
		getters := []bapi.Index{kubeIndexGetter, eeIndexGetter}
		if singleIndex {
			// No need to duplicate since they are the same.
			getters = []bapi.Index{kubeIndexGetter}
		}
		for _, indexGetter := range getters {
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				err = backendutils.CleanupIndices(context.Background(), esClient, singleIndex, indexGetter, bapi.ClusterInfo{Cluster: cluster})
				require.NoError(t, err)
			}
		}

		// Cancel the context
		cancel()
		logCancel()
	}
}

func TestInvalidRequests(t *testing.T) {
	RunAllModes(t, "no log type specified", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}
		_, err := b.Create(ctx, "", clusterInfo, []v1.AuditLog{})
		require.Error(t, err)

		_, err = b.List(ctx, clusterInfo, &v1.AuditLogParams{})
		require.Error(t, err)
	})

	RunAllModes(t, "unsupported log type specified", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}
		_, err := b.Create(ctx, "NotARealType", clusterInfo, []v1.AuditLog{})
		require.Error(t, err)

		_, err = b.List(ctx, clusterInfo, &v1.AuditLogParams{Type: "invalid"})
		require.Error(t, err)
	})
}

// TestCreateKubeAuditLog tests running a real elasticsearch query to create a kube audit log.
func TestCreateKubeAuditLog(t *testing.T) {
	RunAllModes(t, "TestCreateKubeAuditLog", func(t *testing.T) {
		cluster1Info := bapi.ClusterInfo{Cluster: cluster1}
		cluster2Info := bapi.ClusterInfo{Cluster: cluster2}
		cluster3Info := bapi.ClusterInfo{Cluster: cluster3}

		// The DaemonSet that this audit log is for.
		ds := apps.DaemonSet{
			TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		}
		dsRaw, err := json.Marshal(ds)
		require.NoError(t, err)

		f := v1.AuditLog{
			Event: kaudit.Event{
				TypeMeta:   metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
				AuditID:    types.UID("some-uuid-most-likely"),
				Stage:      kaudit.StageResponseComplete,
				Level:      kaudit.LevelRequestResponse,
				RequestURI: "/apis/v1/namespaces",
				Verb:       "GET",
				User: authnv1.UserInfo{
					Username: "user",
					UID:      "uid",
					Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
				},
				ImpersonatedUser: &authnv1.UserInfo{
					Username: "impuser",
					UID:      "impuid",
					Groups:   []string{"g1"},
				},
				SourceIPs:      []string{"1.2.3.4"},
				UserAgent:      "user-agent",
				ObjectRef:      &kaudit.ObjectReference{},
				ResponseStatus: &metav1.Status{},
				RequestObject: &runtime.Unknown{
					Raw:         dsRaw,
					ContentType: runtime.ContentTypeJSON,
				},
				ResponseObject: &runtime.Unknown{
					Raw:         dsRaw,
					ContentType: runtime.ContentTypeJSON,
				},
				RequestReceivedTimestamp: metav1.NewMicroTime(time.Now().Add(-5 * time.Second)),
				StageTimestamp:           metav1.NewMicroTime(time.Now()),
				Annotations:              map[string]string{"brick": "red"},
			},
			Name: testutils.StringPtr("any"),
		}

		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			// Create the event in ES.
			resp, err := b.Create(ctx, v1.AuditLogTypeKube, clusterInfo, []v1.AuditLog{f})
			require.NoError(t, err)
			require.Empty(t, resp.Errors)

			// Refresh the index.
			err = backendutils.RefreshIndex(ctx, client, kubeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)
		}

		params := &v1.AuditLogParams{Type: v1.AuditLogTypeKube}

		t.Run("should query single cluster", func(t *testing.T) {
			// List the event, assert that it matches the one we just wrote.
			results, err := b.List(ctx, cluster1Info, params)
			require.NoError(t, err)
			backendutils.AssertAuditLogsGeneratedTimeAndReset(t, results)
			require.Equal(t, 1, len(results.Items))

			// MicroTime doesn't JSON serialize and deserialize properly, so we need to force the results to
			// match here. When you serialize and deserialize a MicroTime, the microsecond precision is lost
			// and so the resulting objects do not match.
			f.RequestReceivedTimestamp = results.Items[0].RequestReceivedTimestamp
			f.StageTimestamp = results.Items[0].StageTimestamp
			f.Cluster = cluster1Info.Cluster // cluster is set by the backend.

			// require.Equal(t, string(f.RequestObject.Raw), string(results.Items[0].RequestObject.Raw))
			require.Equal(t, f, results.Items[0])
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}

			params.SetClusters(selectedClusters)
			// List the event, assert that it matches the one we just wrote.
			results, err := b.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, params)
			require.NoError(t, err)
			require.Equal(t, 2, len(results.Items))

			require.Falsef(t, backendutils.MatchIn(results.Items, backendutils.AuditLogClusterEquals(cluster1)), "found unexpected cluster %s", cluster1)
			for i, cluster := range selectedClusters {
				require.Truef(t, backendutils.MatchIn(results.Items, backendutils.AuditLogClusterEquals(cluster)), "didn't cluster %d: %s", i, cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			results, err := b.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, params)
			require.NoError(t, err)
			for i, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, backendutils.MatchIn(results.Items, backendutils.AuditLogClusterEquals(cluster)), "didn't find cluster %d: %s", i, cluster)
			}
		})
	})
}

// TestCreateEEAuditLog tests running a real elasticsearch query to create a EE audit log.
func TestCreateEEAuditLog(t *testing.T) {
	RunAllModes(t, "TestCreateEEAuditLog", func(t *testing.T) {
		cluster1Info := bapi.ClusterInfo{Cluster: cluster1}
		cluster2Info := bapi.ClusterInfo{Cluster: cluster2}
		cluster3Info := bapi.ClusterInfo{Cluster: cluster3}

		// The NetworkSet that this audit log is for.
		obj := v3.GlobalNetworkSet{
			TypeMeta: metav1.TypeMeta{Kind: "GlobalNetworkSet", APIVersion: "projectcalico.org/v3"},
		}
		objRaw, err := json.Marshal(obj)
		require.NoError(t, err)

		f := v1.AuditLog{
			Event: kaudit.Event{
				TypeMeta:   metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
				AuditID:    types.UID("some-uuid-most-likely"),
				Stage:      kaudit.StageResponseComplete,
				Level:      kaudit.LevelRequestResponse,
				RequestURI: "/apis/v3/projectcalico.org",
				Verb:       "PUT",
				User: authnv1.UserInfo{
					Username: "user",
					UID:      "uid",
					Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
				},
				ImpersonatedUser: &authnv1.UserInfo{
					Username: "impuser",
					UID:      "impuid",
					Groups:   []string{"g1"},
				},
				SourceIPs:      []string{"1.2.3.4"},
				UserAgent:      "user-agent",
				ObjectRef:      &kaudit.ObjectReference{},
				ResponseStatus: &metav1.Status{},
				RequestObject: &runtime.Unknown{
					Raw:         objRaw,
					ContentType: runtime.ContentTypeJSON,
				},
				ResponseObject: &runtime.Unknown{
					Raw:         objRaw,
					ContentType: runtime.ContentTypeJSON,
				},
				RequestReceivedTimestamp: metav1.NewMicroTime(time.Now().Add(-5 * time.Second)),
				StageTimestamp:           metav1.NewMicroTime(time.Now()),
				Annotations:              map[string]string{"brick": "red"},
			},
			Name: testutils.StringPtr("ee-any"),
		}

		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			// Create the event in ES.
			resp, err := b.Create(ctx, v1.AuditLogTypeEE, clusterInfo, []v1.AuditLog{f})
			require.NoError(t, err)
			require.Equal(t, 0, len(resp.Errors))

			// Refresh the index.
			err = backendutils.RefreshIndex(ctx, client, eeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)
		}

		params := &v1.AuditLogParams{Type: v1.AuditLogTypeEE}
		t.Run("should query single cluster", func(t *testing.T) {
			clusterInfo := cluster1Info
			// List the event, assert that it matches the one we just wrote.
			results, err := b.List(ctx, clusterInfo, params)
			require.NoError(t, err)
			require.Equal(t, 1, len(results.Items))

			// MicroTime doesn't JSON serialize and deserialize properly, so we need to force the results to
			// match here. When you serialize and deserialize a MicroTime, the microsecond precision is lost
			// and so the resulting objects do not match.
			f.RequestReceivedTimestamp = results.Items[0].RequestReceivedTimestamp
			f.StageTimestamp = results.Items[0].StageTimestamp
			f.Cluster = clusterInfo.Cluster // cluster is set by the backend.
			backendutils.AssertGeneratedTimeAndReset(t, &results.Items[0])
			require.Equal(t, f, results.Items[0])
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)
			results, err := b.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, params)
			require.NoError(t, err)
			require.Len(t, results.Items, 2)

			require.Falsef(t, backendutils.MatchIn(results.Items, backendutils.AuditLogClusterEquals(cluster1)), "found unexpected cluster %s", cluster1)
			for i, cluster := range selectedClusters {
				require.Truef(t, backendutils.MatchIn(results.Items, backendutils.AuditLogClusterEquals(cluster)), "didn't find cluster %d: %s", i, cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			results, err := b.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, params)
			require.NoError(t, err)
			for i, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, backendutils.MatchIn(results.Items, backendutils.AuditLogClusterEquals(cluster)), "didn't find cluster %d: %s", i, cluster)
			}
		})
	})
}

func TestAuditLogFiltering(t *testing.T) {
	type testCase struct {
		Name   string
		Params v1.AuditLogParams

		// Configuration for which logs are expected to match.
		ExpectLog1 bool
		ExpectLog2 bool
		ExpectKube bool

		// Whether to perform an equality comparison on the returned
		// logs. Can be useful for tests where stats differ.
		SkipComparison bool

		// Whether or not to filter based on time range.
		AllTime bool

		// Whether to expect an error.
		ExpectError bool
	}

	numExpected := func(tc testCase) int {
		num := 0
		if tc.ExpectLog1 {
			num++
		}
		if tc.ExpectLog2 {
			num++
		}
		if tc.ExpectKube {
			num++
		}
		return num
	}

	testcases := []testCase{
		{
			Name: "should query both logs",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeEE,
			},
			ExpectLog1: true,
			ExpectLog2: true,
		},
		{
			Name: "should filter based on type",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeKube,
			},
			ExpectLog1: false,
			ExpectLog2: false,
			ExpectKube: true,
		},
		{
			Name: "should filter based on kind",
			Params: v1.AuditLogParams{
				Kinds: []v1.Kind{v1.KindNetworkPolicy},
				Type:  v1.AuditLogTypeEE,
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should filter based on name",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeEE,
				ObjectRefs: []v1.ObjectReference{
					{Name: "np-1"},
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should filter based on multiple names",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeEE,
				ObjectRefs: []v1.ObjectReference{
					{Name: "np-1"},
					{Name: "gnp-1"},
				},
			},
			ExpectLog1: true,
			ExpectLog2: true,
		},
		{
			Name: "should filter based on author",
			Params: v1.AuditLogParams{
				Authors: []string{"garfunkel"},
				Type:    v1.AuditLogTypeEE,
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should filter based on namespace",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeEE,
				ObjectRefs: []v1.ObjectReference{
					{Namespace: "default"},
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should filter based on global namespaces",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeEE,
				ObjectRefs: []v1.ObjectReference{
					{Namespace: "-"},
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should filter based on multiple namespaces",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeAny,
				ObjectRefs: []v1.ObjectReference{
					{Namespace: "default"},
					{Namespace: "calico-system"},
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
			ExpectKube: true,
		},
		{
			Name: "should filter based on API group",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeEE,
				ObjectRefs: []v1.ObjectReference{
					{APIGroup: "projectcalico.org"},
				},
			},
			ExpectLog1: true,
			ExpectLog2: true,
		},
		{
			Name: "should filter based on API group and version",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeEE,
				ObjectRefs: []v1.ObjectReference{
					{
						APIGroup:   "projectcalico.org",
						APIVersion: "v4",
					},
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should filter based on resource",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeEE,
				ObjectRefs: []v1.ObjectReference{
					{
						Resource: "globalnetworkpolicies",
					},
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should filter based on response code",
			Params: v1.AuditLogParams{
				Type:          v1.AuditLogTypeEE,
				ResponseCodes: []int32{201},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should support returning both kube and EE audit logs at once",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeAny,
			},
			ExpectLog1: true,
			ExpectLog2: true,
			ExpectKube: true,
		},
		{
			Name: "should support queries that have no time range",
			Params: v1.AuditLogParams{
				Type: v1.AuditLogTypeAny,
			},
			AllTime:    true,
			ExpectLog1: true,
			ExpectLog2: true,
			ExpectKube: true,
		},
		{
			Name: "should support matching on Level",
			Params: v1.AuditLogParams{
				Type:   v1.AuditLogTypeEE,
				Levels: []kaudit.Level{kaudit.LevelRequestResponse},
			},
			AllTime:    true,
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should support matching on Stage",
			Params: v1.AuditLogParams{
				Type:   v1.AuditLogTypeEE,
				Stages: []kaudit.Stage{kaudit.StageResponseComplete},
			},
			AllTime:    true,
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should reject multiple stages",
			Params: v1.AuditLogParams{
				Type:   v1.AuditLogTypeEE,
				Stages: []kaudit.Stage{kaudit.StageResponseComplete, kaudit.StageRequestReceived},
			},
			AllTime:     true,
			ExpectLog1:  false,
			ExpectLog2:  false,
			ExpectError: true,
		},

		{
			Name: "should support matching on Verbs",
			Params: v1.AuditLogParams{
				Type:  v1.AuditLogTypeEE,
				Verbs: []v1.Verb{v1.Get},
			},
			AllTime:    true,
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should exclude dryRun records",
			Params: v1.AuditLogParams{
				Type:           v1.AuditLogTypeEE,
				ExcludeDryRuns: true,
			},
			AllTime:    true,
			ExpectLog1: true,
			ExpectLog2: false,
		},
	}

	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		for _, testcase := range testcases {
			// Each testcase creates multiple audit logs, and then uses
			// different filtering parameters provided in the params
			// to query one or more audit logs.
			name := fmt.Sprintf("%s (tenant=%s)", testcase.Name, tenant)
			RunAllModes(t, name, func(t *testing.T) {
				cluster1Info := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
				cluster2Info := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
				cluster3Info := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

				// Time that the logs occur.
				logTime := time.Unix(1, 0)

				// Set the time range for the test. We set this per-test
				// so that the time range captures the windows that the logs
				// are created in.
				tr := &lmav1.TimeRange{}
				tr.From = logTime.Add(-1 * time.Millisecond)
				tr.To = logTime.Add(1 * time.Millisecond)
				testcase.Params.TimeRange = tr

				// The object that audit log is for.
				obj := v3.NetworkPolicy{
					TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
				}
				objRaw, err := json.Marshal(obj)
				require.NoError(t, err)

				// Create log #1.
				a1 := v1.AuditLog{
					Event: kaudit.Event{
						TypeMeta:   metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
						AuditID:    types.UID("audit-log-one"),
						Stage:      kaudit.StageResponseComplete,
						Level:      kaudit.LevelRequestResponse,
						RequestURI: "/apis/v3/projectcalico.org",
						Verb:       string(v1.Update),
						User: authnv1.UserInfo{
							Username: "garfunkel",
							UID:      "1234",
							Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
						},
						ImpersonatedUser: &authnv1.UserInfo{
							Username: "impuser",
							UID:      "impuid",
							Groups:   []string{"g1"},
						},
						SourceIPs: []string{"1.2.3.4"},
						UserAgent: "user-agent",
						ObjectRef: &kaudit.ObjectReference{
							Resource:   "networkpolicies",
							Name:       "np-1",
							Namespace:  "default",
							APIGroup:   "projectcalico.org",
							APIVersion: "v3",
						},
						ResponseStatus: &metav1.Status{
							Code: 200,
						},
						RequestObject: &runtime.Unknown{
							Raw:         objRaw,
							ContentType: runtime.ContentTypeJSON,
						},
						ResponseObject: &runtime.Unknown{
							Raw:         objRaw,
							ContentType: runtime.ContentTypeJSON,
						},
						RequestReceivedTimestamp: metav1.NewMicroTime(logTime),
						StageTimestamp:           metav1.NewMicroTime(logTime),
						Annotations:              map[string]string{"brick": "red"},
					},
					Name: testutils.StringPtr("ee-any"),
				}

				// The object that audit log is for.
				obj = v3.NetworkPolicy{
					TypeMeta: metav1.TypeMeta{Kind: "GlobalNetworkPolicy", APIVersion: "projectcalico.org/v4"},
				}
				objRaw2, err := json.Marshal(obj)
				require.NoError(t, err)

				// Create log #2.
				a2 := v1.AuditLog{
					Event: kaudit.Event{
						TypeMeta:   metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
						AuditID:    types.UID("audit-log-two"),
						Stage:      kaudit.StageRequestReceived,
						Level:      kaudit.LevelRequest,
						RequestURI: "/apis/v3/projectcalico.org?dryRun=All",
						Verb:       string(v1.Get),
						User: authnv1.UserInfo{
							Username: "oates",
							UID:      "0987",
							Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
						},
						ImpersonatedUser: &authnv1.UserInfo{
							Username: "impuser",
							UID:      "impuid",
							Groups:   []string{"g1"},
						},
						SourceIPs: []string{"1.2.3.4"},
						UserAgent: "user-agent",
						ObjectRef: &kaudit.ObjectReference{
							Resource:   "globalnetworkpolicies",
							Name:       "gnp-1",
							Namespace:  "",
							APIGroup:   "projectcalico.org",
							APIVersion: "v4",
						},
						ResponseStatus: &metav1.Status{
							Code: 201,
						},
						RequestObject: &runtime.Unknown{
							Raw:         objRaw2,
							ContentType: runtime.ContentTypeJSON,
						},
						ResponseObject: &runtime.Unknown{
							Raw:         objRaw2,
							ContentType: runtime.ContentTypeJSON,
						},
						RequestReceivedTimestamp: metav1.NewMicroTime(logTime),
						StageTimestamp:           metav1.NewMicroTime(logTime),
						Annotations:              map[string]string{"brick": "red"},
					},
					Name: testutils.StringPtr("ee-any"),
				}

				// Also create a Kube audit log.
				ds := apps.DaemonSet{
					TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				}
				dsRaw, err := json.Marshal(ds)
				require.NoError(t, err)

				a3 := v1.AuditLog{
					Event: kaudit.Event{
						TypeMeta:   metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
						AuditID:    types.UID("some-uuid-most-likely"),
						Stage:      kaudit.StageResponseComplete,
						Level:      kaudit.LevelRequestResponse,
						RequestURI: "/apis/v1/namespaces",
						Verb:       "GET",
						User: authnv1.UserInfo{
							Username: "prince",
							UID:      "uid",
							Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
						},
						ImpersonatedUser: &authnv1.UserInfo{
							Username: "impuser",
							UID:      "impuid",
							Groups:   []string{"g1"},
						},
						SourceIPs: []string{"1.2.3.4"},
						UserAgent: "user-agent",
						ObjectRef: &kaudit.ObjectReference{
							Resource:   "daemonsets",
							Name:       "calico-node",
							Namespace:  "calico-system",
							APIGroup:   "apps",
							APIVersion: "v1",
						},
						ResponseStatus: &metav1.Status{},
						RequestObject: &runtime.Unknown{
							Raw:         dsRaw,
							ContentType: runtime.ContentTypeJSON,
						},
						ResponseObject: &runtime.Unknown{
							Raw:         dsRaw,
							ContentType: runtime.ContentTypeJSON,
						},
						RequestReceivedTimestamp: metav1.NewMicroTime(logTime),
						StageTimestamp:           metav1.NewMicroTime(logTime),
						Annotations:              map[string]string{"brick": "red"},
					},
					Name: testutils.StringPtr("any"),
				}

				for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
					response, err := b.Create(ctx, v1.AuditLogTypeEE, clusterInfo, []v1.AuditLog{a1, a2})
					require.NoError(t, err)
					require.Equal(t, []v1.BulkError(nil), response.Errors)
					require.Equal(t, 0, response.Failed)

					resp, err := b.Create(ctx, v1.AuditLogTypeKube, clusterInfo, []v1.AuditLog{a3})
					require.NoError(t, err)
					require.Equal(t, 0, len(resp.Errors))

					err = backendutils.RefreshIndex(ctx, client, eeIndexGetter.Index(clusterInfo))
					require.NoError(t, err)
					err = backendutils.RefreshIndex(ctx, client, kubeIndexGetter.Index(clusterInfo))
					require.NoError(t, err)
				}

				t.Run("should query single cluster", func(t *testing.T) {
					clusterInfo := cluster1Info

					// Query for audit logs.
					r, err := b.List(ctx, clusterInfo, &testcase.Params)
					if testcase.ExpectError {
						require.Error(t, err)
						return
					} else {
						require.NoError(t, err)
					}
					require.Len(t, r.Items, numExpected(testcase))
					require.Nil(t, r.AfterKey)
					require.Empty(t, err)
					for i := range r.Items {
						backendutils.AssertAuditLogClusterAndReset(t, clusterInfo.Cluster, &r.Items[i])
						backendutils.AssertGeneratedTimeAndReset(t, &r.Items[i])
					}

					// Querying with another tenant ID should result in zero results.
					r2, err := b.List(ctx, bapi.ClusterInfo{Cluster: clusterInfo.Cluster, Tenant: "bad-actor"}, &testcase.Params)
					require.NoError(t, err)
					require.Len(t, r2.Items, 0)

					if testcase.SkipComparison {
						return
					}

					// Assert that the correct logs are returned.
					if testcase.ExpectLog1 {
						require.Contains(t, r.Items, a1)
					}
					if testcase.ExpectLog2 {
						require.Contains(t, r.Items, a2)
					}
					if testcase.ExpectKube {
						require.Contains(t, r.Items, a3)
					}
				})
			})
		}
	}
}

func TestAggregations(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		RunAllModes(t, fmt.Sprintf("should return time-series audit log aggregation results (tenant=%s)", tenant), func(t *testing.T) {
			cluster1Info := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
			cluster2Info := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
			cluster3Info := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

			// Start the test numLogs minutes in the past.
			numLogs := 5
			timeBetweenLogs := 10 * time.Second
			testStart := time.Unix(0, 0)
			now := testStart.Add(time.Duration(numLogs) * time.Minute)

			// Several dummy logs.
			logs := []v1.AuditLog{}
			start := testStart.Add(1 * time.Second)
			for i := 1; i < numLogs; i++ {
				log := v1.AuditLog{
					Event: kaudit.Event{
						TypeMeta: metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
						Stage:    kaudit.StageResponseComplete,
						Level:    kaudit.LevelRequestResponse,
						User: authnv1.UserInfo{
							Username: "prince",
							UID:      "uid",
							Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
						},
						ImpersonatedUser: &authnv1.UserInfo{
							Username: "impuser",
							UID:      "impuid",
							Groups:   []string{"g1"},
						},
						SourceIPs: []string{"1.2.3.4"},
						ObjectRef: &kaudit.ObjectReference{
							Resource:   "daemonsets",
							Name:       "calico-node",
							Namespace:  "calico-system",
							APIGroup:   "apps",
							APIVersion: "v1",
						},
						RequestReceivedTimestamp: metav1.NewMicroTime(start),
						StageTimestamp:           metav1.NewMicroTime(start),
						Annotations:              map[string]string{"brick": "red"},
					},
					Name: testutils.StringPtr("any"),
				}
				start = start.Add(timeBetweenLogs)
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
				resp, err := b.Create(ctx, v1.AuditLogTypeEE, clusterInfo, logs)
				require.NoError(t, err)
				require.Empty(t, resp.Errors)

				// Refresh.
				err = backendutils.RefreshIndex(ctx, client, eeIndexGetter.Index(clusterInfo))
				require.NoError(t, err)
				err = backendutils.RefreshIndex(ctx, client, kubeIndexGetter.Index(clusterInfo))
				require.NoError(t, err)
			}

			type testCase struct {
				Name             string
				XClusterID       string
				ParamsCallback   func(params *v1.AuditLogAggregationParams)
				ExpectedDocCount int
			}
			testcases := []testCase{
				{
					Name:             "single cluster",
					XClusterID:       cluster1,
					ExpectedDocCount: 1,
				},
				{
					Name:       "multiple clusters",
					XClusterID: v1.QueryMultipleClusters,
					ParamsCallback: func(params *v1.AuditLogAggregationParams) {
						params.SetClusters([]string{cluster1, cluster2})
					},
					ExpectedDocCount: 2,
				},
				{
					Name:       "all clusters",
					XClusterID: v1.QueryMultipleClusters,
					ParamsCallback: func(params *v1.AuditLogAggregationParams) {
						params.SetAllClusters(true)
					},
					ExpectedDocCount: 3,
				},
			}

			for _, tc := range testcases {
				t.Run(tc.Name, func(t *testing.T) {
					clusterInfo := bapi.ClusterInfo{Cluster: tc.XClusterID, Tenant: tenant}

					params := v1.AuditLogAggregationParams{}
					params.Type = v1.AuditLogTypeEE
					params.TimeRange = &lmav1.TimeRange{}
					params.TimeRange.From = testStart
					params.TimeRange.To = now
					params.NumBuckets = 4
					if f := tc.ParamsCallback; f != nil {
						f(&params)
					}

					// Add a simple aggregation to add up the total bytes_in from the logs.
					userAgg := elastic.NewTermsAggregation().Field("user.username")
					src, err := userAgg.Source()
					require.NoError(t, err)
					bytes, err := json.Marshal(src)
					require.NoError(t, err)
					params.Aggregations = map[string]gojson.RawMessage{"user": bytes}

					// Use the backend to perform a query.
					aggs, err := b.Aggregations(ctx, clusterInfo, &params)
					require.NoError(t, err)
					require.NotNil(t, aggs)

					ts, ok := aggs.AutoDateHistogram("tb")
					require.True(t, ok)

					// We asked for 4 buckets.
					require.Len(t, ts.Buckets, 4)

					for i, b := range ts.Buckets {
						require.Equal(t, int64(tc.ExpectedDocCount), b.DocCount, fmt.Sprintf("Bucket %d", i))

						// We asked for a user agg, which should include a single log
						// in each bucket.
						users, ok := b.ValueCount("user")
						require.True(t, ok, "Bucket missing user agg")
						require.NotNil(t, users.Aggregations)
						buckets := string(users.Aggregations["buckets"])
						require.Equal(t, fmt.Sprintf(`[{"key":"prince","doc_count":%d}]`, tc.ExpectedDocCount), buckets)
					}
				})
			}
		})

		RunAllModes(t, fmt.Sprintf("should return aggregate stats (tenant=%s)", tenant), func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}

			// Start the test numLogs minutes in the past.
			numLogs := 5
			timeBetweenLogs := 10 * time.Second
			testStart := time.Unix(0, 0)
			now := testStart.Add(time.Duration(numLogs) * time.Minute)

			// Several dummy logs.
			logs := []v1.AuditLog{}
			start := testStart.Add(1 * time.Second)
			for i := 1; i < numLogs; i++ {
				log := v1.AuditLog{
					Event: kaudit.Event{
						TypeMeta: metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
						Stage:    kaudit.StageResponseComplete,
						Level:    kaudit.LevelRequestResponse,
						User: authnv1.UserInfo{
							Username: "prince",
							UID:      "uid",
							Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
						},
						ImpersonatedUser: &authnv1.UserInfo{
							Username: "impuser",
							UID:      "impuid",
							Groups:   []string{"g1"},
						},
						SourceIPs: []string{"1.2.3.4"},
						ObjectRef: &kaudit.ObjectReference{
							Resource:   "daemonsets",
							Name:       "calico-node",
							Namespace:  "calico-system",
							APIGroup:   "apps",
							APIVersion: "v1",
						},
						RequestReceivedTimestamp: metav1.NewMicroTime(start),
						StageTimestamp:           metav1.NewMicroTime(start),
						Annotations:              map[string]string{"brick": "red"},
					},
					Name: testutils.StringPtr("any"),
				}
				start = start.Add(timeBetweenLogs)
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := b.Create(ctx, v1.AuditLogTypeEE, clusterInfo, logs)
			require.NoError(t, err)
			require.Empty(t, resp.Errors)

			// Refresh.
			err = backendutils.RefreshIndex(ctx, client, eeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)
			err = backendutils.RefreshIndex(ctx, client, kubeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)

			params := v1.AuditLogAggregationParams{}
			params.Type = v1.AuditLogTypeEE
			params.TimeRange = &lmav1.TimeRange{}
			params.TimeRange.From = testStart
			params.TimeRange.To = now
			params.NumBuckets = 0 // Return aggregated stats over the whole time range.

			// Add a simple aggregation to add up the total bytes_in from the logs.
			userAgg := elastic.NewTermsAggregation().Field("user.username")
			src, err := userAgg.Source()
			require.NoError(t, err)
			bytes, err := json.Marshal(src)
			require.NoError(t, err)
			params.Aggregations = map[string]gojson.RawMessage{"user": bytes}

			// Use the backend to perform a stats query.
			result, err := b.Aggregations(ctx, clusterInfo, &params)
			require.NoError(t, err)

			// We should get a sum aggregation with all 4 logs.
			users, ok := result.ValueCount("user")
			require.True(t, ok)
			require.NotNil(t, users.Aggregations)
			buckets := string(users.Aggregations["buckets"])
			require.Equal(t, `[{"key":"prince","doc_count":4}]`, buckets)
		})
	}
}

func TestSorting(t *testing.T) {
	RunAllModes(t, "should respect sorting", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		t1 := time.Unix(100, 0)
		t2 := time.Unix(500, 0)

		log1 := v1.AuditLog{
			Event: kaudit.Event{
				TypeMeta: metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
				Stage:    kaudit.StageResponseComplete,
				Level:    kaudit.LevelRequestResponse,
				User: authnv1.UserInfo{
					Username: "prince",
					UID:      "uid",
					Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
				},
				ImpersonatedUser: &authnv1.UserInfo{
					Username: "impuser",
					UID:      "impuid",
					Groups:   []string{"g1"},
				},
				SourceIPs: []string{"1.2.3.4"},
				ObjectRef: &kaudit.ObjectReference{
					Resource:   "daemonsets",
					Name:       "calico-node",
					Namespace:  "calico-system",
					APIGroup:   "apps",
					APIVersion: "v1",
				},
				RequestReceivedTimestamp: metav1.NewMicroTime(t1),
				StageTimestamp:           metav1.NewMicroTime(t1),
				Annotations:              map[string]string{"brick": "red"},
			},
			Name: testutils.StringPtr("any"),
		}
		log2 := v1.AuditLog{
			Event: kaudit.Event{
				TypeMeta: metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
				Stage:    kaudit.StageResponseComplete,
				Level:    kaudit.LevelRequestResponse,
				User: authnv1.UserInfo{
					Username: "aladdin",
					UID:      "uid",
					Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"strong"})},
				},
				ImpersonatedUser: &authnv1.UserInfo{
					Username: "impuser",
					UID:      "impuid",
					Groups:   []string{"g1"},
				},
				SourceIPs: []string{"1.2.3.4"},
				ObjectRef: &kaudit.ObjectReference{
					Resource:   "daemonsets",
					Name:       "calico-node",
					Namespace:  "calico-system",
					APIGroup:   "apps",
					APIVersion: "v1",
				},
				RequestReceivedTimestamp: metav1.NewMicroTime(t2),
				StageTimestamp:           metav1.NewMicroTime(t2),
				Annotations:              map[string]string{"brick": "red"},
			},
			Name: testutils.StringPtr("any"),
		}

		response, err := b.Create(ctx, v1.AuditLogTypeEE, clusterInfo, []v1.AuditLog{log1, log2})
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = backendutils.RefreshIndex(ctx, client, eeIndexGetter.Index(clusterInfo))
		require.NoError(t, err)
		err = backendutils.RefreshIndex(ctx, client, kubeIndexGetter.Index(clusterInfo))
		require.NoError(t, err)

		// Query for logs without sorting.
		params := v1.AuditLogParams{}
		params.Type = v1.AuditLogTypeEE
		r, err := b.List(ctx, clusterInfo, &params)
		require.NoError(t, err)
		require.Len(t, r.Items, 2)
		require.Nil(t, r.AfterKey)
		for i := range r.Items {
			backendutils.AssertAuditLogClusterAndReset(t, clusterInfo.Cluster, &r.Items[i])
			backendutils.AssertGeneratedTimeAndReset(t, &r.Items[i])
		}

		// Assert that the logs are returned in the correct order.
		require.Equal(t, log1, r.Items[0])
		require.Equal(t, log2, r.Items[1])

		// Query again, this time sorting in order to get the logs in reverse order.
		params.Sort = []v1.SearchRequestSortBy{
			{
				Field:      "requestReceivedTimestamp",
				Descending: true,
			},
		}
		r, err = b.List(ctx, clusterInfo, &params)
		require.NoError(t, err)
		require.Len(t, r.Items, 2)
		require.Nil(t, r.AfterKey)
		for i := range r.Items {
			backendutils.AssertAuditLogClusterAndReset(t, clusterInfo.Cluster, &r.Items[i])
			backendutils.AssertGeneratedTimeAndReset(t, &r.Items[i])
		}
		require.Equal(t, log2, r.Items[0])
		require.Equal(t, log1, r.Items[1])
	})
}

func TestRetrieveMostRecentAuditLogs(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		name := fmt.Sprintf("TestRetrieveMostRecentAuditLogs (tenant=%s)", tenant)
		RunAllModes(t, name, func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Tenant: tenant, Cluster: cluster1}

			t1 := time.Unix(500, 0)
			t2 := time.Unix(400, 0)
			t3 := time.Unix(300, 0)

			now := time.Now().UTC()

			log1 := v1.AuditLog{
				Event: kaudit.Event{
					TypeMeta: metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
					Stage:    kaudit.StageResponseComplete,
					Level:    kaudit.LevelRequestResponse,
					User: authnv1.UserInfo{
						Username: "prince",
						UID:      "uid",
						Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
					},
					ImpersonatedUser: &authnv1.UserInfo{
						Username: "impuser",
						UID:      "impuid",
						Groups:   []string{"g1"},
					},
					SourceIPs: []string{"1.2.3.4"},
					ObjectRef: &kaudit.ObjectReference{
						Resource:   "daemonsets",
						Name:       "calico-node",
						Namespace:  "calico-system",
						APIGroup:   "apps",
						APIVersion: "v1",
					},
					RequestReceivedTimestamp: metav1.NewMicroTime(t1),
					StageTimestamp:           metav1.NewMicroTime(t1),
					Annotations:              map[string]string{"brick": "red"},
				},
				Name: testutils.StringPtr("any"),
			}
			log2 := v1.AuditLog{
				Event: kaudit.Event{
					TypeMeta: metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
					Stage:    kaudit.StageResponseComplete,
					Level:    kaudit.LevelRequestResponse,
					User: authnv1.UserInfo{
						Username: "aladdin",
						UID:      "uid",
						Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"strong"})},
					},
					ImpersonatedUser: &authnv1.UserInfo{
						Username: "impuser",
						UID:      "impuid",
						Groups:   []string{"g1"},
					},
					SourceIPs: []string{"1.2.3.4"},
					ObjectRef: &kaudit.ObjectReference{
						Resource:   "daemonsets",
						Name:       "calico-node",
						Namespace:  "calico-system",
						APIGroup:   "apps",
						APIVersion: "v1",
					},
					RequestReceivedTimestamp: metav1.NewMicroTime(t2),
					StageTimestamp:           metav1.NewMicroTime(t2),
					Annotations:              map[string]string{"brick": "red"},
				},
				Name: testutils.StringPtr("log2-any"),
			}

			response, err := b.Create(ctx, v1.AuditLogTypeEE, clusterInfo, []v1.AuditLog{log1, log2})
			require.NoError(t, err)
			require.Equal(t, []v1.BulkError(nil), response.Errors)
			require.Equal(t, 0, response.Failed)

			err = backendutils.RefreshIndex(ctx, client, eeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)
			err = backendutils.RefreshIndex(ctx, client, kubeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Query for logs
			params := v1.AuditLogParams{}
			params.Type = v1.AuditLogTypeEE
			params.QueryParams = v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					Field: lmav1.FieldGeneratedTime,
					From:  now.Add(-1 * time.Second).UTC(),
				},
			}
			params.Sort = []v1.SearchRequestSortBy{
				{
					Field: string(lmav1.FieldGeneratedTime),
				},
			}
			r, err := b.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, r.Items, 2)
			require.Nil(t, r.AfterKey)
			lastGeneratedTime := r.Items[1].GeneratedTime
			for i := range r.Items {
				backendutils.AssertAuditLogClusterAndReset(t, clusterInfo.Cluster, &r.Items[i])
				backendutils.AssertGeneratedTimeAndReset(t, &r.Items[i])
			}

			// Assert that the logs are returned in the correct order.
			require.Equal(t, log1, r.Items[0])
			require.Equal(t, log2, r.Items[1])

			log3 := v1.AuditLog{
				Event: kaudit.Event{
					TypeMeta: metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
					Stage:    kaudit.StageResponseComplete,
					Level:    kaudit.LevelRequestResponse,
					User: authnv1.UserInfo{
						Username: "jasmin",
						UID:      "uid",
						Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"strong"})},
					},
					ImpersonatedUser: &authnv1.UserInfo{
						Username: "impuser",
						UID:      "impuid",
						Groups:   []string{"g1"},
					},
					SourceIPs: []string{"1.2.3.4"},
					ObjectRef: &kaudit.ObjectReference{
						Resource:   "deployments",
						Name:       "linseed",
						Namespace:  "tigera-elasticsearch",
						APIGroup:   "apps",
						APIVersion: "v1",
					},
					RequestReceivedTimestamp: metav1.NewMicroTime(t3),
					StageTimestamp:           metav1.NewMicroTime(t3),
					Annotations:              map[string]string{"brick": "red"},
				},
				Name: testutils.StringPtr("log3-any"),
			}

			response, err = b.Create(ctx, v1.AuditLogTypeEE, clusterInfo, []v1.AuditLog{log3})
			require.NoError(t, err)
			require.Equal(t, []v1.BulkError(nil), response.Errors)
			require.Equal(t, 0, response.Failed)

			err = backendutils.RefreshIndex(ctx, client, eeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)
			err = backendutils.RefreshIndex(ctx, client, kubeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Query the last ingested log
			params.QueryParams = v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					Field: lmav1.FieldGeneratedTime,
					From:  lastGeneratedTime.UTC(),
				},
			}

			r, err = b.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, r.Items, 1)
			require.Nil(t, r.AfterKey)
			for i := range r.Items {
				backendutils.AssertAuditLogClusterAndReset(t, clusterInfo.Cluster, &r.Items[i])
				backendutils.AssertGeneratedTimeAndReset(t, &r.Items[i])
			}

			// Assert that the logs are returned in the correct order.
			require.Equal(t, log3, r.Items[0])
		})
	}
}

func TestPreserveAuditEEIDs(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		RunAllModes(t, fmt.Sprintf("should preserve IDs across bulk ingestion requests (tenant=%s)", tenant), func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}

			numLogs := 5
			testStart := time.Unix(0, 0).UTC()

			// Several dummy logs.
			logs := []v1.AuditLog{}
			for i := 1; i <= numLogs; i++ {
				start := testStart.Add(time.Duration(i) * time.Second)
				log := v1.AuditLog{Event: kaudit.Event{
					TypeMeta: metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
					Stage:    kaudit.StageResponseComplete,
					Level:    kaudit.LevelRequestResponse,
					User: authnv1.UserInfo{
						Username: "jasmin",
						UID:      "uid",
						Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"strong"})},
					},
					ImpersonatedUser: &authnv1.UserInfo{
						Username: "impuser",
						UID:      "impuid",
						Groups:   []string{"g1"},
					},
					SourceIPs: []string{"1.2.3.4"},
					ObjectRef: &kaudit.ObjectReference{
						Resource:   "deployments",
						Name:       "linseed",
						Namespace:  "tigera-elasticsearch",
						APIGroup:   "apps",
						APIVersion: "v1",
					},
					RequestReceivedTimestamp: metav1.NewMicroTime(start),
					StageTimestamp:           metav1.NewMicroTime(start),
					Annotations:              map[string]string{"brick": "red"},
				},
					Name: testutils.StringPtr("log-any"),
				}
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := migration.Create(ctx, v1.AuditLogTypeEE, clusterInfo, logs)
			require.NoError(t, err)
			require.Empty(t, resp.Errors)

			// Refresh.
			err = backendutils.RefreshIndex(ctx, client, eeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Read it back and make sure generated time values are what we expect.
			allOpts := v1.AuditLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: testStart.Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
				Type: v1.AuditLogTypeEE,
			}
			first, err := migration.List(ctx, clusterInfo, &allOpts)
			require.NoError(t, err)
			require.Len(t, first.Items, numLogs)

			bulk, err := migration.Create(ctx, v1.AuditLogTypeEE, clusterInfo, first.Items)
			require.NoError(t, err)
			require.Empty(t, bulk.Errors)

			second, err := migration.List(ctx, clusterInfo, &allOpts)
			require.NoError(t, err)
			require.Len(t, second.Items, numLogs)

			for _, log := range first.Items {
				require.NotEmpty(t, log.ID)
				backendutils.AssertGeneratedTimeAndReset[v1.AuditLog](t, &log)
			}
			for _, log := range second.Items {
				require.NotEmpty(t, log.ID)
				backendutils.AssertGeneratedTimeAndReset[v1.AuditLog](t, &log)
			}

			require.Equal(t, first.Items, second.Items)

			// Refresh before cleaning up data
			err = backendutils.RefreshIndex(ctx, client, eeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)

		})
	}
}

func TestPreserveAuditKubeIDs(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		RunAllModes(t, fmt.Sprintf("should preserve IDs across bulk ingestion requests (tenant=%s)", tenant), func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}

			numLogs := 5
			testStart := time.Unix(0, 0).UTC()

			// Several dummy logs.
			logs := []v1.AuditLog{}
			for i := 1; i <= numLogs; i++ {
				start := testStart.Add(time.Duration(i) * time.Second)
				log := v1.AuditLog{Event: kaudit.Event{
					TypeMeta: metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
					Stage:    kaudit.StageResponseComplete,
					Level:    kaudit.LevelRequestResponse,
					User: authnv1.UserInfo{
						Username: "jasmin",
						UID:      "uid",
						Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"strong"})},
					},
					ImpersonatedUser: &authnv1.UserInfo{
						Username: "impuser",
						UID:      "impuid",
						Groups:   []string{"g1"},
					},
					SourceIPs: []string{"1.2.3.4"},
					ObjectRef: &kaudit.ObjectReference{
						Resource:   "deployments",
						Name:       "linseed",
						Namespace:  "tigera-elasticsearch",
						APIGroup:   "apps",
						APIVersion: "v1",
					},
					RequestReceivedTimestamp: metav1.NewMicroTime(start),
					StageTimestamp:           metav1.NewMicroTime(start),
					Annotations:              map[string]string{"brick": "red"},
				},
					Name: testutils.StringPtr("log-any"),
				}
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := migration.Create(ctx, v1.AuditLogTypeKube, clusterInfo, logs)
			require.NoError(t, err)
			require.Empty(t, resp.Errors)

			// Refresh.
			err = backendutils.RefreshIndex(ctx, client, kubeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Read it back and make sure generated time values are what we expect.
			allOpts := v1.AuditLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: testStart.Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
				Type: v1.AuditLogTypeKube,
			}
			first, err := migration.List(ctx, clusterInfo, &allOpts)
			require.NoError(t, err)
			require.Len(t, first.Items, numLogs)

			bulk, err := migration.Create(ctx, v1.AuditLogTypeKube, clusterInfo, first.Items)
			require.NoError(t, err)
			require.Empty(t, bulk.Errors)

			second, err := migration.List(ctx, clusterInfo, &allOpts)
			require.NoError(t, err)
			require.Len(t, second.Items, numLogs)

			for _, log := range first.Items {
				require.NotEmpty(t, log.ID)
				backendutils.AssertGeneratedTimeAndReset[v1.AuditLog](t, &log)
			}
			for _, log := range second.Items {
				require.NotEmpty(t, log.ID)
				backendutils.AssertGeneratedTimeAndReset[v1.AuditLog](t, &log)
			}

			require.Equal(t, first.Items, second.Items)

			// Refresh before cleaning up data
			err = backendutils.RefreshIndex(ctx, client, kubeIndexGetter.Index(clusterInfo))
			require.NoError(t, err)

		})
	}
}
