package query

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/aggregations"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/filters"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query"
	fakerepository "github.com/projectcalico/calico/dashboards/pkg/internal/repository/fake"
	"github.com/projectcalico/calico/dashboards/pkg/internal/repository/linseed"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/managedclusters"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lsrest "github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/ui-apis/pkg/authzreview"
)

// mockReviewer implements authzreview.Reviewer for tests.
type mockReviewer struct {
	fn func(ctx context.Context, usr user.Info, cluster string, attrs []v3.AuthorizationReviewResourceAttributes) ([]v3.AuthorizedResourceVerbs, error)
}

func (m *mockReviewer) Review(ctx context.Context, usr user.Info, cluster string, attrs []v3.AuthorizationReviewResourceAttributes) ([]v3.AuthorizedResourceVerbs, error) {
	return m.fn(ctx, usr, cluster, attrs)
}

func (m *mockReviewer) ReviewForLogs(ctx context.Context, usr user.Info, cluster string) ([]v3.AuthorizedResourceVerbs, error) {
	return m.Review(ctx, usr, cluster, nil)
}

// Note: elastic.AggregationBucketHistogramItem does not have json tags to Marshal, so use local structs instead
type bucketItem map[string]any

type bucketItems struct {
	Buckets []bucketItem `json:"buckets,omitempty"`
}

func newLMAResource(verb string, resources ...string) authzv1.ResourceRule {
	return authzv1.ResourceRule{
		Verbs:         []string{verb},
		APIGroups:     []string{security.APIGroupLMATigera},
		ResourceNames: []string{"flows", "dns", "l7"},
		Resources:     resources,
	}
}

func newAuthContext(
	t *testing.T,
	logger logging.Logger,
	namespacedRBAC bool,
	reviewer authzreview.Reviewer,
	resourceRules ...authzv1.ResourceRule,
) security.Context {
	t.Helper()

	authorizer, err := security.NewAuthorizer(
		t.Context(),
		logger,
		3*time.Second,
		security.AuthorizerConfig{
			Namespace:                             "default",
			EnableNamespacedRBAC:                  namespacedRBAC,
			AuthorizedVerbsCacheHardTTL:           3 * time.Second,
			AuthorizedVerbsCacheSoftTTL:           3 * time.Second,
			AuthorizedVerbsCacheReviewsTimeout:    3 * time.Second,
			AuthorizedVerbsCacheRevalidateTimeout: 3 * time.Second,
		},
		reviewer,
	)
	require.NoError(t, err)

	k8sClient := k8sfake.NewClientset()
	k8sClient.PrependReactor("create", "selfsubjectrulesreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {

		createAction, ok := action.(k8stesting.CreateAction)
		require.True(t, ok, "invalid reactor action, expecting k8stesting.CreateAction but got", action)

		object := createAction.GetObject().DeepCopyObject()
		selfSubjectRulesReview, ok := object.(*authzv1.SelfSubjectRulesReview)
		require.True(t, ok, "invalid reactor object, expecting *SelfSubjectRulesReview but got", object)

		selfSubjectRulesReview.Status.ResourceRules = resourceRules

		return true, selfSubjectRulesReview, nil
	})

	return security.NewUserAuthContext(
		context.Background(),
		&user.DefaultInfo{Name: "fake-user"},
		authorizer,
		k8sClient,
		"Bearer fake-token",
		k8s.NewMockClientSetFactory(t),
		"fake-tenant",
		nil,
	)
}

func TestQueryService(t *testing.T) {

	logger := logging.New("TestQueryService")

	ctx := newAuthContext(t, logger, false, nil,
		newLMAResource("get", "cluster1", "cluster2", "cluster3"),
	)

	tenantID := "fake-tenant"

	mockClient := lsclient.NewMockClient(tenantID)
	repository := linseed.NewLinseedRepositoryWithClient(logger, "", mockClient)

	managedClusterLister := managedclusters.NameListerFunc(func(ctx context.Context) ([]query.ManagedClusterName, error) {
		return []query.ManagedClusterName{"cluster1", "cluster2", "cluster3"}, nil
	})

	testConfig := Config{
		QueryTimeout:           time.Duration(2) * time.Minute,
		MaxRequestFilters:      10,
		MaxRequestAggregations: 5,
	}

	allCollections := collections.Collections(nil)

	subject := NewQueryService(logger, repository, allCollections, managedClusterLister, testConfig)

	t.Run("authorization", func(t *testing.T) {
		t.Run("unauthorized", func(t *testing.T) {

			testCases := []struct {
				name               string
				authorizedResource authzv1.ResourceRule
			}{
				{
					name:               "no permissions",
					authorizedResource: authzv1.ResourceRule{},
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ctx := newAuthContext(t, logger, false, nil, tc.authorizedResource)

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
						},
					})

					require.Equal(t, httpreply.ReplyAccessDenied, err)
				})
			}
		})

		t.Run("authorized", func(t *testing.T) {

			testCases := []struct {
				name               string
				config             Config
				clusterFilter      []client.ManagedClusterName
				namespacedRBAC     bool
				authorizedResource authzv1.ResourceRule
				expected           error
			}{
				{
					name:               "partial for cluster1",
					config:             testConfig,
					clusterFilter:      []client.ManagedClusterName{"cluster1", "cluster2"},
					namespacedRBAC:     false,
					authorizedResource: newLMAResource("get", "cluster1"),
					expected: httpreply.Reply{
						Key:     httpreply.AccessDenied,
						Status:  httpreply.ReplyAccessDenied.Status,
						Message: "access denied to cluster cluster2",
					},
				},
				{
					name:               "partial for cluster2",
					clusterFilter:      []client.ManagedClusterName{"cluster1", "cluster2"},
					namespacedRBAC:     false,
					authorizedResource: newLMAResource("get", "cluster2"),
					expected: httpreply.Reply{
						Key:     httpreply.AccessDenied,
						Status:  httpreply.ReplyAccessDenied.Status,
						Message: "access denied to cluster cluster1",
					},
				},
				{
					name:               "all requested clusters",
					clusterFilter:      []client.ManagedClusterName{"cluster1", "cluster2"},
					namespacedRBAC:     false,
					authorizedResource: newLMAResource("get", "cluster1", "cluster2"),
					expected:           nil,
				},
				{
					name:               "all clusters",
					clusterFilter:      nil,
					namespacedRBAC:     false,
					authorizedResource: newLMAResource("get", "cluster1", "cluster2"),
					expected:           nil,
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ctx := newAuthContext(t, logger, tc.namespacedRBAC, nil, tc.authorizedResource)

					mockClient.SetResults(lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})})

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						ClusterFilter:  tc.clusterFilter,
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
						},
					})

					require.Equal(t, tc.expected, err)
				})
			}
		})
	})

	t.Run("permissions", func(t *testing.T) {
		t.Run("namespaced RBAC disabled", func(t *testing.T) {
			ctx := newAuthContext(t, logger, false, nil, newLMAResource("get", "cluster1", "cluster2", "cluster3"))

			fakeRepository := fakerepository.NewFakeRepository()
			subject := NewQueryService(logger, fakeRepository, allCollections, managedClusterLister, testConfig)

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				ClusterFilter:  nil,
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
				},
			})
			require.NoError(t, err)

			queries := fakeRepository.Queries()
			require.Len(t, queries, 1)
			require.Len(t, queries[0].Permissions, 0)
		})

		testCases := []struct {
			name                                    string
			authReviewError                         map[string]error
			authReviewStatusAuthorizedResourceVerbs map[string][]v3.AuthorizedResourceVerbs
			expectedAuthorizedResourceVerbs         []v3.AuthorizedResourceVerbs
			expected                                client.QueryResponse
		}{
			{
				name: "namespaced RBAC enabled",
				expected: client.QueryResponse{
					Documents:     []client.QueryResponseDocument{},
					GroupValues:   []client.QueryResponseGroupValue{},
					Aggregations:  client.QueryResponseAggregations{},
					ClusterErrors: map[string][]error{},
				},
				expectedAuthorizedResourceVerbs: []v3.AuthorizedResourceVerbs{{
					APIGroup: "projectcalico.org",
				}},
			},
			{
				name: "namespaced RBAC enabled with partial results",
				authReviewError: map[string]error{
					"cluster2": fmt.Errorf("an expected error"),
				},
				expected: client.QueryResponse{
					Documents:    []client.QueryResponseDocument{},
					GroupValues:  []client.QueryResponseGroupValue{},
					Aggregations: client.QueryResponseAggregations{},
					ClusterErrors: map[string][]error{
						"cluster2": {fmt.Errorf("an expected error")},
					},
				},
				authReviewStatusAuthorizedResourceVerbs: map[string][]v3.AuthorizedResourceVerbs{
					"cluster1": {{
						APIGroup: "projectcalico.org",
						Resource: "fake-resource",
						Verbs: []v3.AuthorizedResourceVerb{{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{{
								Namespace: "fake-namespace1",
							}},
						}},
					}},
					"cluster3": {{
						APIGroup: "projectcalico.org",
						Resource: "fake-resource",
						Verbs: []v3.AuthorizedResourceVerb{{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{{
								Namespace: "fake-namespace3",
							}},
						}},
					}},
				},
				expectedAuthorizedResourceVerbs: []v3.AuthorizedResourceVerbs{
					{
						APIGroup: "projectcalico.org",
						Resource: "fake-resource",
						Verbs: []v3.AuthorizedResourceVerb{{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{{
								Namespace:      "fake-namespace1",
								ManagedCluster: "cluster1",
							}},
						}},
					},
					{
						APIGroup: "projectcalico.org",
						Resource: "fake-resource",
						Verbs: []v3.AuthorizedResourceVerb{{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{{
								Namespace:      "fake-namespace3",
								ManagedCluster: "cluster3",
							}},
						}},
					},
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				resources := []string{"cluster1", "cluster2", "cluster3"}

				reviewer := &mockReviewer{fn: func(_ context.Context, _ user.Info, cluster string, _ []v3.AuthorizationReviewResourceAttributes) ([]v3.AuthorizedResourceVerbs, error) {
					if err, ok := tc.authReviewError[cluster]; ok {
						return nil, err
					}
					return tc.authReviewStatusAuthorizedResourceVerbs[cluster], nil
				}}

				ctx := newAuthContext(t, logger, true, reviewer, newLMAResource("get", resources...))

				fakeRepository := fakerepository.NewFakeRepository()
				subject := NewQueryService(logger, fakeRepository, allCollections, managedClusterLister, testConfig)

				queryResponse, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					ClusterFilter:  nil,
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
					},
				})
				require.NoError(t, err)

				queries := fakeRepository.Queries()
				require.Len(t, queries, 1)
				require.ElementsMatch(t, tc.expectedAuthorizedResourceVerbs, queries[0].Permissions)
				require.Equal(t, tc.expected, queryResponse)
			})
		}
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("cluster", func(t *testing.T) {
			t.Run("unknown", func(t *testing.T) {
				ctx := newAuthContext(t, logger, false, nil, newLMAResource("get", "cluster1"))

				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"unknown-cluster"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
					},
				})

				require.Equal(t, httpreply.ReplyAccessDenied, err)
			})

			t.Run("clusterFilter", func(t *testing.T) {
				testCases := []struct {
					name                string
					clusterFilter       []client.ManagedClusterName
					authorizedResources []string

					message          string
					expectedErr      error
					expectedClusters []string
				}{
					{
						name:                "is empty",
						clusterFilter:       nil,
						authorizedResources: []string{"*"}, // authorized for all managed clusters
						expectedClusters:    []string{},
						message:             "expected QueryParams clusters be empty and AllClusters to be set",
					},
					{
						name:                "is empty with partial resources authorized authorization",
						clusterFilter:       nil,
						authorizedResources: []string{"cluster2", "cluster3"}, // authorized for subset of managed clusters
						expectedClusters:    []string{"cluster2", "cluster3"},
						message:             "expected QueryParams clusters be match authorized resources",
					},
					{
						name:                "is set",
						clusterFilter:       []client.ManagedClusterName{"cluster2", "cluster3"},
						authorizedResources: []string{"cluster1", "cluster2", "cluster3"},
						expectedClusters:    []string{"cluster2", "cluster3"},
						message:             "expected QueryParams cluster to match clusterFilter",
					},
					{
						name:                "contains unknown cluster",
						clusterFilter:       []client.ManagedClusterName{"cluster2", "cluster3", "cluster-unknown"},
						authorizedResources: []string{"cluster1", "cluster2", "cluster3"},
						message:             "expected request denied",
						expectedErr:         httpreply.ReplyAccessDenied,
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						ctx := newAuthContext(t, logger, false, nil, newLMAResource("get", tc.authorizedResources...))

						if tc.expectedErr == nil {
							mockClient.SetResults(
								lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
							)
						}

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							ClusterFilter:  tc.clusterFilter,
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							},
						})

						if tc.expectedErr != nil {
							require.Equal(t, tc.expectedErr, err)
						} else {
							require.NoError(t, err)

							requests := mockClient.Requests()
							require.Len(t, requests, 1)
							require.IsType(t, &lsv1.FlowLogParams{}, requests[0].GetParams())

							flowLogParams := requests[0].GetParams().(*lsv1.FlowLogParams)
							require.Equal(t, tc.expectedClusters, flowLogParams.GetClusters(), tc.message)

							if len(tc.expectedClusters) == 0 {
								require.True(t, flowLogParams.AllClusters, tc.message)
							} else {
								require.False(t, flowLogParams.AllClusters, tc.message)
							}
						}
					})
				}
			})
		})

		t.Run("unknown criterion type", func(t *testing.T) {
			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "unknown"}},
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
				},
			})
			require.ErrorContains(t, err, "invalid request: Key: 'QueryRequest.Filters[0].Criterion.Type' Error:Field validation for 'Type' failed")
		})
		t.Run("request filters limit", func(t *testing.T) {
			subject := NewQueryService(
				logger,
				repository,
				allCollections,
				managedClusterLister,
				Config{
					QueryTimeout:           testConfig.QueryTimeout,
					MaxRequestFilters:      1,
					MaxRequestAggregations: testConfig.MaxRequestAggregations,
				},
			)

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
					{Criterion: client.QueryRequestFilterCriterion{Type: "exists", Field: "dest_name"}},
				},
			})
			require.ErrorContains(t, err, "filters limit exceeded")
		})
		t.Run("request aggregations limit", func(t *testing.T) {
			subject := NewQueryService(
				logger,
				repository,
				allCollections,
				managedClusterLister,
				Config{
					QueryTimeout:           testConfig.QueryTimeout,
					MaxRequestFilters:      testConfig.MaxRequestFilters,
					MaxRequestAggregations: 1,
				},
			)

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
				},
				Aggregations: map[client.QueryRequestAggregationKey]client.QueryRequestAggregation{
					"agg1": {FieldName: "bytes_in", Function: client.QueryRequestAggregationFunction{Type: "max"}},
					"agg2": {FieldName: "bytes_in", Function: client.QueryRequestAggregationFunction{Type: "min"}},
				},
			})
			require.ErrorContains(t, err, "aggregations limit exceeded")
		})

		t.Run("time range criterion", func(t *testing.T) {
			t.Run("none", func(t *testing.T) {
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
				})
				require.ErrorContains(t, err, "no time range filter set")
			})
			t.Run("empty", func(t *testing.T) {
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange"}},
					},
				})
				require.ErrorContains(t, err, "unknown collection field name '' for criterion type 'relativeTimeRange''")
			})
			t.Run("invalid", func(t *testing.T) {
				t.Run("relativeTimeRange", func(t *testing.T) {
					t.Run("gte duration", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "invalid1", LTE: "10m", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value for relativeTimeRange gte field: invalid1`)
					})
					t.Run("lte duration", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "10m", LTE: "invalid2", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value for relativeTimeRange lte field: invalid2`)
					})
					t.Run("missing field", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "10m", LTE: "5m"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `unknown collection field name '' for criterion type 'relativeTimeRange'`)
					})
					t.Run("unknown field", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "10m", LTE: "5m", Field: "unknown-field"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `unknown collection field name 'unknown-field'`)
					})
					t.Run("incorrect field type", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "10m", LTE: "5m", Field: "bytes_in"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid collection field 'bytes_in' for criterion type 'relativeTimeRange'`)
					})
				})
				t.Run("dateRange", func(t *testing.T) {
					t.Run("gte time", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "invalid1", LTE: "2020-01-01T00:00:00Z", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value 'invalid1' for criterion type 'dateRange' gte field`)
					})
					t.Run("lte time", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "invalid2", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value 'invalid2' for criterion type 'dateRange' lte field`)
					})
					t.Run("missing field", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "2020-01-02T00:00:00Z"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, "unknown collection field name '' for criterion type 'dateRange''")
					})
					t.Run("unknown field", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "2020-01-02T00:00:00Z", Field: "unknown-field"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `unknown collection field name 'unknown-field' for criterion type 'dateRange'`)
					})
					t.Run("incorrect field type", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "2020-01-02T00:00:00Z", Field: "bytes_in"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid collection field 'bytes_in' for criterion type 'dateRange'`)
					})
					t.Run("gte is greater than lte", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2021-01-01T00:00:00Z", LTE: "2020-01-01T00:00:00Z", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value for dateRange: gte is greater than lte`)
					})
					t.Run("gte field is mandatory", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "", LTE: "", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value '' for criterion type 'dateRange' gte field`)
					})

					t.Run("parse formats", func(t *testing.T) {
						testCases := []struct {
							name     string
							value    string
							expected time.Time
						}{
							{
								name:     "date only",
								value:    "2024-01-01",
								expected: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
							},
							{
								name:     "datetime",
								value:    "2024-01-01T12:00:00",
								expected: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
							},
							{
								name:     "datetime utc",
								value:    "2024-01-01T12:00:00Z",
								expected: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
							},
							{
								name:     "datetime with timezone",
								value:    "2024-01-01T12:00:00-07:00",
								expected: time.Date(2024, 1, 1, 12, 0, 0, 0, time.FixedZone("UTC-7", -7*60*60)),
							},
							{
								name:     "datetime nanoseconds utc",
								value:    "2024-01-01T12:00:00.000000123Z",
								expected: time.Date(2024, 1, 1, 12, 0, 0, 123, time.UTC),
							},
							{
								name:     "datetime nanoseconds with timezone",
								value:    "2024-01-01T12:00:00.000000123-07:00",
								expected: time.Date(2024, 1, 1, 12, 0, 0, 123, time.FixedZone("UTC-7", -7*60*60)),
							},
						}

						for _, testCase := range testCases {
							t.Run(testCase.name, func(t *testing.T) {
								mockClient.SetResults(
									lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
								)
								_, err := subject.Query(ctx, client.QueryRequest{
									CollectionName: "flows",
									Filters: []client.QueryRequestFilter{
										{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: testCase.value, LTE: testCase.value, Field: "start_time"}},
									},
								})
								require.NoError(t, err, testCase)
								requests := mockClient.Requests()
								require.Len(t, requests, 1, testCase)
								require.IsType(t, &lsv1.FlowLogParams{}, requests[0].GetParams(), testCase)

								timeRange := requests[0].GetParams().(*lsv1.FlowLogParams).TimeRange
								require.True(t, testCase.expected.Equal(timeRange.From), testCase, timeRange.From)
								require.True(t, testCase.expected.Equal(timeRange.To), testCase, timeRange.To)
							})
						}
					})
				})
			})

			t.Run("multiple", func(t *testing.T) {
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
					},
				})
				require.ErrorContains(t, err, "multiple time range filters set")
			})

			t.Run("collectionName", func(t *testing.T) {
				t.Run("unset", func(t *testing.T) {
					_, err := subject.Query(ctx,
						client.QueryRequest{
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							},
						})
					require.ErrorContains(t, err, "unknown collection ''")
				})

				t.Run("invalid", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "unknown",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
						},
					})
					require.ErrorContains(t, err, "unknown collection 'unknown'")
				})
			})
		})

		t.Run("exists criterion", func(t *testing.T) {

			t.Run("supported for text field", func(t *testing.T) {
				mockClient.SetResults(
					lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
				)
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
						{Criterion: client.QueryRequestFilterCriterion{Type: "exists", Field: "dest_domains"}},
					},
				})
				require.NoError(t, err)
			})

			t.Run("supported for qname field", func(t *testing.T) {
				mockClient.SetResults(
					lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
				)
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "dns",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
						{Criterion: client.QueryRequestFilterCriterion{Type: "exists", Field: "qname"}},
					},
				})
				require.NoError(t, err)
			})

			t.Run("not supported for non-text field", func(t *testing.T) {
				for _, tc := range []string{
					"start_time", "bytes_in", "num_flows", "policy.type",
				} {
					t.Run(tc, func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
								{Criterion: client.QueryRequestFilterCriterion{Type: "exists", Field: tc}},
							},
						})
						require.ErrorContains(t, err, fmt.Sprintf("invalid collection field '%s' for criterion type 'exists'", tc))
					})
				}
			})
		})

		t.Run("range criterion", func(t *testing.T) {
			t.Run("invalid", func(t *testing.T) {
				t.Run("gte value", func(t *testing.T) {

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "invalid-value", LTE: "10", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "failed to parse range gte field: invalid-value")
				})

				t.Run("lte value", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "10", LTE: "invalid-value", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "failed to parse range lte field: invalid-value")
				})

				t.Run("no values set", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "invalid gte and lte values for range criterion")
				})

				t.Run("gte greater than lte", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "100", LTE: "1", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "invalid gte and lte values for range criterion")
				})
			})

			t.Run("success", func(t *testing.T) {
				t.Run("only gte field set", func(t *testing.T) {
					mockClient.SetResults(
						lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
					)

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "10", Field: "bytes_in"}},
						},
					})
					require.NoError(t, err)
				})
				t.Run("only lte field set", func(t *testing.T) {
					mockClient.SetResults(
						lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
					)

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", LTE: "10", Field: "bytes_in"}},
						},
					})
					require.NoError(t, err)
				})

				t.Run("lte and gte fields set", func(t *testing.T) {
					t.Run("to the same value", func(t *testing.T) {
						mockClient.SetResults(
							lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
						)

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
								{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "99", LTE: "100", Field: "bytes_in"}},
							},
						})
						require.NoError(t, err)
					})

					t.Run("lte greater than gte", func(t *testing.T) {
						mockClient.SetResults(
							lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
						)

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
								{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "99", LTE: "100", Field: "bytes_in"}},
							},
						})
						require.NoError(t, err)
					})
				})
			})
		})

		t.Run("maxDocs", func(t *testing.T) {

			setMockResult := func() {
				t.Helper()
				mockClient.SetResults(
					lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 11, Items: []lsv1.FlowLog{
						{ID: "flow-log1", Cluster: "cluster1"},
						{ID: "flow-log2", Cluster: "cluster1"},
						{ID: "flow-log3", Cluster: "cluster1"},
						{ID: "flow-log4", Cluster: "cluster1"},
						{ID: "flow-log5", Cluster: "cluster1"},
						{ID: "flow-log6", Cluster: "cluster1"},
						{ID: "flow-log7", Cluster: "cluster1"},
						{ID: "flow-log8", Cluster: "cluster1"},
						{ID: "flow-log9", Cluster: "cluster1"},
						{ID: "flow-log10", Cluster: "cluster1"},
						{ID: "flow-log11", Cluster: "cluster1"},
					}})},
				)
			}

			t.Run("value is honoured", func(t *testing.T) {
				setMockResult()
				resp, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        intp(2),
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, 2)

				require.Equal(t, []string{"flow-log1", "flow-log2"}, slices.Map(resp.Documents, documentToFlowLogID))
			})

			t.Run("default value", func(t *testing.T) {
				setMockResult()
				resp, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        nil,
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, MaxQueryDocumentsDefault)
			})

			t.Run("limit", func(t *testing.T) {
				mockResult := lsv1.List[lsv1.FlowLog]{TotalHits: 1000}
				for i := int64(0); i < mockResult.TotalHits; i++ {
					mockResult.Items = append(mockResult.Items, lsv1.FlowLog{ID: "flow-log" + strconv.FormatInt(i, 10)})
				}
				mockClient.SetResults(lsrest.MockResult{Body: jsonMarshal(t, mockResult)})

				resp, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        intp(1000),
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, MaxQueryDocumentsLimit)
			})
		})

		t.Run("groupBy combination", func(t *testing.T) {
			testCases := []struct {
				name     string
				valid    bool
				groupBys []client.QueryRequestGroup
			}{
				{
					name:  "invalid",
					valid: false,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "bytes_in"},
						{FieldName: "action"},
					},
				},
				{
					name:  "valid for partial group list",
					valid: true,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "source_namespace"},
						{FieldName: "source_name_aggr"},
						{FieldName: "source_name"},
					},
				},
				{
					name:  "valid for complete group list",
					valid: true,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "source_namespace"},
						{FieldName: "source_name_aggr"},
						{FieldName: "source_name"},
						{FieldName: "dest_namespace"},
						{FieldName: "dest_name_aggr"},
						{FieldName: "dest_name"},
					},
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					if testCase.valid {
						mockClient.SetResults(lsrest.MockResult{Body: nil})
					}

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
						},
						GroupBys: testCase.groupBys,
					})

					if testCase.valid {
						require.NoError(t, err)
					} else {
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid group combination`)
					}
				})
			}
		})

		t.Run("groupBy combination with backtracking", func(t *testing.T) {
			// Tests for groupBy validation backtracking behavior when multiple
			// groupBy trees share the same root field (e.g., L7 collection has
			// multiple groupBys starting with start_time)
			testCases := []struct {
				name           string
				collectionName client.CollectionName
				valid          bool
				groupBys       []client.QueryRequestGroup
			}{
				{
					// L7: Charts use start_time → gateway_route_name
					name:           "l7 charts groupBy (start_time → gateway_route_name)",
					collectionName: "l7",
					valid:          true,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "start_time"},
						{FieldName: "gateway_route_name"},
					},
				},
				{
					// L7: Traffic Performance uses start_time → gateway_namespace → gateway_name → ...
					// This requires backtracking because the first start_time groupBy
					// leads to gateway_route_name, not gateway_namespace
					name:           "l7 traffic performance groupBy (start_time → gateway_namespace → gateway_name)",
					collectionName: "l7",
					valid:          true,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "start_time"},
						{FieldName: "gateway_namespace"},
						{FieldName: "gateway_name"},
					},
				},
				{
					// L7: Full Traffic Performance path
					name:           "l7 full traffic performance groupBy path",
					collectionName: "l7",
					valid:          true,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "start_time"},
						{FieldName: "gateway_namespace"},
						{FieldName: "gateway_name"},
						{FieldName: "gateway_listener_full_name"},
						{FieldName: "gateway_route_type"},
						{FieldName: "gateway_route_namespace"},
						{FieldName: "gateway_route_name"},
						{FieldName: "dest_service_name"},
						{FieldName: "dest_port_num"},
						{FieldName: "response_code"},
					},
				},
				{
					// L7: Gateways table groupBy path
					name:           "l7 gateways table groupBy path",
					collectionName: "l7",
					valid:          true,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "gateway_namespace"},
						{FieldName: "gateway_name"},
						{FieldName: "gateway_listener_full_name"},
						{FieldName: "host"},
						{FieldName: "gateway_class"},
						{FieldName: "gateway_status"},
					},
				},
				{
					// L7: Routes table groupBy path (starts with gateway_route_type)
					name:           "l7 routes table groupBy path",
					collectionName: "l7",
					valid:          true,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "gateway_route_type"},
						{FieldName: "gateway_route_namespace"},
						{FieldName: "gateway_route_name"},
						{FieldName: "gateway_namespace"},
						{FieldName: "gateway_name"},
						{FieldName: "gateway_listener_full_name"},
						{FieldName: "dest_service_name"},
						{FieldName: "dest_port_num"},
						{FieldName: "gateway_route_status"},
					},
				},
				{
					// L7: Invalid path - start_time exists but wrong nested field
					name:           "l7 invalid path (start_time → invalid_field)",
					collectionName: "l7",
					valid:          false,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "start_time"},
						{FieldName: "invalid_field_that_does_not_exist"},
					},
				},
				{
					// L7: Invalid path - valid root but wrong continuation
					name:           "l7 invalid path (gateway_namespace → wrong nested field)",
					collectionName: "l7",
					valid:          false,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "gateway_namespace"},
						{FieldName: "response_code"}, // response_code is not nested under gateway_namespace
					},
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					if testCase.valid {
						mockClient.SetResults(lsrest.MockResult{Body: nil})
					}

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: testCase.collectionName,
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
						},
						GroupBys: testCase.groupBys,
					})

					if testCase.valid {
						require.NoError(t, err, "expected valid groupBy combination for %s", testCase.name)
					} else {
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid group combination`)
					}
				})
			}
		})
	})

	t.Run("aggregation", func(t *testing.T) {
		testCases := []struct {
			name         string
			valid        bool
			functionType client.AggregationFunctionType
		}{
			{
				name:         "valid",
				functionType: client.AggregationFunctionTypeSum,
				valid:        true,
			},
			{
				name:         "invalid",
				functionType: client.AggregationFunctionTypeAvg,
				valid:        false,
			},
			{
				name:         "valid for all",
				functionType: client.AggregationFunctionTypeCount,
				valid:        true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if tc.valid {
					mockClient.SetResults(lsrest.MockResult{Body: nil})
				}

				_, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        intp(1000),
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
					},
					Aggregations: client.QueryRequestAggregations{
						"agg0": {FieldName: "bytes_in", Function: client.QueryRequestAggregationFunction{Type: tc.functionType}},
					},
				})

				if tc.valid {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, httpreply.ToBadRequest(``))
					require.ErrorContains(t, err, `invalid aggregation function`)
				}
			})
		}
	})

	t.Run("percentile aggregation mapping", func(t *testing.T) {
		testCases := []struct {
			functionType       string
			expectedPercentile float64
		}{
			{functionType: "p50", expectedPercentile: 50},
			{functionType: "p90", expectedPercentile: 90},
			{functionType: "p95", expectedPercentile: 95},
			{functionType: "p100", expectedPercentile: 100},
		}

		queryCollection, found := slices.Find(allCollections, func(collection collections.Collection) bool {
			return collection.Name() == "flows"
		})
		require.True(t, found)

		for _, tc := range testCases {
			t.Run(tc.functionType, func(t *testing.T) {
				agg, err := mapClientAggregation("agg0", client.QueryRequestAggregation{
					FieldName: "tcp_max_min_rtt",
					Function: client.QueryRequestAggregationFunction{
						Type: client.AggregationFunctionType(tc.functionType),
					},
				}, queryCollection)
				require.NoError(t, err)

				pct, ok := agg.(aggregations.AggregationPercentile)
				require.True(t, ok)

				require.Equal(t, tc.expectedPercentile, pct.Percentile())
			})
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Run("single-tenant", func(t *testing.T) {
			t.Run("query", func(t *testing.T) {
				mockClient.SetResults(
					lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 5, Items: []lsv1.FlowLog{
						{ID: "flow-log1", Cluster: "cluster1"},
						{ID: "flow-log2", Cluster: "cluster1"},
						{ID: "flow-log3", Cluster: "cluster1"},
						{ID: "flow-log4", Cluster: "cluster2"},
						{ID: "flow-log5", Cluster: "cluster2"},
					}})},
				)

				expectedFlowLogsIDs := []string{"flow-log1", "flow-log2", "flow-log3", "flow-log4", "flow-log5"}

				resp, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, 5)
				require.Equal(t, client.QueryResponseTotals{Value: 5}, resp.Totals)
				require.Empty(t, resp.GroupValues)
				require.Empty(t, resp.Aggregations)

				require.Equal(t, expectedFlowLogsIDs, slices.Map(resp.Documents, documentToFlowLogID))
			})

			t.Run("result", func(t *testing.T) {
				t.Run("groups", func(t *testing.T) {
					t.Run("max values", func(t *testing.T) {
						t.Run("discrete group", func(t *testing.T) {

							groupResults := []bucketItems{
								{
									Buckets: []bucketItem{
										{"key": "1"}, {"key": "2"}, {"key": "3"}, {"key": "4"},
										{"key": "5"}, {"key": "6"}, {"key": "7"}, {"key": "8"},
										{"key": "9"}, {"key": "10"}, {"key": "11"}, {"key": "12"},
									},
								},
								{
									Buckets: []bucketItem{
										{"key": "13"}, {"key": "14"}, {"key": "15"}, {"key": "16"},
									},
								},
							}

							t.Run("defaults to 10", func(t *testing.T) {
								// see defaultMaxValue in cc-dashboard-query-api/pkg/internal/domain/groups/group_discrete.go

								mockClient.SetResults(
									lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[0]),
									})},
									lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[1]),
									})},
								)

								resp, err := subject.Query(ctx, client.QueryRequest{
									CollectionName: "flows",
									Filters: []client.QueryRequestFilter{
										{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
									},
									GroupBys: []client.QueryRequestGroup{
										{FieldName: "dest_namespace", MaxValues: 0},
									},
								})

								require.NoError(t, err)
								require.Empty(t, resp.Aggregations)

								require.Len(t, resp.GroupValues, 10)
							})

							mockClient.SetResults(
								lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[0]),
								})},
								lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[1]),
								})},
							)

							resp, err := subject.Query(ctx, client.QueryRequest{
								CollectionName: "flows",
								Filters: []client.QueryRequestFilter{
									{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
								},
								GroupBys: []client.QueryRequestGroup{
									{FieldName: "dest_namespace", MaxValues: 11},
								},
							})

							require.NoError(t, err)
							require.Empty(t, resp.Aggregations)

							require.Len(t, resp.GroupValues, 11)
						})

						t.Run("time group", func(t *testing.T) {

							t.Run("no defaults", func(t *testing.T) {
								// Note that time group requests are limited in the elastic request by
								// maxGroupTimeAggregationResults

								groupResults := make([]bucketItems, 2)

								for i := range 1000 {
									strIndex := strconv.FormatInt(int64(i), 10)
									groupResults[0].Buckets = append(groupResults[0].Buckets, bucketItem{"key_as_string": "gbi-0-" + strIndex})
									groupResults[1].Buckets = append(groupResults[1].Buckets, bucketItem{"key_as_string": "gbi-1-" + strIndex})
								}

								mockClient.SetResults(
									lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[0]),
									})},
									lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[1]),
									})},
								)

								resp, err := subject.Query(ctx, client.QueryRequest{
									CollectionName: "flows",
									Filters: []client.QueryRequestFilter{
										{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
									},
									GroupBys: []client.QueryRequestGroup{
										{FieldName: "start_time"},
									},
								})

								require.NoError(t, err)
								require.Empty(t, resp.Aggregations)
								require.Len(t, resp.GroupValues, 1000)
							})

							groupResults := []bucketItems{
								{
									Buckets: []bucketItem{
										{"key_as_string": "1500"},
										{"key_as_string": "1600"},
										{"key_as_string": "1150"},
										{"key_as_string": "1800"},
									},
								},
								{
									Buckets: []bucketItem{
										{"key_as_string": "1400"},
										{"key_as_string": "1200"},
										{"key_as_string": "1900"},
									},
								},
								{
									Buckets: []bucketItem{
										{"key_as_string": "1300"},
										{"key_as_string": "1950"},
									},
								},
							}

							mockClient.SetResults(
								lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[0]),
								})},
								lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[1]),
								})},
								lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[2]),
								})},
							)

							// Create a query service with 3 managed clusters
							subject := NewQueryService(
								logger,
								repository,
								allCollections,
								managedclusters.NameListerFunc(func(ctx context.Context) ([]query.ManagedClusterName, error) {
									return []query.ManagedClusterName{"cluster1", "cluster2", "cluster3"}, nil
								}),
								Config{
									QueryTimeout:           time.Duration(2) * time.Minute,
									MaxRequestFilters:      10,
									MaxRequestAggregations: 5,
								},
							)

							resp, err := subject.Query(ctx, client.QueryRequest{
								CollectionName: "flows",
								ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2", "cluster3"},
								Filters: []client.QueryRequestFilter{
									{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
								},
								GroupBys: []client.QueryRequestGroup{
									{FieldName: "start_time", MaxValues: 3},
								},
							})
							require.NoError(t, err)
							require.Empty(t, resp.Aggregations)

							require.Equal(t, []client.QueryResponseGroupValue{
								{Key: "1500", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1600", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1150", Aggregations: client.QueryResponseAggregations{}},
							}, resp.GroupValues)
						})
					})
				})

				t.Run("count aggregation with no groups", func(t *testing.T) {
					subject := NewQueryService(
						logger,
						repository,
						allCollections,
						managedClusterLister,
						Config{
							QueryTimeout:           time.Duration(2) * time.Minute,
							MaxRequestFilters:      10,
							MaxRequestAggregations: 5,
						},
					)

					mockClient.SetResults(
						lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 3, Items: []lsv1.FlowLog{
							{ID: "flow-log1"},
							{ID: "flow-log2"},
							{ID: "flow-log3"},
						}})},
					)

					resp, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						MaxDocs:        intp(0),
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
						},
						Aggregations: client.QueryRequestAggregations{
							"a-count-aggregation": {
								FieldName: "_count",
								Function: client.QueryRequestAggregationFunction{
									Type: client.AggregationFunctionTypeCount,
								},
							},
						},
					})

					require.NoError(t, err)
					require.Empty(t, resp.Documents)
					require.Equal(t, client.QueryResponseTotals{Value: 3}, resp.Totals)
					require.Empty(t, resp.GroupValues)
					require.Equal(t, client.QueryResponseAggregations{
						"a-count-aggregation": {AsString: "3"},
					}, resp.Aggregations)
				})

				t.Run("time range fields", func(t *testing.T) {
					queryWithFilter := func(t *testing.T, filter client.QueryRequestFilter) *lsv1.FlowLogParams {
						t.Helper()
						subject := NewQueryService(
							logger,
							repository,
							allCollections,
							managedClusterLister,
							Config{
								QueryTimeout:           time.Duration(2) * time.Minute,
								MaxRequestFilters:      10,
								MaxRequestAggregations: 5,
							},
						)

						mockClient.SetResults(
							lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 0, Items: []lsv1.FlowLog{}})},
						)

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							MaxDocs:        intp(0),
							Filters: []client.QueryRequestFilter{
								filter,
							},
							Aggregations: client.QueryRequestAggregations{
								"a-count-aggregation": {
									FieldName: "_count",
									Function: client.QueryRequestAggregationFunction{
										Type: client.AggregationFunctionTypeCount,
									},
								},
							},
						})
						require.NoError(t, err)
						requests := mockClient.Requests()
						require.Len(t, requests, 1)
						params, ok := requests[0].GetParams().(*lsv1.FlowLogParams)
						require.True(t, ok, "expected params type to be *lsv1.FlowLogParams, but it was %T", requests[0].GetParams())
						return params
					}

					t.Run("relativeTimeRange", func(t *testing.T) {
						params := queryWithFilter(t, client.QueryRequestFilter{
							Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"},
						})
						require.Equal(t, lmav1.FieldStartTime, params.TimeRange.Field)
					})

					t.Run("dateRange", func(t *testing.T) {
						params := queryWithFilter(t, client.QueryRequestFilter{
							Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "2020-01-02T00:00:00Z", Field: "end_time"},
						})
						require.Empty(t, params.TimeRange.Field)
					})
				})

				t.Run("json unmarshal", func(t *testing.T) {
					subject := NewQueryService(
						logger,
						repository,
						allCollections,
						managedClusterLister,
						Config{
							QueryTimeout:           time.Duration(2) * time.Minute,
							MaxRequestFilters:      10,
							MaxRequestAggregations: 5,
						},
					)

					dnsName := lsv1.DNSName{
						Name:  "test-name.svc.cluster.local",
						Class: 1,
						Type:  1,
					}
					mockClient.SetResults(
						lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.DNSLog]{TotalHits: 1, Items: []lsv1.DNSLog{
							{ID: "dns-log1", RRSets: lsv1.DNSRRSets{dnsName: lsv1.DNSRDatas{{Decoded: net.ParseIP("127.0.0.1")}}}},
						}})},
					)

					resp, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "dns",
						MaxDocs:        intp(10),
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
						},
					})

					require.NoError(t, err)
					require.Len(t, resp.Documents, 1)
					require.Contains(t, resp.Documents[0], "rrsets")
					require.Equal(t, []any{
						map[string]any{"class": "IN", "name": "test-name.svc.cluster.local", "type": "A", "rdata": []any{"127.0.0.1"}},
					}, resp.Documents[0]["rrsets"])
				})
			})
		})

		t.Run("multi-tenant", func(t *testing.T) {
			subject := NewQueryService(
				logger,
				repository,
				allCollections,
				managedClusterLister,
				Config{
					QueryTimeout:           time.Duration(2) * time.Minute,
					MaxRequestFilters:      10,
					MaxRequestAggregations: 5,
				},
			)

			mockClient.SetResults(
				lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 5, Items: []lsv1.FlowLog{
					{ID: "flow-log1", Cluster: "cluster1"},
					{ID: "flow-log2", Cluster: "cluster1"},
					{ID: "flow-log3", Cluster: "cluster1"},
					{ID: "flow-log4", Cluster: "cluster2"},
					{ID: "flow-log5", Cluster: "cluster2"},
				}})},
			)

			expectedFlowLogsIDs := []string{"flow-log1", "flow-log2", "flow-log3", "flow-log4", "flow-log5"}

			resp, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
				},
			})

			require.NoError(t, err)
			require.Len(t, resp.Documents, 5)
			require.Equal(t, client.QueryResponseTotals{Value: 5}, resp.Totals)
			require.Empty(t, resp.GroupValues)
			require.Empty(t, resp.Aggregations)

			require.Equal(t, expectedFlowLogsIDs, slices.Map(resp.Documents, documentToFlowLogID))
		})
	})

	t.Run("mapping", func(t *testing.T) {
		t.Run("client criterion or", func(t *testing.T) {
			collection, found := slices.Find(allCollections, func(c collections.Collection) bool { return c.Name() == "flows" })
			require.True(t, found)

			testCases := []struct {
				name    string
				negated bool
			}{
				{name: "not negated", negated: false},
				{name: "negated", negated: true},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					filterCriterion, err := subject.mapClientCriterion(ctx, client.QueryRequestFilterCriterion{
						Type: client.CriterionTypeOr,
						Criteria: []client.QueryRequestFilterCriterion{
							{Type: client.CriterionTypeEquals, Field: "source_namespace", Value: client.NewQueryRequestFilterCriterionValue("fake-namespace1")},
							{Type: client.CriterionTypeEquals, Field: "source_namespace", Value: client.NewQueryRequestFilterCriterionValue("fake-namespace2")},
						},
					}, tc.negated, collection)
					require.NoError(t, err)

					filterCriterionOr, ok := filterCriterion.(*filters.CriterionOr)
					require.True(t, ok)
					require.Equal(t, tc.negated, filterCriterionOr.Negate())

					subCriteria := filterCriterionOr.SubCriteria()
					require.Len(t, subCriteria, 2)
					require.False(t, subCriteria[0].Negate())
					require.False(t, subCriteria[1].Negate())
				})
			}
		})
	})
}

func documentToFlowLogID(d client.QueryResponseDocument) string {
	return d["id"].(string)
}

func jsonMarshal(t *testing.T, v any) []byte {
	t.Helper()

	bytes, err := json.Marshal(v)
	require.NoError(t, err)

	return bytes
}

func intp(i int) *int {
	return &i
}

func TestQueryService_Query_ExportLimit(t *testing.T) {
	logger := logging.New("TestQueryService_Query_ExportLimit")

	mockRepo := fakerepository.NewFakeRepository()
	mockLister := managedclusters.NameListerFunc(func(ctx context.Context) ([]query.ManagedClusterName, error) {
		return []query.ManagedClusterName{"cluster1"}, nil
	})

	svc := NewQueryService(logger, mockRepo, collections.Collections(nil), mockLister, Config{
		QueryTimeout:      time.Second,
		MaxRequestFilters: 10,
	})

	ctx := newAuthContext(t, logger, false, nil, newLMAResource("get", "*"))

	// Test normal query limit
	req := client.QueryRequest{
		CollectionName: "flows",
		MaxDocs:        intp(20000),
		Filters: []client.QueryRequestFilter{
			{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
		},
	}

	_, err := svc.Query(ctx, req)
	require.NoError(t, err)

	queries := mockRepo.Queries()
	require.Len(t, queries, 1)
	require.Equal(t, 500, queries[0].MaxDocuments)

	// Test export query limit
	reqExport := client.QueryRequest{
		CollectionName: "flows",
		MaxDocs:        intp(20000),
		IsExport:       true,
		Filters: []client.QueryRequestFilter{
			{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
		},
	}

	_, err = svc.Query(ctx, reqExport)
	require.NoError(t, err)

	queries = mockRepo.Queries()
	require.Len(t, queries, 2)
	require.Equal(t, 10000, queries[1].MaxDocuments)
}
