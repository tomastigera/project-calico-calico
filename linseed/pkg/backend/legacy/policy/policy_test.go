package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

type mockIndexInitializer struct {
	InitializeFunc func(ctx context.Context, idx bapi.Index, info bapi.ClusterInfo) error
}

func (m *mockIndexInitializer) Initialize(ctx context.Context, idx bapi.Index, info bapi.ClusterInfo) error {
	if m.InitializeFunc != nil {
		return m.InitializeFunc(ctx, idx, info)
	}
	return nil
}

type mockLMAClient struct {
	lmaelastic.Client
	esClient *elastic.Client
}

func (m *mockLMAClient) Backend() *elastic.Client {
	return m.esClient
}

func (m *mockLMAClient) CleanUp() {}

func (m *mockLMAClient) ClusterIndex(cluster, suffix string) string {
	return fmt.Sprintf("%s.%s", cluster, suffix)
}

func (m *mockLMAClient) ClusterAlias(cluster string) string {
	return fmt.Sprintf(".%s", cluster)
}

func (m *mockLMAClient) IndexTemplateName(index string) string {
	return fmt.Sprintf("template.%s", index)
}

func (m *mockLMAClient) Do(ctx context.Context, s *elastic.SearchService) (*elastic.SearchResult, error) {
	// Pass through to the real ES client service logic.
	return s.Do(ctx)
}

func (m *mockLMAClient) SearchCompositeAggregations(
	ctx context.Context,
	q *lmaelastic.CompositeAggregationQuery,
	key lmaelastic.CompositeAggregationKey,
) (<-chan *lmaelastic.CompositeAggregationBucket, <-chan error) {

	buckets := make(chan *lmaelastic.CompositeAggregationBucket)
	errs := make(chan error)

	// Close them immediately to simulate an empty result set (stops tests from hanging).
	close(buckets)
	close(errs)

	return buckets, errs
}

func setupBackendWithHandler(t *testing.T, handlerFunc http.HandlerFunc, singleIndex bool) (*policyBackend, *httptest.Server) {
	ts := httptest.NewServer(handlerFunc)

	client, err := elastic.NewClient(
		elastic.SetURL(ts.URL),
		elastic.SetSniff(false),
		elastic.SetHealthcheck(false),
	)
	require.NoError(t, err)

	lmaClient := &mockLMAClient{esClient: client}
	mockInit := &mockIndexInitializer{}

	var b bapi.PolicyBackend
	if singleIndex {
		b = NewSingleIndexBackend(lmaClient, mockInit, 10*time.Minute, 2*time.Hour)
	} else {
		b = NewBackend(lmaClient, mockInit, 10*time.Minute, 2*time.Hour)
	}

	pb := b.(*policyBackend)
	pb.dedupWindow = 1 * time.Hour

	return pb, ts
}

func TestGenDeterministicID(t *testing.T) {
	id1 := genDeterministicID(v1.PolicyInfo{Kind: "kind", Namespace: "ns", Name: "name"}, "cluster", "tenant", "rule")
	id2 := genDeterministicID(v1.PolicyInfo{Kind: "kind", Namespace: "ns", Name: "name"}, "cluster", "tenant", "rule")
	id3 := genDeterministicID(v1.PolicyInfo{Kind: "kind", Namespace: "ns", Name: "other"}, "cluster", "tenant", "rule")

	assert.Equal(t, id1, id2, "IDs for same input should match")
	assert.NotEqual(t, id1, id3, "IDs for different input should differ")
	assert.NotEmpty(t, id1)
}

func TestPrepareForWrite(t *testing.T) {
	// Single Index Mode
	pbSingle, _ := setupBackendWithHandler(t, nil, true)
	info := bapi.ClusterInfo{Cluster: "c1", Tenant: "t1"}
	log := v1.PolicyActivity{Rule: "r1"}

	resSingle := pbSingle.prepareForWrite(info, log)
	lwe, ok := resSingle.(*logWithExtras)
	require.True(t, ok)
	assert.Equal(t, "c1", lwe.Cluster)
	assert.Equal(t, "t1", lwe.Tenant)

	// Multi Index Mode
	pbMulti, _ := setupBackendWithHandler(t, nil, false)
	resMulti := pbMulti.prepareForWrite(info, log)
	lOrig, ok := resMulti.(v1.PolicyActivity)
	require.True(t, ok)
	assert.Equal(t, "c1", lOrig.Cluster)
}

func TestCreate_FullFlow(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/_mget" {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, `{"docs": [{"found": false}, {"found": false}]}`)
			return
		}

		if r.Method == "POST" && r.URL.Path == "/_bulk" {
			body, _ := io.ReadAll(r.Body)
			assert.Contains(t, string(body), "index")

			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, `{
				"took": 1,
				"errors": false,
				"items": [
					{"index": {"_id": "1", "result": "created", "status": 201}},
					{"index": {"_id": "2", "result": "created", "status": 201}}
				]
			}`)
			return
		}
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}

	b, ts := setupBackendWithHandler(t, handler, false)
	defer ts.Close()

	logs := []v1.PolicyActivity{
		{Policy: v1.PolicyInfo{Name: "p1"}, Rule: "r1", LastEvaluated: time.Now()},
		{Policy: v1.PolicyInfo{Name: "p2"}, Rule: "r2", LastEvaluated: time.Now()},
	}
	info := bapi.ClusterInfo{Cluster: "test-cluster"}

	resp, err := b.Create(context.Background(), info, logs)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Succeeded)
	assert.Equal(t, 0, resp.Failed)

	count := 0
	b.policyActivityCache.Range(func(key, value any) bool {
		count++
		return true
	})
	assert.Equal(t, 2, count, "Cache should have 2 entries")
}

func TestCreate_Deduplication(t *testing.T) {
	logItem := v1.PolicyActivity{Policy: v1.PolicyInfo{Name: "p1"}, Rule: "r1", LastEvaluated: time.Now()}
	info := bapi.ClusterInfo{Cluster: "c1", Tenant: "t1"}

	expectedID := genDeterministicID(logItem.Policy, info.Cluster, info.Tenant, logItem.Rule)

	esHits := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		esHits++
		if r.URL.Path == "/_mget" {
			_, _ = fmt.Fprintln(w, `{"docs": [{"found": false}]}`)
			return
		}
		if r.URL.Path == "/_bulk" {
			resp := fmt.Sprintf(`{"took": 1, "errors": false, "items": [{"index": {"_id": "%s", "result": "created", "status": 201}}]}`, expectedID)
			_, _ = fmt.Fprintln(w, resp)
			return
		}
	}

	b, ts := setupBackendWithHandler(t, handler, false)
	defer ts.Close()

	_, err := b.Create(context.Background(), info, []v1.PolicyActivity{logItem})
	require.NoError(t, err)
	assert.Greater(t, esHits, 0, "First write should hit ES")

	// Reset counter
	esHits = 0

	resp, err := b.Create(context.Background(), info, []v1.PolicyActivity{logItem})
	require.NoError(t, err)
	assert.Equal(t, 0, esHits, "Second immediate write should NOT hit ES due to cache")
	assert.Equal(t, 1, resp.Succeeded)

	// Manually expire the cache entry
	b.policyActivityCache.Store(expectedID, time.Now().Add(-2*time.Hour))

	esHits = 0
	_, err = b.Create(context.Background(), info, []v1.PolicyActivity{logItem})
	require.NoError(t, err)
	assert.Greater(t, esHits, 0, "Write after window expiry should hit ES")
}

func TestGetPolicyActivity_FullFlow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	earlier := now.Add(-1 * time.Hour)

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		// Verify the query contains expected terms.
		assert.Contains(t, bodyStr, "policy.kind")
		assert.Contains(t, bodyStr, "NetworkPolicy")
		assert.Contains(t, bodyStr, "policy.name")
		assert.Contains(t, bodyStr, "allow-dns")
		assert.Contains(t, bodyStr, "prefix")
		assert.Contains(t, bodyStr, "3|") // generation prefix

		// Return two docs for the same policy with different rules.
		response := fmt.Sprintf(`{
			"hits": {
				"total": { "value": 2, "relation": "eq" },
				"hits": [
					{
						"_id": "1",
						"_source": {
							"policy": {"kind": "NetworkPolicy", "namespace": "default", "name": "allow-dns"},
							"rule": "3|ingress|0",
							"last_evaluated": %q
						}
					},
					{
						"_id": "2",
						"_source": {
							"policy": {"kind": "NetworkPolicy", "namespace": "default", "name": "allow-dns"},
							"rule": "3|egress|1",
							"last_evaluated": %q
						}
					}
				]
			}
		}`, now.Format(time.RFC3339Nano), earlier.Format(time.RFC3339Nano))
		_, _ = fmt.Fprint(w, response)
	}

	b, ts := setupBackendWithHandler(t, handler, false)
	defer ts.Close()

	req := &v1.PolicyActivityRequest{
		Policies: []v1.PolicyActivityQueryPolicy{
			{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-dns", Generation: 3},
		},
	}
	info := bapi.ClusterInfo{Cluster: "c1"}

	resp, err := b.GetPolicyActivity(context.Background(), info, req)
	require.NoError(t, err)
	require.Len(t, resp.Items, 1)

	item := resp.Items[0]
	assert.Equal(t, "NetworkPolicy", item.Policy.Kind)
	assert.Equal(t, "default", item.Policy.Namespace)
	assert.Equal(t, "allow-dns", item.Policy.Name)
	assert.NotNil(t, item.LastEvaluated)
	assert.Equal(t, now, *item.LastEvaluated) // max of now and earlier
	assert.Len(t, item.Rules, 2)

	// Verify rule parsing.
	assert.Equal(t, "ingress", item.Rules[0].Direction)
	assert.Equal(t, "0", item.Rules[0].Index)
	assert.Equal(t, now, item.Rules[0].LastEvaluated)

	assert.Equal(t, "egress", item.Rules[1].Direction)
	assert.Equal(t, "1", item.Rules[1].Index)
	assert.Equal(t, earlier, item.Rules[1].LastEvaluated)
}

func TestGetPolicyActivity_EmptyPolicies(t *testing.T) {
	b, ts := setupBackendWithHandler(t, nil, false)
	defer ts.Close()

	req := &v1.PolicyActivityRequest{Policies: []v1.PolicyActivityQueryPolicy{}}
	info := bapi.ClusterInfo{Cluster: "c1"}

	resp, err := b.GetPolicyActivity(context.Background(), info, req)
	require.NoError(t, err)
	assert.Empty(t, resp.Items)
}

func TestGetPolicyActivity_ESError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "ES unavailable", http.StatusServiceUnavailable)
	}

	b, ts := setupBackendWithHandler(t, handler, false)
	defer ts.Close()

	req := &v1.PolicyActivityRequest{
		Policies: []v1.PolicyActivityQueryPolicy{
			{Kind: "NetworkPolicy", Name: "p1", Generation: 1},
		},
	}
	info := bapi.ClusterInfo{Cluster: "c1"}

	_, err := b.GetPolicyActivity(context.Background(), info, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "elasticsearch search failed")
}

func TestGetPolicyActivity_MultiplePolicies(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	handler := func(w http.ResponseWriter, r *http.Request) {
		response := fmt.Sprintf(`{
			"hits": {
				"total": { "value": 2, "relation": "eq" },
				"hits": [
					{
						"_id": "1",
						"_source": {
							"policy": {"kind": "NetworkPolicy", "namespace": "ns1", "name": "p1"},
							"rule": "1|ingress|0",
							"last_evaluated": %q
						}
					},
					{
						"_id": "2",
						"_source": {
							"policy": {"kind": "GlobalNetworkPolicy", "namespace": "", "name": "gnp1"},
							"rule": "2|egress|0",
							"last_evaluated": %q
						}
					}
				]
			}
		}`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		_, _ = fmt.Fprint(w, response)
	}

	b, ts := setupBackendWithHandler(t, handler, false)
	defer ts.Close()

	req := &v1.PolicyActivityRequest{
		Policies: []v1.PolicyActivityQueryPolicy{
			{Kind: "GlobalNetworkPolicy", Name: "gnp1", Generation: 2},
			{Kind: "NetworkPolicy", Namespace: "ns1", Name: "p1", Generation: 1},
		},
	}
	info := bapi.ClusterInfo{Cluster: "c1"}

	resp, err := b.GetPolicyActivity(context.Background(), info, req)
	require.NoError(t, err)
	require.Len(t, resp.Items, 2)

	// Verify results are in request order.
	assert.Equal(t, "gnp1", resp.Items[0].Policy.Name)
	assert.Equal(t, "p1", resp.Items[1].Policy.Name)
}

func TestGetPolicyActivity_SkipsUnparsableRules(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	handler := func(w http.ResponseWriter, r *http.Request) {
		response := fmt.Sprintf(`{
			"hits": {
				"total": { "value": 2, "relation": "eq" },
				"hits": [
					{
						"_id": "1",
						"_source": {
							"policy": {"kind": "NetworkPolicy", "namespace": "ns", "name": "p1"},
							"rule": "bad-format",
							"last_evaluated": %q
						}
					},
					{
						"_id": "2",
						"_source": {
							"policy": {"kind": "NetworkPolicy", "namespace": "ns", "name": "p1"},
							"rule": "1|ingress|0",
							"last_evaluated": %q
						}
					}
				]
			}
		}`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		_, _ = fmt.Fprint(w, response)
	}

	b, ts := setupBackendWithHandler(t, handler, false)
	defer ts.Close()

	req := &v1.PolicyActivityRequest{
		Policies: []v1.PolicyActivityQueryPolicy{
			{Kind: "NetworkPolicy", Namespace: "ns", Name: "p1", Generation: 1},
		},
	}
	info := bapi.ClusterInfo{Cluster: "c1"}

	resp, err := b.GetPolicyActivity(context.Background(), info, req)
	require.NoError(t, err)
	require.Len(t, resp.Items, 1)
	assert.Len(t, resp.Items[0].Rules, 1) // Only the valid rule
	assert.Equal(t, "ingress", resp.Items[0].Rules[0].Direction)
}

func TestBuildPolicyActivityQuery_WithTimeRange(t *testing.T) {
	b, ts := setupBackendWithHandler(t, nil, false)
	defer ts.Close()

	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	req := &v1.PolicyActivityRequest{
		From: &from,
		To:   &to,
		Policies: []v1.PolicyActivityQueryPolicy{
			{Kind: "NetworkPolicy", Name: "p1", Generation: 1},
		},
	}
	info := bapi.ClusterInfo{Cluster: "c1"}

	q := b.buildPolicyActivityQuery(info, req)
	src, err := q.Source()
	require.NoError(t, err)

	jsonBytes, _ := json.Marshal(src)
	jsonStr := string(jsonBytes)

	assert.Contains(t, jsonStr, "last_evaluated")
	assert.Contains(t, jsonStr, "from")
	assert.Contains(t, jsonStr, "to")
}

func TestBuildPolicyActivityQuery_SingleIndex(t *testing.T) {
	b, ts := setupBackendWithHandler(t, nil, true)
	defer ts.Close()

	req := &v1.PolicyActivityRequest{
		Policies: []v1.PolicyActivityQueryPolicy{
			{Kind: "NetworkPolicy", Namespace: "ns1", Name: "p1", Generation: 5},
		},
	}
	info := bapi.ClusterInfo{Cluster: "c1", Tenant: "t1"}

	q := b.buildPolicyActivityQuery(info, req)
	src, err := q.Source()
	require.NoError(t, err)

	jsonBytes, _ := json.Marshal(src)
	jsonStr := string(jsonBytes)

	// Should include cluster and tenant filters in single-index mode.
	assert.Contains(t, jsonStr, `"cluster"`)
	assert.Contains(t, jsonStr, "c1")
	assert.Contains(t, jsonStr, `"tenant"`)
	assert.Contains(t, jsonStr, "t1")
	// Should include generation prefix.
	assert.Contains(t, jsonStr, "5|")
}

func TestGetPolicyActivity_InvalidCluster(t *testing.T) {
	b, ts := setupBackendWithHandler(t, nil, false)
	defer ts.Close()

	req := &v1.PolicyActivityRequest{
		Policies: []v1.PolicyActivityQueryPolicy{
			{Kind: "NetworkPolicy", Name: "p1", Generation: 1},
		},
	}
	info := bapi.ClusterInfo{Cluster: ""} // Invalid - empty cluster

	_, err := b.GetPolicyActivity(context.Background(), info, req)
	assert.Error(t, err)
}
