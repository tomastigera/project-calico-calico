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
		b = NewSingleIndexBackend(lmaClient, mockInit, 1000, false, 10*time.Minute, 2*time.Hour)
	} else {
		b = NewBackend(lmaClient, mockInit, 1000, false, 10*time.Minute, 2*time.Hour)
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

func TestList_Integration(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		assert.Contains(t, bodyStr, "term")
		assert.Contains(t, bodyStr, "policy.name")
		assert.Contains(t, bodyStr, "test-policy")

		// Return Mock Hits
		response := `{
            "hits": {
                "total": { "value": 1, "relation": "eq" },
                "hits": [
                    { "_id": "123", "_source": { "rule": "allow-all" }, "sort": [12345] }
                ]
            }
        }`
		_, _ = fmt.Fprint(w, response)
	}

	b, ts := setupBackendWithHandler(t, handler, false)
	defer ts.Close()

	params := &v1.PolicyActivityParams{
		Policy: v1.PolicyInfo{Name: "test-policy"},
	}
	info := bapi.ClusterInfo{Cluster: "c1"}

	list, err := b.List(context.Background(), info, params)
	require.NoError(t, err)
	assert.Equal(t, int64(1), list.TotalHits)
	assert.Equal(t, "123", list.Items[0].ID)
}

func TestList_ElasticError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "ES unavailable", http.StatusServiceUnavailable)
	}
	b, ts := setupBackendWithHandler(t, handler, false)
	defer ts.Close()

	_, err := b.List(context.Background(), bapi.ClusterInfo{Cluster: "c1"}, &v1.PolicyActivityParams{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "elasticsearch search failed")
}

func TestBuildQuery_Complex(t *testing.T) {
	b, ts := setupBackendWithHandler(t, nil, false)
	defer ts.Close()

	now := time.Now()
	opts := &v1.PolicyActivityParams{
		Selector:      "\"policy.namespace\" = 'frontend'",
		Rules:         []string{"r1", "r2"},
		Policy:        v1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: "gnp1"},
		LastEvaluated: now,
	}

	q, err := b.buildQuery(bapi.ClusterInfo{Cluster: "c1"}, opts)
	require.NoError(t, err)

	src, err := q.Source()
	require.NoError(t, err)

	jsonBytes, _ := json.Marshal(src)
	jsonStr := string(jsonBytes)

	assert.Contains(t, jsonStr, "frontend")
	assert.Contains(t, jsonStr, "policy.namespace")
	assert.Contains(t, jsonStr, "r1")
	assert.Contains(t, jsonStr, "gnp1")
}

func TestList_UnmarshalError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		// We send valid JSON structure but the content inside _source makes Unmarshal fail
		// if we were strictly checking types, but standard json.Unmarshal usually tolerates extra fields.
		// To force an unmarshal error on the struct, we send a type mismatch.
		responseMismatch := `{
			"hits": {
				"hits": [ { "_source": "this_should_be_an_object_but_is_string" } ]
			}
		}`
		_, _ = fmt.Fprint(w, responseMismatch)
	}

	b, ts := setupBackendWithHandler(t, handler, false)
	defer ts.Close()

	list, err := b.List(context.Background(), bapi.ClusterInfo{Cluster: "c1"}, &v1.PolicyActivityParams{})

	// The code logs the error and continues, effectively returning empty list.
	require.NoError(t, err) // It doesn't return error, it just skips the item.
	assert.Equal(t, 0, len(list.Items))
}
