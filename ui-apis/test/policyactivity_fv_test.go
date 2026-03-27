// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package fv_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/olivere/elastic/v7"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"k8s.io/utils/ptr"

	linseedv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lsrest "github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
	k8s "github.com/projectcalico/calico/lma/pkg/k8s"
	uiapi "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
)

func newFVPolicyActivityPOST(req uiapi.PolicyActivityRequest) *http.Request {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/policies/activities", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// expectedFVResponseJSON marshals a PolicyActivityResponse to JSON for use with MatchJSON.
func expectedFVResponseJSON(items []uiapi.PolicyActivityItem) []byte {
	b, err := json.Marshal(uiapi.PolicyActivityResponse{Items: items})
	Expect(err).NotTo(HaveOccurred())
	return b
}

// expectPolicyActivityDocs verifies that the expected number of documents for a
// given policy actually landed in Elasticsearch.  This catches silent no-ops
// from Linseed's dedup cache, which returns Succeeded: N without writing.
func expectPolicyActivityDocs(ctx context.Context, esClient *elastic.Client, idx bapi.Index, clusterInfo bapi.ClusterInfo, kind, name string, expected int64) {
	count, err := esClient.Count(idx.Index(clusterInfo)).
		Query(elastic.NewBoolQuery().Must(
			elastic.NewTermQuery("cluster", clusterInfo.Cluster),
			elastic.NewTermQuery("tenant", clusterInfo.Tenant),
			elastic.NewTermQuery("policy.kind", kind),
			elastic.NewTermQuery("policy.name", name),
		)).
		Do(ctx)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "ES count query failed")
	ExpectWithOffset(1, count).To(Equal(expected), "unexpected ES doc count for policy %s/%s", kind, name)
}

var policyActivityTestSeq int64

var _ = Describe("PolicyActivity FV", func() {
	var (
		linseedCli  lsclient.Client
		esClient    *elastic.Client
		lmaClient   lmaelastic.Client
		handler     http.Handler
		clusterInfo bapi.ClusterInfo
		idx         bapi.Index
		ctx         context.Context
		cancel      context.CancelFunc
		// testID ensures unique policy names per test.  Linseed's policy-activity
		// backend deduplicates writes using an in-memory cache keyed by a
		// deterministic doc ID (policy+rule+cluster+tenant).  The cache has a 1-hour
		// window, so reusing the same policy names across tests — or across repeated
		// ginkgo runs against the same Linseed container — causes Create to
		// short-circuit and return success without writing to ES.
		testID string
	)

	BeforeEach(func() {
		var err error

		policyActivityTestSeq++
		testID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), policyActivityTestSeq)

		By("Connecting to Elasticsearch")
		esClient, err = elastic.NewSimpleClient(
			elastic.SetURL("http://localhost:9200"),
			elastic.SetInfoLog(logrus.StandardLogger()),
		)
		Expect(err).NotTo(HaveOccurred(), "Failed to connect to Elasticsearch")
		lmaClient = lmaelastic.NewWithClient(esClient)

		By("Configuring Linseed connection")
		linseedPort := 8444
		linseedTenantId := "tenant-a"
		clusterInfo = bapi.ClusterInfo{Cluster: k8s.DefaultCluster, Tenant: linseedTenantId}

		cfg := lsrest.Config{
			CACertPath:     "../../linseed/fv/cert/RootCA.crt",
			URL:            fmt.Sprintf("https://localhost:%d/", linseedPort),
			ClientCertPath: "../../linseed/fv/cert/localhost.crt",
			ClientKeyPath:  "../../linseed/fv/cert/localhost.key",
			ServerName:     "localhost",
		}

		linseedCli, err = lsclient.NewClient(linseedTenantId, cfg, lsrest.WithTokenPath(LinseedTokenPath))
		Expect(err).NotTo(HaveOccurred(), "Failed to create Linseed client")

		idx = index.PolicyActivityIndex()

		By("Creating handler")
		handler = middleware.NewPolicyActivityHandler(linseedCli)

		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	})

	AfterEach(func() {
		By("Cleaning up ES data")
		err := testutils.CleanupIndices(context.Background(), esClient, idx.IsSingleIndex(), idx, clusterInfo)
		Expect(err).NotTo(HaveOccurred())
		err = testutils.RefreshIndex(context.Background(), lmaClient, idx.Index(clusterInfo))
		Expect(err).NotTo(HaveOccurred())

		cancel()
	})

	It("returns items with nil timestamps when no activity data exists", func() {
		policyName := "nonexistent-" + testID
		req := newFVPolicyActivityPOST(uiapi.PolicyActivityRequest{
			Policies: []uiapi.PolicyActivityQuery{
				{Kind: "GlobalNetworkPolicy", Name: policyName, Generation: 1},
			},
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
		Expect(w.Body.Bytes()).To(MatchJSON(expectedFVResponseJSON([]uiapi.PolicyActivityItem{
			{PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: policyName}},
		})))
	})

	It("returns lastEvaluated for a policy with activity data at the requested generation", func() {
		now := time.Now()
		policyName := "allow-dns-" + testID
		By("Ingesting policy activity data into Linseed")
		logs := []linseedv1.PolicyActivity{
			{
				Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: policyName},
				Rule:          "1|ingress|0",
				LastEvaluated: now,
			},
			{
				Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: policyName},
				Rule:          "1|egress|0",
				LastEvaluated: now.Add(-1 * time.Minute),
			},
		}

		_, err := linseedCli.PolicyActivity(clusterInfo.Cluster).Create(ctx, logs)
		Expect(err).NotTo(HaveOccurred())

		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		Expect(err).NotTo(HaveOccurred())
		expectPolicyActivityDocs(ctx, esClient, idx, clusterInfo, "GlobalNetworkPolicy", policyName, 2)

		By("Querying the handler")
		req := newFVPolicyActivityPOST(uiapi.PolicyActivityRequest{
			Policies: []uiapi.PolicyActivityQuery{
				{Kind: "GlobalNetworkPolicy", Name: policyName, Generation: 1},
			},
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
		Expect(w.Body.Bytes()).To(MatchJSON(expectedFVResponseJSON([]uiapi.PolicyActivityItem{
			{PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: policyName}, PolicyActivity: uiapi.PolicyActivity{LastEvaluated: &now, LastEvaluatedGeneration: ptr.To(int64(1))}},
		})))
	})

	It("returns results for multiple policies in a single request", func() {
		now := time.Now()
		polA := "policy-a-" + testID
		polB := "policy-b-" + testID
		earlierB := now.Add(-5 * time.Minute)

		By("Ingesting activity for two policies")
		logs := []linseedv1.PolicyActivity{
			{
				Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: polA},
				Rule:          "1|ingress|0",
				LastEvaluated: now,
			},
			{
				Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: polB},
				Rule:          "1|ingress|0",
				LastEvaluated: earlierB,
			},
		}

		_, err := linseedCli.PolicyActivity(clusterInfo.Cluster).Create(ctx, logs)
		Expect(err).NotTo(HaveOccurred())

		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		Expect(err).NotTo(HaveOccurred())
		expectPolicyActivityDocs(ctx, esClient, idx, clusterInfo, "GlobalNetworkPolicy", polA, 1)
		expectPolicyActivityDocs(ctx, esClient, idx, clusterInfo, "GlobalNetworkPolicy", polB, 1)

		By("Querying for both policies")
		req := newFVPolicyActivityPOST(uiapi.PolicyActivityRequest{
			Policies: []uiapi.PolicyActivityQuery{
				{Kind: "GlobalNetworkPolicy", Name: polA, Generation: 1},
				{Kind: "GlobalNetworkPolicy", Name: polB, Generation: 1},
			},
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
		Expect(w.Body.Bytes()).To(MatchJSON(expectedFVResponseJSON([]uiapi.PolicyActivityItem{
			{PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: polA}, PolicyActivity: uiapi.PolicyActivity{LastEvaluated: &now, LastEvaluatedGeneration: ptr.To(int64(1))}},
			{PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: polB}, PolicyActivity: uiapi.PolicyActivity{LastEvaluated: &earlierB, LastEvaluatedGeneration: ptr.To(int64(1))}},
		})))
	})

	It("only returns data for the requested policies, not others", func() {
		now := time.Now()
		requested := "requested-" + testID
		other := "other-" + testID
		By("Ingesting activity for two policies, querying only one")
		logs := []linseedv1.PolicyActivity{
			{
				Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: requested},
				Rule:          "1|ingress|0",
				LastEvaluated: now,
			},
			{
				Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: other},
				Rule:          "1|ingress|0",
				LastEvaluated: now,
			},
		}

		_, err := linseedCli.PolicyActivity(clusterInfo.Cluster).Create(ctx, logs)
		Expect(err).NotTo(HaveOccurred())

		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		Expect(err).NotTo(HaveOccurred())
		expectPolicyActivityDocs(ctx, esClient, idx, clusterInfo, "GlobalNetworkPolicy", requested, 1)
		expectPolicyActivityDocs(ctx, esClient, idx, clusterInfo, "GlobalNetworkPolicy", other, 1)

		req := newFVPolicyActivityPOST(uiapi.PolicyActivityRequest{
			Policies: []uiapi.PolicyActivityQuery{
				{Kind: "GlobalNetworkPolicy", Name: requested, Generation: 1},
			},
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
		Expect(w.Body.Bytes()).To(MatchJSON(expectedFVResponseJSON([]uiapi.PolicyActivityItem{
			{PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: requested}, PolicyActivity: uiapi.PolicyActivity{LastEvaluated: &now, LastEvaluatedGeneration: ptr.To(int64(1))}},
		})))
	})

	It("returns activity data for namespaced NetworkPolicy", func() {
		now := time.Now()
		policyName := "allow-web-" + testID
		By("Ingesting namespaced policy activity")
		logs := []linseedv1.PolicyActivity{
			{
				Policy:        linseedv1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "production", Name: policyName},
				Rule:          "1|ingress|0",
				LastEvaluated: now,
			},
		}

		_, err := linseedCli.PolicyActivity(clusterInfo.Cluster).Create(ctx, logs)
		Expect(err).NotTo(HaveOccurred())

		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		Expect(err).NotTo(HaveOccurred())
		expectPolicyActivityDocs(ctx, esClient, idx, clusterInfo, "NetworkPolicy", policyName, 1)

		By("Querying with namespace parameter")
		req := newFVPolicyActivityPOST(uiapi.PolicyActivityRequest{
			Policies: []uiapi.PolicyActivityQuery{
				{Kind: "NetworkPolicy", Name: policyName, Namespace: "production", Generation: 1},
			},
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
		Expect(w.Body.Bytes()).To(MatchJSON(expectedFVResponseJSON([]uiapi.PolicyActivityItem{
			{PolicyKey: uiapi.PolicyKey{Kind: "NetworkPolicy", Namespace: "production", Name: policyName}, PolicyActivity: uiapi.PolicyActivity{LastEvaluated: &now, LastEvaluatedGeneration: ptr.To(int64(1))}},
		})))
	})

	It("returns lastEvaluatedAnyGeneration when data exists at a different generation", func() {
		now := time.Now()
		policyName := "evolving-" + testID
		By("Ingesting activity data at generation 1")
		logs := []linseedv1.PolicyActivity{
			{
				Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: policyName},
				Rule:          "1|ingress|0",
				LastEvaluated: now,
			},
		}

		_, err := linseedCli.PolicyActivity(clusterInfo.Cluster).Create(ctx, logs)
		Expect(err).NotTo(HaveOccurred())

		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		Expect(err).NotTo(HaveOccurred())
		expectPolicyActivityDocs(ctx, esClient, idx, clusterInfo, "GlobalNetworkPolicy", policyName, 1)

		By("Querying at generation 2 (no data at this generation)")
		req := newFVPolicyActivityPOST(uiapi.PolicyActivityRequest{
			Policies: []uiapi.PolicyActivityQuery{
				{Kind: "GlobalNetworkPolicy", Name: policyName, Generation: 2},
			},
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
		Expect(w.Body.Bytes()).To(MatchJSON(expectedFVResponseJSON([]uiapi.PolicyActivityItem{
			{PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: policyName}, PolicyActivity: uiapi.PolicyActivity{LastEvaluatedAnyGeneration: &now, LastEvaluatedGeneration: ptr.To(int64(1))}},
		})))
	})

	It("returns both nil when policy has never been evaluated at any generation", func() {
		policyName := "never-evaluated-" + testID
		By("Not ingesting any data, querying a non-existent policy")
		req := newFVPolicyActivityPOST(uiapi.PolicyActivityRequest{
			Policies: []uiapi.PolicyActivityQuery{
				{Kind: "GlobalNetworkPolicy", Name: policyName, Generation: 1},
			},
		})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		Expect(w.Code).To(Equal(http.StatusOK))
		Expect(w.Body.Bytes()).To(MatchJSON(expectedFVResponseJSON([]uiapi.PolicyActivityItem{
			{PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: policyName}},
		})))
	})

})
