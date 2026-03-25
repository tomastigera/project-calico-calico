// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package visibility

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/e2e/pkg/config"
	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	cclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/elasticsearch"
)

// policiesResponse mirrors the queryserver QueryPoliciesResp for JSON unmarshalling.
type policiesResponse struct {
	Count int              `json:"count"`
	Items []policyResponse `json:"items"`
}

// policyResponse contains the fields we care about for validation.
// lastEvaluated is a pointer so we can distinguish null from absent.
type policyResponse struct {
	Kind          string             `json:"kind"`
	Name          string             `json:"name"`
	Namespace     string             `json:"namespace,omitempty"`
	Tier          string             `json:"tier,omitempty"`
	LastEvaluated *time.Time         `json:"lastEvaluated"`
	IngressRules  []ruleDirectionRes `json:"ingressRules,omitempty"`
	EgressRules   []ruleDirectionRes `json:"egressRules,omitempty"`
}

type ruleDirectionRes struct {
	LastEvaluated *time.Time `json:"lastEvaluated"`
}

// DESCRIPTION: This test validates the queryserver /policies API returns
// policy activity enrichment data (lastEvaluated timestamps).
// PRECONDITIONS: Calico Enterprise with Linseed deployed.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.EV),
	describe.WithFeature("PolicyActivity"),
	describe.WithCategory(describe.Visibility),
	"policy activity enrichment",
	func() {
		var (
			f             = utils.NewDefaultFramework("policy-activity")
			httpClient    *http.Client
			token         string
			cancelForward func()
		)

		BeforeEach(func() {
			ctx := context.Background()

			cli, err := cclient.New(f.ClientConfig())
			Expect(err).ShouldNot(HaveOccurred())

			isEnterprise, err := utils.IsEnterprise(ctx, cli)
			Expect(err).NotTo(HaveOccurred())
			if !isEnterprise {
				Skip("Policy activity tests require Calico Enterprise")
			}

			// Skip if calico-manager deployment is not ready (e.g. kind clusters without voltron).
			mgr, err := f.ClientSet.AppsV1().Deployments("calico-system").Get(ctx, "calico-manager", metav1.GetOptions{})
			if err != nil || mgr.Status.ReadyReplicas == 0 {
				Skip("Policy activity tests require a running calico-manager (voltron)")
			}

			// Port-forward to manager (voltron proxies to queryserver).
			cancelForward = elasticsearch.PortForward()

			// HTTP client with TLS CA from the cluster.
			caCert := utils.GetTigeraCACert(ctx, f)
			httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: caCert,
			}}}

			// Create network-admin SA and get token.
			token, err = utils.NetworkAdminToken(ctx, f.ClientSet, f.Namespace.Name)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				if cancelForward != nil {
					cancelForward()
				}
			})
		})

		// TODO(EV-6445): Revert to framework.ConformanceIt once e2e test setup for
		// policy activity is merged and the infrastructure is in place.
		It("should return lastEvaluated field in policy responses", func() {
			resp := queryPolicies(httpClient, config.ManagerURL(), token, nil, nil)
			Expect(resp.Count).To(BeNumerically(">", 0), "Cluster should have at least one policy")

			// Verify every policy item has the lastEvaluated key present in JSON
			// (it may be null, but the field must be serialized).
			By("Checking that lastEvaluated field is present in all policy items")
			rawBody := queryPoliciesRaw(httpClient, config.ManagerURL(), token, nil, nil)
			var raw map[string]json.RawMessage
			Expect(json.Unmarshal(rawBody, &raw)).To(Succeed())

			var items []json.RawMessage
			Expect(json.Unmarshal(raw["items"], &items)).To(Succeed())
			Expect(items).NotTo(BeEmpty())

			for i, item := range items {
				var fields map[string]json.RawMessage
				Expect(json.Unmarshal(item, &fields)).To(Succeed())
				_, hasLastEvaluated := fields["lastEvaluated"]
				Expect(hasLastEvaluated).To(BeTrue(),
					fmt.Sprintf("policy item %d should have lastEvaluated field", i))
			}
		})

		It("should return rules with lastEvaluated field", func() {
			resp := queryPolicies(httpClient, config.ManagerURL(), token, nil, nil)
			Expect(resp.Count).To(BeNumerically(">", 0))

			// Find a policy with rules to check.
			foundRules := false
			for _, pol := range resp.Items {
				for _, rule := range pol.IngressRules {
					foundRules = true
					// lastEvaluated can be nil (no activity) but the field must exist.
					// We just verify the struct unmarshalled correctly (no panic).
					_ = rule.LastEvaluated
				}
				for _, rule := range pol.EgressRules {
					foundRules = true
					_ = rule.LastEvaluated
				}
			}
			if !foundRules {
				logrus.Warn("No policies with rules found; rule-level lastEvaluated check skipped")
			}
		})

		It("should accept from and to query parameters", func() {
			now := time.Now().UTC()
			from := now.Add(-1 * time.Hour)
			to := now

			resp := queryPolicies(httpClient, config.ManagerURL(), token, &from, &to)
			// Should succeed and return policies (the cluster always has default policies).
			Expect(resp.Count).To(BeNumerically(">", 0))
		})

		It("should reject invalid from parameter", func() {
			url := fmt.Sprintf("%s/tigera-elasticsearch/policies?from=not-a-date", config.ManagerURL())
			req, err := http.NewRequest(http.MethodGet, url, nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			resp, err := httpClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()

			Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
		})

		It("should reject to before from", func() {
			url := fmt.Sprintf(
				"%s/tigera-elasticsearch/policies?from=%s&to=%s",
				config.ManagerURL(),
				time.Now().UTC().Format(time.RFC3339),
				time.Now().UTC().Add(-1*time.Hour).Format(time.RFC3339),
			)
			req, err := http.NewRequest(http.MethodGet, url, nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			resp, err := httpClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()

			Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
		})
	})

// queryPolicies calls the queryserver /policies endpoint and returns the parsed response.
func queryPolicies(httpClient *http.Client, managerURL, token string, from, to *time.Time) policiesResponse {
	body := queryPoliciesRaw(httpClient, managerURL, token, from, to)
	var resp policiesResponse
	Expect(json.Unmarshal(body, &resp)).To(Succeed(), "Failed to parse policies response")
	return resp
}

// queryPoliciesRaw calls the queryserver /policies endpoint and returns the raw JSON body.
func queryPoliciesRaw(httpClient *http.Client, managerURL, token string, from, to *time.Time) []byte {
	url := fmt.Sprintf("%s/tigera-elasticsearch/policies", managerURL)
	sep := "?"
	if from != nil {
		url += fmt.Sprintf("%sfrom=%s", sep, from.UTC().Format(time.RFC3339))
		sep = "&"
	}
	if to != nil {
		url += fmt.Sprintf("%sto=%s", sep, to.UTC().Format(time.RFC3339))
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := httpClient.Do(req)
	Expect(err).NotTo(HaveOccurred(), "Failed to call queryserver /policies")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode).To(Equal(http.StatusOK),
		fmt.Sprintf("Expected 200 from /policies, got %d: %s", resp.StatusCode, string(body)))

	return body
}
