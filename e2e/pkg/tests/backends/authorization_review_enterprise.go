// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package backends

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	cclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
)

// DESCRIPTION: Verifies the AuthorizationReview API served by ui-apis through Voltron.
// Exercises the end-to-end request path (client -> Voltron -> ui-apis -> RBAC calculator)
// and confirms the API enforces its security invariants (no explicit user info, no impersonation).
// PRECONDITIONS: Calico Enterprise cluster with ui-apis and Voltron (calico-manager) running.
var _ = describe.EnterpriseDescribe(
	describe.WithTeam(describe.EV),
	describe.WithFeature("AuthorizationReview"),
	describe.WithCategory(describe.Visibility),
	"AuthorizationReview API",
	func() {
		f := utils.NewDefaultFramework("authz-review")

		var (
			cli        ctrlclient.Client
			httpClient *http.Client
			managerURL string
			stopCh     chan time.Time
			token      string
		)

		ginkgo.BeforeEach(func() {
			ctx := context.Background()

			var err error
			cli, err = cclient.New(f.ClientConfig())
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to create controller-runtime client")

			// Fail fast if this isn't an enterprise cluster.
			isEnterprise, err := utils.IsEnterprise(ctx, cli)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to check enterprise status")
			if !isEnterprise {
				ginkgo.Fail("AuthorizationReview tests require Calico Enterprise")
			}

			// Port-forward to calico-manager (Voltron) and build the manager URL
			// from the dynamically allocated local port.
			stopCh = make(chan time.Time, 1)
			kubectl := utils.Kubectl{}
			port, err := kubectl.PortForward("calico-system", "svc/calico-manager", "9443", "", stopCh)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to port-forward to calico-manager")
			managerURL = fmt.Sprintf("https://localhost:%d", port)

			// Build an HTTP client that trusts the cluster CA.
			caCert := utils.GetTigeraCACert(ctx, f)
			httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: caCert,
			}}}

			// Ensure the port-forward is ready before proceeding.
			kubectl.WaitForPortForward(httpClient, managerURL)

			ginkgo.By("Creating a network-admin service account and token")
			token, err = utils.NetworkAdminToken(ctx, f.ClientSet, f.Namespace.Name)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to create network-admin token")

			ginkgo.DeferCleanup(func() {
				stopCh <- time.Now()
				close(stopCh)
			})
		})

		// Helper to send an AuthorizationReview with the authenticated user's token.
		doReview := func(ctx context.Context, review *v3.AuthorizationReview, extraHeaders map[string]string) (*http.Response, error) {
			headers := map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", token),
			}
			for k, v := range extraHeaders {
				headers[k] = v
			}
			return doAuthorizationReview(ctx, httpClient, managerURL, review, headers)
		}

		// End-to-end smoke test: send a valid AuthorizationReview and confirm
		// the full request path (Voltron -> ui-apis -> RBAC calculator) returns 200
		// with a well-formed response containing at least some authorized verbs.
		framework.ConformanceIt("should return a successful response with authorized verbs", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			ginkgo.By("Sending an AuthorizationReview request for Calico policy resources")
			review := newAuthorizationReview([]v3.AuthorizationReviewResourceAttributes{
				{
					APIGroup:  "projectcalico.org",
					Resources: []string{"tiers", "networkpolicies"},
					Verbs:     []string{"get", "list", "create", "delete"},
				},
			})

			resp, err := doReview(ctx, review, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "AuthorizationReview request failed")
			gomega.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK), "expected 200 from AuthorizationReview")

			result := decodeAuthorizationReview(resp)
			gomega.Expect(result.Status.AuthorizedResourceVerbs).NotTo(gomega.BeEmpty(), "expected at least some authorized resource verbs in the response")
		})

		// The handler must reject requests that set Spec.User, since user identity
		// should come from the authenticated request context, not the request body. The
		// request body is only used for MCM flows, and never from the UI.
		framework.ConformanceIt("should reject requests with explicit user info in the spec", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			ginkgo.By("Sending an AuthorizationReview with Spec.User set")
			review := newAuthorizationReview([]v3.AuthorizationReviewResourceAttributes{
				{
					APIGroup:  "projectcalico.org",
					Resources: []string{"networkpolicies"},
					Verbs:     []string{"get"},
				},
			})
			review.Spec.User = "someone-else"

			resp, err := doReview(ctx, review, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "AuthorizationReview request failed")

			body := readBody(resp)
			gomega.Expect(resp.StatusCode).To(gomega.Equal(http.StatusBadRequest), "expected 400 when Spec.User is set, got body: %s", body)
		})

		// Voltron forwards requests to ui-apis, which rejects any request carrying
		// impersonation headers.
		framework.ConformanceIt("should reject requests with impersonation headers", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			ginkgo.By("Sending an AuthorizationReview with an Impersonate-User header")
			review := newAuthorizationReview([]v3.AuthorizationReviewResourceAttributes{
				{
					APIGroup:  "projectcalico.org",
					Resources: []string{"networkpolicies"},
					Verbs:     []string{"get"},
				},
			})

			resp, err := doReview(ctx, review, map[string]string{
				"Impersonate-User": "someone-else",
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "AuthorizationReview request failed")

			respBody := readBody(resp)
			// The request should be rejected — either by Voltron (403) stripping/rejecting
			// impersonation from non-privileged users, or by ui-apis (403) if the header
			// makes it through. Either way, it must not succeed.
			gomega.Expect(resp.StatusCode).NotTo(gomega.Equal(http.StatusOK), "impersonation header should not be accepted, got body: %s", respBody)
		})
	},
)

// newAuthorizationReview builds an AuthorizationReview with the given resource attributes.
func newAuthorizationReview(attrs []v3.AuthorizationReviewResourceAttributes) *v3.AuthorizationReview {
	return &v3.AuthorizationReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindAuthorizationReview,
			APIVersion: "projectcalico.org/v3",
		},
		Spec: v3.AuthorizationReviewSpec{
			ResourceAttributes: attrs,
		},
	}
}

// doAuthorizationReview sends an AuthorizationReview POST to the manager and returns the raw response.
func doAuthorizationReview(ctx context.Context, httpClient *http.Client, managerURL string, review *v3.AuthorizationReview, headers map[string]string) (*http.Response, error) {
	body, err := json.Marshal(review)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/apis/projectcalico.org/v3/authorizationreviews", managerURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	return httpClient.Do(req)
}

// decodeAuthorizationReview reads and decodes an AuthorizationReview from an HTTP response.
func decodeAuthorizationReview(resp *http.Response) *v3.AuthorizationReview {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred(), "failed to read response body")

	result := &v3.AuthorizationReview{}
	err = json.Unmarshal(body, result)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred(), "failed to decode AuthorizationReview response: %s", string(body))
	return result
}

// readBody reads and returns the response body as a string, closing the body.
func readBody(resp *http.Response) string {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	gomega.ExpectWithOffset(1, err).NotTo(gomega.HaveOccurred(), "failed to read response body")
	return string(body)
}
