// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package middleware_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	calicofake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	projectcalicov3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/discovery"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/ui-apis/pkg/authzreview"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
)

// mockCalculator is a test double for rbac.Calculator.
type mockCalculator struct {
	permissions  rbac.Permissions
	err          error
	capturedRVs  []rbac.ResourceVerbs
	capturedUser user.Info
}

func (m *mockCalculator) CalculatePermissions(u user.Info, rvs []rbac.ResourceVerbs) (rbac.Permissions, error) {
	m.capturedUser = u
	m.capturedRVs = rvs
	return m.permissions, m.err
}

// fakeClientSet satisfies lmak8s.ClientSet by wrapping a K8s fake clientset and adding ProjectcalicoV3().
// Optionally overrides Discovery() for testing forbidden scenarios.
type fakeClientSet struct {
	*k8sfake.Clientset
	calico            projectcalicov3.ProjectcalicoV3Interface
	discoveryOverride discovery.DiscoveryInterface
}

func (f *fakeClientSet) Discovery() discovery.DiscoveryInterface {
	if f.discoveryOverride != nil {
		return f.discoveryOverride
	}
	return f.Clientset.Discovery()
}

func (f *fakeClientSet) ProjectcalicoV3() projectcalicov3.ProjectcalicoV3Interface {
	return f.calico
}

// forbiddenDiscovery returns a forbidden error from ServerPreferredResources, simulating an older
// managed cluster where the service account lacks RBAC list permissions.
type forbiddenDiscovery struct {
	discovery.DiscoveryInterface
}

func (f *forbiddenDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	return nil, kerrors.NewForbidden(
		schema.GroupResource{Resource: "serverresources"}, "",
		fmt.Errorf("forbidden"),
	)
}

var _ = Describe("AuthorizationReviewHandler", func() {
	var (
		handler  http.Handler
		recorder *httptest.ResponseRecorder
		calc     *mockCalculator
	)

	BeforeEach(func() {
		calc = &mockCalculator{
			permissions: rbac.Permissions{
				rbac.ResourceType{APIGroup: "projectcalico.org", Resource: "tiers"}: {
					rbac.VerbGet: []rbac.Match{{Tier: "default"}},
				},
			},
		}
		handler = middleware.NewAuthorizationReviewHandler(authzreview.NewAuthzReviewer(calc, nil))
		recorder = httptest.NewRecorder()
	})

	Context("happy path with user from context", func() {
		It("returns permissions for the authenticated user", func() {
			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())

			ctxUser := &user.DefaultInfo{Name: "test-user", Groups: []string{"system:authenticated"}}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusOK))

			var out v3.AuthorizationReview
			err = json.Unmarshal(recorder.Body.Bytes(), &out)
			Expect(err).NotTo(HaveOccurred())
			Expect(out.Status.AuthorizedResourceVerbs).To(HaveLen(1))
			Expect(out.Status.AuthorizedResourceVerbs[0].Resource).To(Equal("tiers"))

			// Verify the correct user was passed to the calculator.
			Expect(calc.capturedUser.GetName()).To(Equal("test-user"))
		})
	})

	Context("explicit user info in spec", func() {
		It("rejects requests with Spec.User set", func() {
			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					User: "override-user",
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())

			ctxUser := &user.DefaultInfo{Name: "context-user"}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusBadRequest))
		})

		It("rejects requests with Spec.Groups set", func() {
			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					Groups: []string{"group-a"},
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())

			ctxUser := &user.DefaultInfo{Name: "context-user"}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusBadRequest))
		})

		It("rejects requests with Spec.UID set", func() {
			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					UID: "uid-123",
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())

			ctxUser := &user.DefaultInfo{Name: "context-user"}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusBadRequest))
		})

		It("rejects requests with Spec.Extra set", func() {
			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					Extra: map[string][]string{"key": {"val"}},
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())

			ctxUser := &user.DefaultInfo{Name: "context-user"}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusBadRequest))
		})
	})

	Context("impersonation headers", func() {
		It("rejects requests with Impersonate-User header", func() {
			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Impersonate-User", "someone-else")

			ctxUser := &user.DefaultInfo{Name: "test-user"}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusForbidden))
		})

		It("rejects requests with Impersonate-Group header", func() {
			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Impersonate-Group", "system:masters")

			ctxUser := &user.DefaultInfo{Name: "test-user"}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusForbidden))
		})
	})

	Context("malformed JSON", func() {
		It("returns 400", func() {
			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader([]byte("not json")))
			Expect(err).NotTo(HaveOccurred())

			ctxUser := &user.DefaultInfo{Name: "test-user"}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusBadRequest))
		})
	})

	Context("wrong HTTP method", func() {
		It("returns 405 for GET", func() {
			req, err := http.NewRequest(http.MethodGet, "/authorizationreviews", nil)
			Expect(err).NotTo(HaveOccurred())

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
		})
	})

	Context("user with zero permissions", func() {
		It("returns an empty AuthorizedResourceVerbs list", func() {
			calc.permissions = rbac.Permissions{}

			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())

			ctxUser := &user.DefaultInfo{Name: "no-permissions-user"}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusOK))

			var out v3.AuthorizationReview
			err = json.Unmarshal(recorder.Body.Bytes(), &out)
			Expect(err).NotTo(HaveOccurred())
			Expect(out.Status.AuthorizedResourceVerbs).To(BeEmpty())
		})
	})

	Context("calculator error", func() {
		It("returns 500", func() {
			calc.err = errors.New("calculator failure")

			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())

			ctxUser := &user.DefaultInfo{Name: "test-user"}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
		})
	})

	Context("no user in context and no spec user", func() {
		It("returns 500", func() {
			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())
			// No user set on context.

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
		})
	})

	Context("managed cluster via x-cluster-id header", func() {
		Context("calculator succeeds (new cluster with RBAC access)", func() {
			var mockCSFactory *lmak8s.MockClientSetFactory

			BeforeEach(func() {
				mockCSFactory = &lmak8s.MockClientSetFactory{}
				fCS := &fakeClientSet{
					Clientset: k8sfake.NewClientset(),
					calico:    calicofake.NewClientset().ProjectcalicoV3(),
				}
				mockCSFactory.On("NewClientSetForApplication", "managed-01").Return(fCS, nil)
				handler = middleware.NewAuthorizationReviewHandler(authzreview.NewAuthzReviewer(calc, mockCSFactory))
				recorder = httptest.NewRecorder()
			})

			It("uses the Calculator directly and populates user from context", func() {
				review := &v3.AuthorizationReview{
					Spec: v3.AuthorizationReviewSpec{
						ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
							{
								APIGroup:  "projectcalico.org",
								Resources: []string{"tiers"},
								Verbs:     []string{"get"},
							},
						},
					},
				}
				body, err := json.Marshal(review)
				Expect(err).NotTo(HaveOccurred())

				req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("x-cluster-id", "managed-01")

				ctxUser := &user.DefaultInfo{Name: "test-user", Groups: []string{"system:authenticated"}}
				req = req.WithContext(request.WithUser(req.Context(), ctxUser))

				handler.ServeHTTP(recorder, req)

				Expect(recorder.Code).To(Equal(http.StatusOK))

				var out v3.AuthorizationReview
				err = json.Unmarshal(recorder.Body.Bytes(), &out)
				Expect(err).NotTo(HaveOccurred())

				// User info should have been populated from context.
				Expect(out.Spec.User).To(Equal("test-user"))
				Expect(out.Spec.Groups).To(Equal([]string{"system:authenticated"}))

				// Status should be populated by the Calculator (AuthorizedResourceVerbs present).
				Expect(out.Status.AuthorizedResourceVerbs).To(HaveLen(1))
				Expect(out.Status.AuthorizedResourceVerbs[0].Resource).To(Equal("tiers"))

				// The local (management) calculator should NOT have been called.
				Expect(calc.capturedUser).To(BeNil())

				mockCSFactory.AssertCalled(GinkgoT(), "NewClientSetForApplication", "managed-01")
			})

			It("rejects requests with explicit user info in spec", func() {
				review := &v3.AuthorizationReview{
					Spec: v3.AuthorizationReviewSpec{
						User:   "override-user",
						UID:    "uid-456",
						Groups: []string{"group-b"},
						ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
							{
								APIGroup:  "projectcalico.org",
								Resources: []string{"tiers"},
								Verbs:     []string{"get"},
							},
						},
					},
				}
				body, err := json.Marshal(review)
				Expect(err).NotTo(HaveOccurred())

				req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("x-cluster-id", "managed-01")

				ctxUser := &user.DefaultInfo{Name: "context-user"}
				req = req.WithContext(request.WithUser(req.Context(), ctxUser))

				handler.ServeHTTP(recorder, req)
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("calculator returns forbidden (older cluster without RBAC access)", func() {
			var mockCSFactory *lmak8s.MockClientSetFactory

			BeforeEach(func() {
				mockCSFactory = &lmak8s.MockClientSetFactory{}
				fCS := &fakeClientSet{
					Clientset:         k8sfake.NewClientset(),
					calico:            calicofake.NewClientset().ProjectcalicoV3(),
					discoveryOverride: &forbiddenDiscovery{},
				}
				mockCSFactory.On("NewClientSetForApplication", "managed-01").Return(fCS, nil)
				handler = middleware.NewAuthorizationReviewHandler(authzreview.NewAuthzReviewer(calc, mockCSFactory))
				recorder = httptest.NewRecorder()
			})

			It("falls back to API server implementation", func() {
				review := &v3.AuthorizationReview{
					Spec: v3.AuthorizationReviewSpec{
						ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
							{
								APIGroup:  "projectcalico.org",
								Resources: []string{"tiers"},
								Verbs:     []string{"get"},
							},
						},
					},
				}
				body, err := json.Marshal(review)
				Expect(err).NotTo(HaveOccurred())

				req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("x-cluster-id", "managed-01")

				ctxUser := &user.DefaultInfo{Name: "test-user", Groups: []string{"system:authenticated"}}
				req = req.WithContext(request.WithUser(req.Context(), ctxUser))

				handler.ServeHTTP(recorder, req)

				Expect(recorder.Code).To(Equal(http.StatusOK))

				var out v3.AuthorizationReview
				err = json.Unmarshal(recorder.Body.Bytes(), &out)
				Expect(err).NotTo(HaveOccurred())

				// User info should have been populated from context for the API server fallback.
				Expect(out.Spec.User).To(Equal("test-user"))
				Expect(out.Spec.Groups).To(Equal([]string{"system:authenticated"}))

				// Status is empty because the fake API server Create doesn't compute permissions.
				Expect(out.Status.AuthorizedResourceVerbs).To(BeEmpty())

				// The local (management) calculator should NOT have been called.
				Expect(calc.capturedUser).To(BeNil())

				// Without a context-injected factory, the fallback reuses the static factory.
				mockCSFactory.AssertCalled(GinkgoT(), "NewClientSetForApplication", "managed-01")
			})
		})

		It("returns 500 when client set factory fails", func() {
			failFactory := &lmak8s.MockClientSetFactory{}
			failFactory.On("NewClientSetForApplication", "bad-cluster").Return(nil, errors.New("connection refused"))
			handler = middleware.NewAuthorizationReviewHandler(authzreview.NewAuthzReviewer(calc, failFactory))

			review := &v3.AuthorizationReview{
				Spec: v3.AuthorizationReviewSpec{
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "projectcalico.org",
							Resources: []string{"tiers"},
							Verbs:     []string{"get"},
						},
					},
				},
			}
			body, err := json.Marshal(review)
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "/authorizationreviews", bytes.NewReader(body))
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("x-cluster-id", "bad-cluster")

			ctxUser := &user.DefaultInfo{Name: "test-user"}
			req = req.WithContext(request.WithUser(req.Context(), ctxUser))

			handler.ServeHTTP(recorder, req)
			Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
		})
	})
})
