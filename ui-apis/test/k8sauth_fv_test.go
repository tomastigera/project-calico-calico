// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authzv1 "k8s.io/api/authorization/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"

	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/auth/testing"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
)

// HttpHandler to see that the 'next' handler was called or not
type DummyHttpHandler struct {
	serveCalled bool
}

func (dhh *DummyHttpHandler) ServeHTTP(http.ResponseWriter, *http.Request) {
	dhh.serveCalled = true
}

var tigeraFlowPath = "/tigera_secure_ee_flows*/_search"
var pathToSomething = "/path/to/something"

func genPath(q string) string {
	return fmt.Sprintf("/%s/_search", q)
}

var _ = Describe("Authenticate against K8s apiserver", func() {
	var (
		k8sClient     k8s.Interface
		dhh           *DummyHttpHandler
		rr            *httptest.ResponseRecorder
		authorizer    auth.RBACAuthorizer
		authenticator auth.JWTAuth

		iss = auth.ServiceAccountIss

		fakeK8sCli *fake.Clientset

		tokenuserall           = testing.NewFakeJWT(iss, "tokenuserall")
		tokenuserflowonly      = testing.NewFakeJWT(iss, "tokenuserflowonly")
		tokenuserauditonly     = testing.NewFakeJWT(iss, "tokenuserauditonly")
		tokenuserauditkubeonly = testing.NewFakeJWT(iss, "tokenuserauditkubeonly")
		tokenusernone          = testing.NewFakeJWT(iss, "tokenuserauditkubeonly")
		tokenusernru           = testing.NewFakeJWT(iss, "tokenusernru")
	)
	BeforeEach(func() {
		restCfg := restclient.Config{}
		restCfg.Host = "https://localhost:6443"
		restCfg.Insecure = true
		if restCfg.RateLimiter == nil && restCfg.QPS > 0 {
			restCfg.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(restCfg.QPS, restCfg.Burst)
		}

		k8sClient = k8s.NewForConfigOrDie(&restCfg)
		Expect(k8sClient).NotTo(BeNil())

		dhh = &DummyHttpHandler{serveCalled: false}
		rr = httptest.NewRecorder()
		fakeK8sCli = new(fake.Clientset)
		var err error
		authenticator, err = auth.NewJWTAuth(&restclient.Config{BearerToken: tokenuserall.ToString()}, fakeK8sCli)
		Expect(err).NotTo(HaveOccurred())
		authorizer = auth.NewRBACAuthorizer(k8sClient)

		// Register all users.
		testing.SetTokenReviewsReactor(fakeK8sCli, tokenuserall, tokenuserflowonly, tokenuserauditonly, tokenuserauditkubeonly, tokenusernone, tokenusernru)
	})
	AfterEach(func() {
	})

	// This is really more of a test that RequestToResource does not add a
	// ResourceAttribute to the context and that K8sAuth interprets that as
	// Forbidden.
	It("Should cause StatusForbidden with valid token but missing URL", func() {
		By("authenticating the token", func() {
			uut := middleware.RequestToResource(
				middleware.AuthenticateRequest(authenticator,
					middleware.AuthorizeRequest(authorizer, dhh)))
			req := &http.Request{Header: http.Header{"Authorization": []string{tokenuserall.BearerTokenHeader()}}}
			uut.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusForbidden), "Token deadbeef authentication failed")
			Expect(dhh.serveCalled).To(BeFalse())
		})
	})

	DescribeTable("Invalid login causes StatusUnauthorized",
		func(req *http.Request) {
			uut := middleware.RequestToResource(
				middleware.AuthenticateRequest(authenticator,
					middleware.AuthorizeRequest(authorizer, dhh)))
			uut.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusUnauthorized),
				fmt.Sprintf("Message in response writer: %s", rr.Body.String()))
			Expect(dhh.serveCalled).To(BeFalse())
		},
		Entry("Bad bearer token",
			&http.Request{
				Header: http.Header{"Authorization": []string{"Bearer d00dbeef"}},
				URL:    &url.URL{Path: tigeraFlowPath},
			}),
	)

	// These test that tokens are mapping to users that have access to certain
	// paths/resources. See the test folder for the users (in *.csv) and roles
	// and bindings for them.
	DescribeTable("Test valid Authorization Headers",
		func(req *http.Request) {
			uut := middleware.RequestToResource(
				middleware.AuthenticateRequest(authenticator,
					middleware.AuthorizeRequest(authorizer, dhh)))
			uut.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK),
				fmt.Sprintf("Should get OK status, message: %s", rr.Body.String()))
			Expect(dhh.serveCalled).To(BeTrue())
		},

		Entry("Allow all token access flow",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserall.BearerTokenHeader()}},
				URL:    &url.URL{Path: tigeraFlowPath},
			}),
		Entry("Allow all token access audit*",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserall.BearerTokenHeader()}},
				URL:    &url.URL{Path: genPath("tigera_secure_ee_audit_*.cluster.*")},
			}),
		Entry("Allow all token access audit_ee",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserall.BearerTokenHeader()}},
				URL:    &url.URL{Path: genPath("tigera_secure_ee_audit_ee.cluster.*")},
			}),
		Entry("Allow all token access audit_kube",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserall.BearerTokenHeader()}},
				URL:    &url.URL{Path: genPath("tigera_secure_ee_audit_kube.cluster.*")},
			}),
		Entry("Allow all token access events",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserall.BearerTokenHeader()}},
				URL:    &url.URL{Path: genPath("tigera_secure_ee_events*")},
			}),
		Entry("Flow token access flow",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserflowonly.BearerTokenHeader()}},
				URL:    &url.URL{Path: tigeraFlowPath},
			}),
		Entry("All Audit token access audit*",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserauditonly.BearerTokenHeader()}},
				URL:    &url.URL{Path: genPath("tigera_secure_ee_audit_*.cluster.*")},
			}),
		Entry("All Audit token access audit_ee",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserauditonly.BearerTokenHeader()}},
				URL:    &url.URL{Path: genPath("tigera_secure_ee_audit_ee.cluster.*")},
			}),
		Entry("Audit kube token access audit_kube",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserauditkubeonly.BearerTokenHeader()}},
				URL:    &url.URL{Path: genPath("tigera_secure_ee_audit_kube.cluster.*")},
			}),
	)

	DescribeTable("Test valid Authorization Headers to unauthorized resource causes Forbidden",
		func(req *http.Request) {
			uut := middleware.RequestToResource(
				middleware.AuthenticateRequest(authenticator,
					middleware.AuthorizeRequest(authorizer, dhh)))
			uut.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusForbidden),
				fmt.Sprintf("Should get %d status, message: %s",
					http.StatusForbidden, rr.Body.String()))
			Expect(dhh.serveCalled).To(BeFalse())
		},

		Entry("Token for user tokenuserauditonly try to access flows",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserauditonly.BearerTokenHeader()}},
				URL:    &url.URL{Path: tigeraFlowPath},
			}),
		Entry("Token with no access (user tokenusernone) try to access flows",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenusernone.BearerTokenHeader()}},
				URL:    &url.URL{Path: tigeraFlowPath},
			}),
		Entry("Token with only audit_kube access try to access audit*",
			&http.Request{
				Header: http.Header{"Authorization": []string{tokenuserauditkubeonly.BearerTokenHeader()}},
				URL:    &url.URL{Path: genPath("tigera_secure_ee_audit*")},
			}),
	)

	It("Should cause an InternalServer error when no ResourceAttribute is set on the context", func() {
		By("authorizing the request", func() {
			uut := middleware.AuthenticateRequest(authenticator, middleware.AuthorizeRequest(authorizer, dhh))
			req := &http.Request{
				Header: http.Header{"Authorization": []string{tokenuserall.BearerTokenHeader()}},
				// The URL should not matter but include it anyway to ensure the
				// KubernetesAuthnAuthz does not parse the path.
				URL: &url.URL{Path: tigeraFlowPath},
			}
			uut.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusInternalServerError),
				fmt.Sprintf("The message written to the request writer: %s", rr.Body.String()))
			Expect(dhh.serveCalled).To(BeFalse())
		})
	})

	Context("Test non resource URL", func() {
		DescribeTable("RBAC enforcement on access to non resource URL",
			func(req *http.Request, statusCode int, isServeCalled bool) {
				uut := dummyNonResourceMiddleware(
					middleware.AuthenticateRequest(authenticator,
						middleware.AuthorizeRequest(authorizer, dhh)))
				uut.ServeHTTP(rr, req)

				Expect(rr.Code).To(Equal(statusCode),
					fmt.Sprintf("Should get %d status, message: %s", statusCode, rr.Body.String()))
				Expect(dhh.serveCalled).To(Equal(isServeCalled))
			},

			Entry("Token for user tokenusernru try to access /path/to/something is allowed",
				&http.Request{
					Header: http.Header{"Authorization": []string{tokenusernru.BearerTokenHeader()}},
					URL:    &url.URL{Path: pathToSomething},
				}, http.StatusOK, true),
			Entry("Token for user tokenusernone try to access /path/to/something is forbidden",
				&http.Request{
					Header: http.Header{"Authorization": []string{tokenusernone.BearerTokenHeader()}},
					URL:    &url.URL{Path: pathToSomething},
				}, http.StatusForbidden, false),
		)
	})

})

func dummyNonResourceMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h.ServeHTTP(w, req.WithContext(auth.NewContextWithReviewNonResource(req.Context(), getNonResourceAttributes(req.URL.Path))))
	})
}

func getNonResourceAttributes(path string) *authzv1.NonResourceAttributes {
	return &authzv1.NonResourceAttributes{
		Verb: "get",
		Path: path,
	}
}
