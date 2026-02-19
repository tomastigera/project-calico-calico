// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/ui-apis/pkg/kibana"
)

const (
	dexIssuer = "https://127.0.0.1:9443/dex"
)

var _ = Describe("Kibana", func() {
	var (
		fakeClientSet datastore.ClientSet
		mockKibanaCli *kibana.MockClient
	)
	BeforeEach(func() {
		fakeClientSet = datastore.NewClientSet(fake.NewSimpleClientset(), nil)
		mockKibanaCli = new(kibana.MockClient)
	})

	Context("Redirect to Kibana without logging in", func() {
		When("Dex is not enabled", func() {
			It("redirects to Kibana without setting the sid cookie", func() {
				respRecorder := httptest.NewRecorder()

				req, err := http.NewRequest("GET", "", nil)
				Expect(err).ShouldNot(HaveOccurred())

				req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{
					Name: "test-user",
					Extra: map[string][]string{
						"iss": {dexIssuer},
						"sub": {"asdf"},
					},
				}))

				Expect(err).ShouldNot(HaveOccurred())

				NewKibanaLoginHandler(fakeClientSet, mockKibanaCli, false, dexIssuer, ElasticsearchLicenseTypeBasic).ServeHTTP(respRecorder, req)
				response := respRecorder.Result()

				Expect(response.StatusCode).Should(Equal(http.StatusFound))
				Expect(len(response.Cookies())).Should(Equal(0))
				Expect(response.Header.Get("Location")).Should(Equal(kibanaURL))
			})
		})

		When("the issuer is not Dex", func() {
			It("redirects to Kibana without setting the sid cookie", func() {
				respRecorder := httptest.NewRecorder()

				req, err := http.NewRequest("GET", "http://localhost:9443", nil)
				Expect(err).ShouldNot(HaveOccurred())

				req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{
					Name: "test-user",
					Extra: map[string][]string{
						"iss": {dexIssuer},
						"sub": {"asdf"},
					},
				}))

				NewKibanaLoginHandler(fakeClientSet, mockKibanaCli, true, "not-dex", ElasticsearchLicenseTypeBasic).ServeHTTP(respRecorder, req)
				response := respRecorder.Result()

				Expect(len(response.Cookies())).Should(Equal(0))
				Expect(response.Header.Get("Location")).Should(Equal(kibanaURL))
			})
		})

		When("the Elasticsearch license is not basic", func() {
			It("redirects to Kibana without setting the sid cookie", func() {
				respRecorder := httptest.NewRecorder()

				req, err := http.NewRequest("GET", "", nil)
				Expect(err).ShouldNot(HaveOccurred())

				req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{
					Name: "test-user",
					Extra: map[string][]string{
						"iss": {dexIssuer},
						"sub": {"asdf"},
					},
				}))

				NewKibanaLoginHandler(fakeClientSet, mockKibanaCli, true, dexIssuer, "badlincensetype").ServeHTTP(respRecorder, req)
				response := respRecorder.Result()

				Expect(len(response.Cookies())).Should(Equal(0))
				Expect(response.Header.Get("Location")).Should(Equal(kibanaURL))
			})
		})
	})

	Context("Dex is enabled, issuer is Dex, and the Elasticsearch license is basic", func() {
		It("logs the user in by setting cookies and redirects to Kibana", func() {
			userSubjectID := "123456789abcdefg"
			userESPassword := "password"
			sid := "lmnop987654321"

			_, err := fakeClientSet.CoreV1().Secrets(ElasticsearchNamespace).Create(context.Background(), &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      OIDCUsersElasticsearchCredentialsSecret,
					Namespace: ElasticsearchNamespace,
				},
				Data: map[string][]byte{
					userSubjectID: []byte(userESPassword),
				},
			}, metav1.CreateOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			respRecorder := httptest.NewRecorder()

			req, err := http.NewRequest("GET", "https://localhost:9443/tigera-elasticsearch/kibana/login", nil)
			Expect(err).ShouldNot(HaveOccurred())

			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{
				Name: "test-user",
				Extra: map[string][]string{
					"iss": {dexIssuer},
					"sub": {userSubjectID},
				},
			}))

			mockKibanaCli.On("Login", "https://localhost:9443", userSubjectID, userESPassword).Return(&http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Set-Cookie": {(&http.Cookie{Name: "sid", Value: sid}).String()},
				},
			}, nil)

			NewKibanaLoginHandler(fakeClientSet, mockKibanaCli, true, dexIssuer, ElasticsearchLicenseTypeBasic).ServeHTTP(respRecorder, req)
			response := respRecorder.Result()

			Expect(len(response.Cookies())).Should(Equal(1))
			Expect(response.Header.Get("Location")).Should(Equal(kibanaURL))
		})

		It("returns error if user does't exist in Elasticsearch", func() {
			userSubjectID := "123456789abcdefg"

			_, err := fakeClientSet.CoreV1().Secrets(ElasticsearchNamespace).Create(context.Background(), &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      OIDCUsersElasticsearchCredentialsSecret,
					Namespace: ElasticsearchNamespace,
				},
			}, metav1.CreateOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			respRecorder := httptest.NewRecorder()

			req, err := http.NewRequest("GET", "https://localhost:9443/tigera-elasticsearch/kibana/login", nil)
			Expect(err).ShouldNot(HaveOccurred())

			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{
				Name: "test-user",
				Extra: map[string][]string{
					"iss": {dexIssuer},
					"sub": {userSubjectID},
				},
			}))

			NewKibanaLoginHandler(fakeClientSet, mockKibanaCli, true, dexIssuer, ElasticsearchLicenseTypeBasic).ServeHTTP(respRecorder, req)
			response := respRecorder.Result()

			Expect(len(response.Cookies())).Should(Equal(0))
			Expect(response.Header.Get("Location")).Should(HavePrefix(dashboardURL))
			Expect(response.Header.Get("Location")).Should(ContainSubstring("errorCode=403"))
		})
	})
})
