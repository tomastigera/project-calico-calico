// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package middleware_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
	usr "github.com/projectcalico/calico/ui-apis/pkg/user"
)

const (
	iss = "https://127.0.0.1:9443/dex"
	sub = "ChUxMDkxMzE"
)

var _ = Describe("ElasticBasicUser", func() {
	var (
		fakeKube      k8s.Interface
		handler       http.Handler
		mockClientSet datastore.ClientSet
		defaultUser   user.Info
		ctx           context.Context
	)

	var (
		basicElasticLicenseCM = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      middleware.ECKLicenseConfigMapName,
				Namespace: middleware.ECKOperatorNamespace,
			},
			Data: map[string]string{
				"eck_license_level": "basic",
			},
		}
		elasticUsersCM = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      middleware.OIDCUsersConfigMapName,
				Namespace: middleware.ElasticsearchNamespace,
			},
		}
	)
	Context("dex enabled and Elasticsearch uses basic license", func() {
		BeforeEach(func() {

			fakeKube = fake.NewSimpleClientset(basicElasticLicenseCM, elasticUsersCM)
			mockClientSet = datastore.NewClientSet(fakeKube, nil)
			ctx = context.Background()
		})
		It("updates ConfigMap with username and group", func() {
			handler = middleware.NewUserHandler(mockClientSet, true, iss, "basic")

			respRecorder := httptest.NewRecorder()

			username := "abc@test.com"
			groups := []string{"admins", "random@test.com"}
			extras := make(map[string][]string)
			extras[usr.Subject] = []string{sub}
			extras[usr.Issuer] = []string{iss}
			defaultUser = &user.DefaultInfo{Name: "abc@test.com", Groups: groups, Extra: extras}

			req, err := http.NewRequest("POST", "/user", nil)
			Expect(err).ShouldNot(HaveOccurred())

			req.Header.Set("Authorization", authHeader(iss, username, groups))
			req = req.WithContext(request.WithUser(req.Context(), defaultUser))

			handler.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Code).Should(BeEquivalentTo(http.StatusOK))

			actualCm, err := mockClientSet.CoreV1().
				ConfigMaps(middleware.ElasticsearchNamespace).
				Get(ctx, middleware.OIDCUsersConfigMapName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			var actualVal *usr.OIDCUser
			err = json.Unmarshal([]byte(actualCm.Data[sub]), &actualVal)
			Expect(err).ShouldNot(HaveOccurred())

			expectedVal := &usr.OIDCUser{
				Username: username,
				Groups:   groups,
			}
			Expect(actualVal).Should(BeEquivalentTo(expectedVal))
		})
		It("updates ConfigMap with username", func() {
			handler = middleware.NewUserHandler(mockClientSet, true, iss, "basic")

			respRecorder := httptest.NewRecorder()

			username := "abc@test.com"
			extras := make(map[string][]string)
			extras[usr.Subject] = []string{sub}
			extras[usr.Issuer] = []string{iss}
			defaultUser = &user.DefaultInfo{Name: "abc@test.com", Extra: extras}

			req, err := http.NewRequest("POST", "/user", nil)
			Expect(err).ShouldNot(HaveOccurred())

			req.Header.Set("Authorization", authHeader(iss, username, nil))
			req = req.WithContext(request.WithUser(req.Context(), defaultUser))

			handler.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Code).Should(BeEquivalentTo(http.StatusOK))
			actualCm, err := mockClientSet.CoreV1().
				ConfigMaps(middleware.ElasticsearchNamespace).
				Get(ctx, middleware.OIDCUsersConfigMapName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			var actualVal *usr.OIDCUser
			err = json.Unmarshal([]byte(actualCm.Data[sub]), &actualVal)
			Expect(err).ShouldNot(HaveOccurred())

			expectedVal := &usr.OIDCUser{
				Username: username,
				Groups:   nil,
			}
			Expect(actualVal).Should(BeEquivalentTo(expectedVal))
		})
		It("doesn't update ConfigMap if JWT is not issued by dex", func() {
			handler = middleware.NewUserHandler(mockClientSet, true, "https://random_issuer", "basic")

			username := "abc@test.com"
			groups := []string{"admins", "random@test.com"}
			extras := make(map[string][]string)
			extras[usr.Subject] = []string{sub}
			extras[usr.Issuer] = []string{iss}
			defaultUser = &user.DefaultInfo{Name: "abc@test.com", Groups: groups, Extra: extras}

			req, err := http.NewRequest("POST", "/user", nil)
			Expect(err).ShouldNot(HaveOccurred())

			req.Header.Set("Authorization", authHeader(iss, username, groups))
			req = req.WithContext(request.WithUser(req.Context(), defaultUser))

			respRecorder := httptest.NewRecorder()
			handler.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Code).Should(BeEquivalentTo(http.StatusOK))
			actualCm, err := mockClientSet.CoreV1().
				ConfigMaps(middleware.ElasticsearchNamespace).
				Get(context.Background(), middleware.OIDCUsersConfigMapName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(actualCm.Data[sub]).Should(BeEquivalentTo(""))
		})
		It("returns error on unexpected http method", func() {
			handler = middleware.NewUserHandler(mockClientSet, true, iss, "")
			respRecorder := httptest.NewRecorder()

			req, err := http.NewRequest("GET", "/user", nil)
			Expect(err).ShouldNot(HaveOccurred())

			req = req.WithContext(request.WithUser(req.Context(), defaultUser))
			handler.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Code).Should(BeEquivalentTo(http.StatusMethodNotAllowed))
		})
	})
	Context("dex is not configured and Elasticsearch license is not basic", func() {
		BeforeEach(func() {
			fakeKube = fake.NewSimpleClientset()
			mockClientSet = datastore.NewClientSet(fakeKube, nil)
			ctx = context.Background()
		})
		It("returns without error", func() {
			handler = middleware.NewUserHandler(mockClientSet, false, iss, "enterprise")
			respRecorder := httptest.NewRecorder()

			req, err := http.NewRequest("POST", "/user", nil)
			Expect(err).ShouldNot(HaveOccurred())

			req = req.WithContext(request.WithUser(req.Context(), defaultUser))
			handler.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Code).Should(BeEquivalentTo(http.StatusOK))
		})
	})
	Context("dex is configured and Elasticsearch license is not basic", func() {
		BeforeEach(func() {
			cmElasticLicense := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      middleware.ECKLicenseConfigMapName,
					Namespace: middleware.ECKOperatorNamespace,
				},
				Data: map[string]string{
					"eck_license_level": "enterprise",
				},
			}

			fakeKube = fake.NewSimpleClientset(cmElasticLicense)
			mockClientSet = datastore.NewClientSet(fakeKube, nil)
			ctx = context.Background()
		})
		It("returns without error", func() {
			handler = middleware.NewUserHandler(mockClientSet, true, iss, "enterprise")
			respRecorder := httptest.NewRecorder()

			req, err := http.NewRequest("POST", "/user", nil)
			Expect(err).ShouldNot(HaveOccurred())

			req = req.WithContext(request.WithUser(req.Context(), defaultUser))
			handler.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Code).Should(BeEquivalentTo(http.StatusOK))
		})
	})
	Context("dex is configured and claim is not issued by dex", func() {
		BeforeEach(func() {
			fakeKube = fake.NewSimpleClientset(basicElasticLicenseCM, elasticUsersCM)
			mockClientSet = datastore.NewClientSet(fakeKube, nil)
			ctx = context.Background()
		})
		It("returns without error and does not update ConfigMap", func() {
			handler = middleware.NewUserHandler(mockClientSet, true, iss, "enterprise")

			respRecorder := httptest.NewRecorder()

			username := "abc@test.com"
			groups := []string{"admins", "random@test.com"}
			defaultUser = &user.DefaultInfo{Name: "abc@test.com", Groups: groups}

			req, err := http.NewRequest("POST", "/user", nil)
			Expect(err).ShouldNot(HaveOccurred())

			req.Header.Set("Authorization", authHeader("kubernetes/serviceaccount", username, groups))
			req = req.WithContext(request.WithUser(req.Context(), defaultUser))

			handler.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Code).Should(BeEquivalentTo(http.StatusOK))
			actualCm, err := mockClientSet.CoreV1().
				ConfigMaps(middleware.ElasticsearchNamespace).
				Get(ctx, middleware.OIDCUsersConfigMapName, metav1.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			_, ok := actualCm.Data[sub]
			Expect(ok).To(BeFalse())
		})
	})
})

func authHeader(issuer string, username string, groups []string) string {
	hdrhdr := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk3ODM2YzRiMjdmN2M3ZmVjMjk1MTk0NTFkNDc5MmUyNjQ4M2RmYWUifQ" // rs256 header
	payload := map[string]interface{}{
		"iss":            issuer,
		"sub":            sub,
		"aud":            "tigera-manager",
		"exp":            9600964803, //Very far in the future
		"iat":            1600878403,
		"nonce":          "35e32c66028243f592cc3103c7c2dfb2",
		"at_hash":        "jOq0F62t_NE9a3UXtNJkYg",
		"email":          username,
		"email_verified": true,
		"groups":         groups,
		"name":           username,
	}
	payloadJson, _ := json.Marshal(payload)
	payloadStr := base64.RawURLEncoding.EncodeToString(payloadJson)
	return fmt.Sprintf("Bearer %s.%s.%s", hdrhdr, payloadStr, "e30")
}
