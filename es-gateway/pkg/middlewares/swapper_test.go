// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package middlewares

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/es-gateway/pkg/cache"
)

var _ = Describe("Credential swapper middleware", func() {
	type args struct {
		c          cache.SecretsCache
		secretName string
	}
	type testCase struct {
		args                args
		expectedUsername    string
		expectedPassword    string
		expectedClusterName string
		expectedErr         bool
	}
	DescribeTable("Test getting plain ES credentials",
		func(tt testCase) {
			actualUsername, actualPassword, clusterName, err := getPlainESCredentials(tt.args.c, tt.args.secretName)

			if tt.expectedErr {
				Expect(err).ToNot(BeNil())
			} else {
				Expect(err).To(BeNil())
			}
			Expect(actualUsername).To(Equal(tt.expectedUsername))
			Expect(actualPassword).To(Equal(tt.expectedPassword))
			Expect(clusterName).To(Equal(tt.expectedClusterName))
		},
		Entry(
			"Should successfully retrieve username and password.",
			testCase{
				args: args{
					c: &mockSecretCache{
						mockSecretName:     "secret-name",
						mockUsername:       "username",
						includeUsername:    true,
						mockPassword:       "passwordHash",
						includePassword:    true,
						clusterName:        "my-tenant.my-cluster",
						includeClusterName: true,
					},
					secretName: "secret-name",
				},
				expectedUsername:    "username",
				expectedPassword:    "passwordHash",
				expectedClusterName: "my-tenant.my-cluster",
				expectedErr:         false,
			},
		),
		Entry(
			"Should return error (failed to retrieve secret).",
			testCase{
				args: args{
					c: &mockSecretCache{
						// Only need to populate this field because we expect the secret not to be found.
						mockSecretName: "secret-name",
					},
					secretName: "secret-name-not-found",
				},
				expectedErr: true,
			},
		),
		Entry(
			"Should return error (secret did not contain expected field).",
			testCase{
				args: args{
					c: &mockSecretCache{
						mockSecretName: "secret-name",
					},
					secretName: "secret-name",
				},
				expectedErr: true,
			},
		),
		Entry(
			"Should return error (secret did not contain expected field password).",
			testCase{
				args: args{
					c: &mockSecretCache{
						mockSecretName:  "secret-name",
						mockUsername:    "username",
						includeUsername: true,
					},
					secretName: "secret-name",
				},
				expectedErr: true,
			},
		),
	)

	type swapperTestCase struct {
		args             args
		expectedUsername string
		expectedPassword string
		expectedStatus   int
	}

	DescribeTable("Validate requests for Credential swapper middleware",
		func(tt swapperTestCase) {
			var req, err = http.NewRequest("GET", "/does-not-matter", nil)
			Expect(err).NotTo(HaveOccurred())

			// Create end handler for validation (that executes after the swapper middlewares).
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Expect the Authorization header value to contain the right username and password.
				actualAuthValue := r.Header.Get("Authorization")
				expectedAuthValue := "Basic " + base64.StdEncoding.EncodeToString([]byte(tt.expectedUsername+":"+tt.expectedPassword))
				Expect(actualAuthValue).To(Equal(expectedAuthValue))
			})

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			reqContext := context.WithValue(req.Context(), ESUserKey, &User{Username: tt.expectedUsername})
			middlewareHandler := NewSwapElasticCredMiddlware(tt.args.c)
			handler := middlewareHandler(testHandler)
			handler.ServeHTTP(recorder, req.WithContext(reqContext))

			Expect(recorder.Code).To(Equal(tt.expectedStatus))
		},
		Entry(
			"Should successfully swap username and password.",
			swapperTestCase{
				args: args{
					c: &mockSecretCache{
						mockSecretName:  "username-" + ElasticsearchCredsSecretSuffix,
						mockUsername:    "username",
						includeUsername: true,
						mockPassword:    "passwordHash",
						includePassword: true,
					},
				},
				expectedUsername: "username",
				expectedPassword: "passwordHash",
				expectedStatus:   http.StatusOK,
			},
		),
		Entry(
			"Should return HTTP 401 error due to credentials not being found.",
			swapperTestCase{
				args: args{
					c: &mockSecretCache{
						mockSecretName: "username-" + ElasticsearchCredsSecretSuffix,
					},
				},
				expectedUsername: "different-username",
				expectedStatus:   http.StatusUnauthorized,
			},
		),
	)

})
