// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package middlewares

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/es-gateway/pkg/cache"
)

var _ = Describe("Authentication middleware", func() {
	type args struct {
		value string
	}
	type extractionTestCase struct {
		args             args
		expectedUsername string
		expectedPassword string
		expectedErr      bool
	}
	DescribeTable("Test extracting credentials from request Authorization header string",
		func(tt extractionTestCase) {
			actualUsername, actualPassword, err := extractCredentials(tt.args.value)

			if tt.expectedErr {
				Expect(err).ToNot(BeNil())
			} else {
				Expect(err).To(BeNil())
			}
			Expect(actualUsername).To(Equal(tt.expectedUsername))
			Expect(actualPassword).To(Equal(tt.expectedPassword))
		},
		Entry(
			"Should successfully extract username and password.",
			extractionTestCase{
				args: args{
					value: "Basic dGlnZXJhLWVlLWt1YmUtY29udHJvbGxlcnM6Tmw3THFqcVh1bWV6M21wWA==",
				},
				expectedUsername: "tigera-ee-kube-controllers",
				expectedPassword: "Nl7LqjqXumez3mpX",
				expectedErr:      false,
			},
		),
		Entry(
			"Should return error (bad hash value).",
			extractionTestCase{
				args: args{
					value: "Basic this-is-not-a-proper-hash-value",
				},
				expectedErr: true,
			},
		),
		Entry(
			"Should return error (hash value has incorrect format).",
			extractionTestCase{
				args: args{
					// This hash value is properly encoded but is missing an expected format.
					value: "Basic dGlnZXJhLWVlLWt1YmUtY29udHJvbGxlcnNObDdMcWpxWHVtZXozbXBY",
				},
				expectedErr: true,
			},
		),
	)

	type hashArgs struct {
		c          cache.SecretsCache
		secretName string
	}
	type hashTestCase struct {
		args         hashArgs
		expectedHash string
		expectedErr  bool
	}

	DescribeTable("Test getting hashed ES credentials",
		func(tt hashTestCase) {
			actualHash, err := getHashedESCredentials(tt.args.c, tt.args.secretName)

			if tt.expectedErr {
				Expect(err).ToNot(BeNil())
			} else {
				Expect(err).To(BeNil())
			}
			Expect(actualHash).To(Equal(tt.expectedHash))
		},
		Entry(
			"Should successfully retrieve hash value.",
			hashTestCase{
				args: hashArgs{
					c: &mockSecretCache{
						mockSecretName:  "secret-name",
						mockPassword:    "passwordHash",
						includePassword: true,
					},
					secretName: "secret-name",
				},
				expectedHash: "passwordHash",
				expectedErr:  false,
			},
		),
		Entry(
			"Should return error (failed to retrieve secret).",
			hashTestCase{
				args: hashArgs{
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
			hashTestCase{
				args: hashArgs{
					c: &mockSecretCache{
						mockSecretName:  "secret-name",
						includePassword: false,
					},
					secretName: "secret-name",
				},
				expectedErr: true,
			},
		),
	)

	type authTestCase struct {
		args             hashArgs
		expectedUsername string
		expectedPassword string
		expectedErr      bool
		expectedStatus   int
		includeAuth      bool
	}

	DescribeTable("Validate requests for Authentication middleware",
		func(tt authTestCase) {
			var req, err = http.NewRequest("GET", "/does-not-matter", nil)
			Expect(err).NotTo(HaveOccurred())

			// Create end handler for validation (that executes after the swapper middlewares).
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Expect the request context to contain the right username.
				user, ok := r.Context().Value(ESUserKey).(*User)

				if tt.expectedErr {
					Expect(ok).To(BeFalse())
				} else {
					Expect(ok).To(BeTrue())
				}
				Expect(user.Username).To(Equal(tt.expectedUsername))
			})

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			if tt.includeAuth {
				req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(tt.expectedUsername+":"+tt.expectedPassword)))
			}
			middlewareHandler := NewAuthMiddleware(tt.args.c)
			handler := middlewareHandler(testHandler)
			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(tt.expectedStatus))
		},
		Entry(
			"Should successfully authenticate user and set username into request context.",
			authTestCase{
				args: hashArgs{
					c: &mockSecretCache{
						mockSecretName:  "username-" + ESGatewayPasswordSecretSuffix,
						mockUsername:    "username",
						includeUsername: true,
						mockPassword:    "$2a$04$fapMa3ApFCPd9aLvf25Z2uBLrSlVyIUQQvLUo6824dSEOVRsDv7RO",
						includePassword: true,
					},
				},
				expectedUsername: "username",
				expectedPassword: "passwordHash",
				expectedErr:      false,
				expectedStatus:   http.StatusOK,
				includeAuth:      true,
			},
		),
		Entry(
			"Should return HTTP 401 error due to missing authorization header.",
			authTestCase{
				args: hashArgs{
					c: &mockSecretCache{},
				},
				expectedStatus: http.StatusUnauthorized,
				includeAuth:    false,
			},
		),
		Entry(
			"Should return HTTP 401 error due to missing secret in cache.",
			authTestCase{
				args: hashArgs{
					c: &mockSecretCache{
						mockSecretName:  "username-" + ESGatewayPasswordSecretSuffix,
						mockUsername:    "username",
						includeUsername: true,
						mockPassword:    "$2a$04$fapMa3ApFCPd9aLvf25Z2uBLrSlVyIUQQvLUo6824dSEOVRsDv7RO",
						includePassword: true,
					},
				},
				expectedUsername: "different-username",
				expectedStatus:   http.StatusUnauthorized,
				includeAuth:      false,
			},
		),
		Entry(
			"Should return HTTP 401 error due to password mismatch with cache.",
			authTestCase{
				args: hashArgs{
					c: &mockSecretCache{
						mockSecretName:  "username-" + ESGatewayPasswordSecretSuffix,
						mockUsername:    "username",
						includeUsername: true,
						mockPassword:    "$2a$04$yk6GL75GHV1WqIblFnoaEeveefmeXTKls3hVd9lW78Rh6FfbP.jh.", // This value will not match
						includePassword: true,
					},
				},
				expectedUsername: "username",
				expectedPassword: "passwordHash",
				expectedStatus:   http.StatusUnauthorized,
				includeAuth:      false,
			},
		),
	)

})

// mockSecretCache is mock for the cache.SecretsCache interface to be used for testing.
type mockSecretCache struct {
	mockSecretName     string
	mockPassword       string
	clusterName        string
	includePassword    bool
	mockUsername       string
	includeUsername    bool
	includeClusterName bool
}

// GetSecret implements the cache.SecretsCache interface and returns the expected mock value for the given name.
func (sc *mockSecretCache) GetSecret(name string) (*v1.Secret, error) {
	ok := sc.mockSecretName == name
	if !ok {
		return nil, fmt.Errorf("secret %s not found in cache", name)
	}

	secret := &v1.Secret{
		Data: map[string][]byte{},
	}

	// Only include the actual expected username if flag is true (for testing scenarios).
	if sc.includeUsername {
		secret.Data[SecretDataFieldUsername] = []byte(sc.mockUsername)
	}

	// Only include the actual expected password if flag is true (for testing scenarios).
	if sc.includePassword {
		secret.Data[SecretDataFieldPassword] = []byte(sc.mockPassword)
	}

	if sc.includeClusterName {
		secret.Data[SecretDataFieldClusterName] = []byte(sc.clusterName)
	}

	return secret, nil
}
