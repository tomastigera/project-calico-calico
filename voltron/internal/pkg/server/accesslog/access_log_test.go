// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package accesslog_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/felixge/httpsnoop"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/voltron/internal/pkg/server/accesslog"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/accesslog/test"
)

var _ = Describe("Access Logs", func() {
	const clusterID = "tigera-labs"

	// note these tokens are not valid
	const userToken = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im5tdkJHSWE4YkZvMlZadDhPNnpzMiJ9.eyJodHRwczovL2NhbGljb2Nsb3VkLmlvL2dyb3VwcyI6WyJ0aWdlcmEtYXV0aC1heG5jM2ttNS1hZG1pbiJdLCJodHRwczovL2NhbGljb2Nsb3VkLmlvL29yZyI6InkwbnVjZWk1ZCIsImh0dHBzOi8vY2FsaWNvY2xvdWQuaW8vdGVuYW50SUQiOiJheG5jM2ttNSIsImh0dHBzOi8vY2FsaWNvY2xvdWQuaW8vdXNlcm5hbWUiOiJnb3Jkb24rbWFyMTRAdGlnZXJhLmlvIiwibmlja25hbWUiOiJnb3Jkb24rbWFyMTQiLCJuYW1lIjoiZ29yZG9uK21hcjE0QHRpZ2VyYS5pbyIsInBpY3R1cmUiOiJodHRwczovL3MuZ3JhdmF0YXIuY29tL2F2YXRhci83NTdiODQ3YjZjNTk3NWQ2MmQwMTIzOWU2ZjAyZGMwMD9zPTQ4MCZyPXBnJmQ9aHR0cHMlM0ElMkYlMkZjZG4uYXV0aDAuY29tJTJGYXZhdGFycyUyRmdvLnBuZyIsInVwZGF0ZWRfYXQiOiIyMDIzLTAzLTIxVDA5OjIyOjIwLjc3NFoiLCJlbWFpbCI6ImdvcmRvbittYXIxNEB0aWdlcmEuaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9hdXRoLmRldi5jYWxpY29jbG91ZC5pby8iLCJhdWQiOiJPQTNNUGlvZjl3d1g3MnhweVE4SWd5RWZPZTFxTlVEZyIsImlhdCI6MTY3OTM5MDU0OCwiZXhwIjoxNjc5NDI2NTQ4LCJzdWIiOiJhdXRoMHw2NDEwNjUyZTAxNmEwZDQ5Zjk3YTY3MDQiLCJhdF9oYXNoIjoiWnpyUDNZemQ2Njg2MFNfaGRzd0NDdyIsInNpZCI6IlNtUEJSTXNPazlITGpiY2o4ZklrSDMwdmtKUWlRcDZMIiwibm9uY2UiOiI3MGNmZTFiMzc0MTE0MGQxYTQwNDRmMTk3MWYwMTY3OSJ9.jZN2l9tywr7ZNXkVlVyipB4usuRpXR7eOFAFYo_m3yEMIhDcf87f2X8O6P7TwPAiV1VL3aOTFnHZTHs1wOC-vj8CYqQl07mwqH_DgQQPNFqNp-oSTQa0_JsXXOsgnVGm6NxwsSvPM1jUMYPdgLShv4NXv6ZvDUFwyuYDT9NMOuZW2_5wyfJGAov_ZWT8iSTSTAm9Fhulkz2yPQj3EZ3QKNoq9vuVXaGqXysYWUycViuQvYAJixA4zBToangFpdzD4mavoXmjvQ4bv6gUeO-dgX9uX1OiLtSGr9VIX4Op4Yc1ub4HkD_LXTopHzzaAtgLxhyz"
	const saToken = "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkVlZ2dmU1FsM0Y5NUxzYTBGM01OeDdFUXVUekpUSGowTlEzVk9QanJVTVUifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJ0aWdlcmEtY29tcGxpYW5jZSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJ0aWdlcmEtY29tcGxpYW5jZS1zZXJ2ZXItdG9rZW4tZjl4dHgiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoidGlnZXJhLWNvbXBsaWFuY2Utc2VydmVyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiZDdjMGFmMzAtMmI1Zi00MjQxLWFmOWYtM2E0ZTM2NDZjZGM1Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnRpZ2VyYS1jb21wbGlhbmNlOnRpZ2VyYS1jb21wbGlhbmNlLXNlcnZlciJ9.OlnghOV7Q1-vY6cD1lA3LsavYaazVjYK_wsoCsFWeu78_z0mUbcAs5eUij9TeA7dgnvOpgRPwU2mVo6UDLninWFBHMY6vzUua6T-YiwkEFFtaXXBp13k5puxryiBBBTSJxyVpDnTiY76DPC_zcyMNLh0S1m8hAZ566a2Zh-Kwcdr-Y2Z7H21OF-ViBRQI3vgQxTvMuVoCnES14jK_o1GuY6HMAzyB3pMBFRlzEQqfgXOCSKvfYJ8AE8w1xagHXnEZQn9WYbuRta168sjwLnmKgUG1nrQ6KnHn5nMV5Yfi1AzSN7RvMyAVVH"

	expectedUserTokenAuth := test.AccessLogAuth{
		Iss:      "https://auth.dev.calicocloud.io/",
		Sub:      "auth0|6410652e016a0d49f97a6704",
		Aud:      "OA3MPiof9wwX72xpyQ8IgyEfOe1qNUDg",
		Sid:      "SmPBRMsOk9HLjbcj8fIkH30vkJQiQp6L",
		Nonce:    "70cfe1b3741140d1a4044f1971f01679",
		Username: "gordon+mar14@tigera.io",
		Groups:   []string{"tigera-auth-axnc3km5-admin"},
		TenantID: "axnc3km5",
	}

	expectedSATokenAuth := test.AccessLogAuth{
		Iss: "kubernetes/serviceaccount",
		Sub: "system:serviceaccount:tigera-compliance:tigera-compliance-server",
	}

	logFile, err := os.CreateTemp("", "voltron-access-log")
	Expect(err).ToNot(HaveOccurred())
	defer func() {
		Expect(os.Remove(logFile.Name())).ToNot(HaveOccurred())
	}()

	log.Info("output file: ", logFile.Name())

	accessLogger, err := accesslog.New(
		accesslog.WithPath(logFile.Name()),
		accesslog.WithRequestHeader("x-cluster-id", "xClusterID"),
		accesslog.WithRequestHeader("User-Agent", "userAgent"),
		accesslog.WithRequestHeader("accept", "accept"),
		accesslog.WithRequestHeader("impersonate-group", "impersonateGroup"),
		accesslog.WithStandardJWTClaims(),
		accesslog.WithStringJWTClaim("email", "username"),
		accesslog.WithStringArrayJWTClaim("https://calicocloud.io/groups", "groups"),
		accesslog.WithStringJWTClaim("https://calicocloud.io/tenantID", "ccTenantID"),
		accesslog.WithErrorResponseBodyCaptureSize(10),
	)

	const successPath = "/foo/bar"
	const errorPath = "/foo/baz"

	mux := http.NewServeMux()
	mux.HandleFunc(successPath, func(w http.ResponseWriter, r *http.Request) {
		// voltron deletes headers, so this handler will too
		r.Header.Del("Authorization")
		r.Header.Del("x-cluster-id")
		time.Sleep(5 * time.Millisecond)
		_, _ = w.Write([]byte("hello"))
	})
	mux.HandleFunc(errorPath, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond)
		errMsg := "an error occurred"
		if customMsg := r.Header.Get("errMsg"); customMsg != "" {
			errMsg = customMsg
		}
		http.Error(w, errMsg, http.StatusBadRequest)
	})

	accessLoggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var httpSnoopMetrics httpsnoop.Metrics

		var authToken jwt.JWT
		var authTokenErr error
		if rawAuthToken := authorizationHeaderBearerToken(r); rawAuthToken != "" {
			authToken, authTokenErr = jws.ParseJWT([]byte(rawAuthToken))
		}

		wrappedWriter, loggerEnd := accessLogger.OnRequest(w, r, authToken, authTokenErr)
		defer loggerEnd(&httpSnoopMetrics)

		w = wrappedWriter

		httpSnoopMetrics = httpsnoop.CaptureMetricsFn(w, func(w http.ResponseWriter) {
			mux.ServeHTTP(w, r)
		})
	})
	Expect(err).ToNot(HaveOccurred())

	httpServer := httptest.NewUnstartedServer(accessLoggingHandler)
	httpServer.EnableHTTP2 = true
	httpServer.StartTLS()

	httpClient := httpServer.Client()

	Context("request should log", func() {

		It("a user authenticated request", func() {
			request, err := http.NewRequest(http.MethodGet, httpServer.URL+successPath, nil)
			Expect(err).ToNot(HaveOccurred())

			request.Header.Set("x-cluster-id", clusterID)
			request.Header.Set("authorization", userToken)
			request.Header.Set("accept", "*/*")
			request.Header.Set("Impersonate-Group", "group1")
			request.Header.Add("Impersonate-Group", "group2")

			response, err := httpClient.Do(request)
			Expect(err).ToNot(HaveOccurred())
			Expect(response.StatusCode).To(Equal(http.StatusOK))

			accessLog := flushAndReadLastAccessLog(accessLogger, logFile)
			requireMessageMatches(test.AccessLogMessage{
				Request: test.AccessLogRequest{
					RemoteAddr:       "127.0.0.1:",
					Proto:            "HTTP/2.0",
					Method:           http.MethodGet,
					Host:             httpServer.Listener.Addr().String(),
					Path:             successPath,
					ClusterID:        clusterID,
					UserAgent:        "Go-http-client/2.0",
					Accept:           "*/*",
					ImpersonateGroup: "group1; group2",
					Auth:             expectedUserTokenAuth,
				},
				Response: test.AccessLogResponse{
					Status:       200,
					BytesWritten: 5,
					Body:         "",
				},
			}, accessLog)
		})

		It("a serviceaccount authenticated request", func() {
			request, err := http.NewRequest(http.MethodGet, httpServer.URL+successPath, nil)
			Expect(err).ToNot(HaveOccurred())

			request.Header.Set("authorization", saToken)
			request.Header.Set("accept", "application/json")

			response, err := httpClient.Do(request)
			Expect(err).ToNot(HaveOccurred())
			Expect(response.StatusCode).To(Equal(http.StatusOK))

			accessLog := flushAndReadLastAccessLog(accessLogger, logFile)
			requireMessageMatches(test.AccessLogMessage{
				Request: test.AccessLogRequest{
					RemoteAddr: "127.0.0.1:",
					Proto:      "HTTP/2.0",
					Method:     http.MethodGet,
					Host:       httpServer.Listener.Addr().String(),
					Path:       successPath,
					UserAgent:  "Go-http-client/2.0",
					Accept:     "application/json",
					Auth:       expectedSATokenAuth,
				},
				Response: test.AccessLogResponse{
					Status:       200,
					BytesWritten: 5,
					Body:         "",
				},
			}, accessLog)
		})

		It("a non-authenticated request", func() {
			request, err := http.NewRequest(http.MethodPost, httpServer.URL+successPath, nil)
			Expect(err).ToNot(HaveOccurred())

			response, err := httpClient.Do(request)
			Expect(err).ToNot(HaveOccurred())
			Expect(response.StatusCode).To(Equal(http.StatusOK))

			accessLog := flushAndReadLastAccessLog(accessLogger, logFile)
			requireMessageMatches(test.AccessLogMessage{
				Request: test.AccessLogRequest{
					RemoteAddr: "127.0.0.1:",
					Proto:      "HTTP/2.0",
					Method:     http.MethodPost,
					Host:       httpServer.Listener.Addr().String(),
					Path:       successPath,
					UserAgent:  "Go-http-client/2.0",
					Auth:       test.AccessLogAuth{},
				},
				Response: test.AccessLogResponse{
					Status:       200,
					BytesWritten: 5,
					Body:         "",
				},
			}, accessLog)
		})

		errorResponseTests := []struct {
			name                string
			fullError           string
			expectedLoggedError string
		}{
			// ErrorResponseBodyCaptureSize is set to 10 above
			{
				name:                "error response capture length is larger than the actual response",
				fullError:           "error",
				expectedLoggedError: "error\n",
			},
			{
				name:                "error response capture length is smaller than the actual response",
				fullError:           "error error error",
				expectedLoggedError: "error erro",
			},
			{
				name:                "error response includes non-ascii chars",
				fullError:           "error😀",
				expectedLoggedError: "error😀\n",
			},
			{
				name:                "error response truncates a non-ascii char",
				fullError:           "error  😀",
				expectedLoggedError: "error  ���",
			},
		}

		for _, t := range errorResponseTests {
			var t = t // capture the loop variable
			It(t.name, func() {

				request, err := http.NewRequest(http.MethodDelete, httpServer.URL+errorPath, nil)
				Expect(err).ToNot(HaveOccurred())

				request.Header.Set("authorization", userToken)
				request.Header.Set("errMsg", t.fullError)

				response, err := httpClient.Do(request)
				Expect(err).ToNot(HaveOccurred())
				Expect(response.StatusCode).To(Equal(http.StatusBadRequest))

				accessLog := flushAndReadLastAccessLog(accessLogger, logFile)
				requireMessageMatches(test.AccessLogMessage{
					Request: test.AccessLogRequest{
						RemoteAddr: "127.0.0.1:",
						Proto:      "HTTP/2.0",
						Method:     http.MethodDelete,
						Host:       httpServer.Listener.Addr().String(),
						Path:       errorPath,
						UserAgent:  "Go-http-client/2.0",
						Auth:       expectedUserTokenAuth,
					},
					Response: test.AccessLogResponse{
						Status:       400,
						BytesWritten: len([]byte(t.fullError)) + 1, // +1 for the newline
						Body:         t.expectedLoggedError,
					},
				}, accessLog)
			})
		}

	})
})

func requireMessageMatches(expected, actual test.AccessLogMessage) {
	now := time.Now()
	Expect(actual.Time).To(BeTemporally("<", now), "log timestamp before now")
	Expect(actual.Request.Time).To(BeTemporally("<", actual.Time), "request timestamp before log timestamp")
	Expect(actual.Response.Duration).To(BeNumerically(">", 0.001), "non-zero duration")
	Expect(actual.Response.Duration).To(BeNumerically("<", 1.0), "slept for a few milliseconds, duration in seconds")

	Expect(actual.Request.RemoteAddr).To(HavePrefix(expected.Request.RemoteAddr), "request.remoteAddr")

	Expect(actual.Request.Proto).To(Equal(actual.Request.Proto), "request.proto")
	Expect(actual.Request.Proto).To(Equal(expected.Request.Proto), "request.proto")
	Expect(actual.Request.Method).To(Equal(expected.Request.Method), "request.method")
	Expect(actual.Request.Host).To(Equal(expected.Request.Host), "request.host")
	Expect(actual.Request.Path).To(Equal(expected.Request.Path), "request.path")
	Expect(actual.Request.Query).To(Equal(expected.Request.Query), "request.query")
	Expect(actual.Request.UserAgent).To(Equal(expected.Request.UserAgent), "request.userAgent")
	Expect(actual.Request.ClusterID).To(Equal(expected.Request.ClusterID), "request.clusterID")
	Expect(actual.Request.Accept).To(Equal(expected.Request.Accept), "request.accept")
	Expect(actual.Request.ImpersonateGroup).To(Equal(expected.Request.ImpersonateGroup), "request.impersonateGroup")
	Expect(actual.Request.Auth).To(Equal(expected.Request.Auth), "request.auth")

	Expect(actual.Response.Status).To(Equal(expected.Response.Status), "response.status")
	Expect(actual.Response.BytesWritten).To(Equal(expected.Response.BytesWritten), "response.bytesWritten")
	Expect(actual.Response.Body).To(Equal(expected.Response.Body), "response.body")

	// tls is the same for all requests, avoid repeating it in all callers
	expected.TLS = test.AccessLogTLS{
		Proto:       "h2",
		Version:     772,
		ServerName:  "", // blank in the test request, works in a real env
		CipherSuite: "TLS_AES_128_GCM_SHA256",
	}

	Expect(actual.TLS).To(Equal(expected.TLS), "tls")
}

func flushAndReadLastAccessLog(logger *accesslog.Logger, outputFile *os.File) test.AccessLogMessage {
	logger.Flush()
	logMessage, err := test.ReadLastAccessLog(outputFile)
	Expect(err).ToNot(HaveOccurred())
	return logMessage
}

func authorizationHeaderBearerToken(r *http.Request) string {
	if value := r.Header.Get("Authorization"); len(value) > 7 && strings.EqualFold(value[0:7], "bearer ") {
		return value[7:]
	}
	return ""
}
