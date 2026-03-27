// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package review

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

func TestResolveServer(t *testing.T) {
	RegisterTestingT(t)

	t.Run("returns error when no server configured", func(t *testing.T) {
		RegisterTestingT(t)
		t.Setenv("CALICO_MANAGER_ADDRESS", "")
		args := map[string]interface{}{"--server": nil}
		_, err := resolveServer(args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no server address"))
	})

	t.Run("uses --server flag", func(t *testing.T) {
		RegisterTestingT(t)
		args := map[string]interface{}{"--server": "https://my-server:9443"}
		server, err := resolveServer(args)
		Expect(err).NotTo(HaveOccurred())
		Expect(server).To(Equal("https://my-server:9443"))
	})

	t.Run("falls back to CALICO_MANAGER_ADDRESS env", func(t *testing.T) {
		RegisterTestingT(t)
		t.Setenv("CALICO_MANAGER_ADDRESS", "https://env-server:9443")
		args := map[string]interface{}{"--server": nil}
		server, err := resolveServer(args)
		Expect(err).NotTo(HaveOccurred())
		Expect(server).To(Equal("https://env-server:9443"))
	})

	t.Run("--server takes precedence over env", func(t *testing.T) {
		RegisterTestingT(t)
		t.Setenv("CALICO_MANAGER_ADDRESS", "https://env-server:9443")
		args := map[string]interface{}{"--server": "https://flag-server:9443"}
		server, err := resolveServer(args)
		Expect(err).NotTo(HaveOccurred())
		Expect(server).To(Equal("https://flag-server:9443"))
	})
}

func TestResolveToken(t *testing.T) {
	RegisterTestingT(t)

	t.Run("returns error when no token configured", func(t *testing.T) {
		RegisterTestingT(t)
		t.Setenv("SERVICE_ACCOUNT_TOKEN", "")
		args := map[string]interface{}{"--token": nil, "--token-file": nil}
		_, err := resolveToken(args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no authentication token"))
	})

	t.Run("uses --token flag", func(t *testing.T) {
		RegisterTestingT(t)
		args := map[string]interface{}{"--token": "my-token", "--token-file": nil}
		token, err := resolveToken(args)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal("my-token"))
	})

	t.Run("falls back to SERVICE_ACCOUNT_TOKEN env", func(t *testing.T) {
		RegisterTestingT(t)
		t.Setenv("SERVICE_ACCOUNT_TOKEN", "env-token")
		args := map[string]interface{}{"--token": nil, "--token-file": nil}
		token, err := resolveToken(args)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal("env-token"))
	})

	t.Run("reads --token-file", func(t *testing.T) {
		RegisterTestingT(t)
		tmpFile, err := os.CreateTemp("", "token-*")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		_, err = tmpFile.WriteString("  file-token  \n")
		Expect(err).NotTo(HaveOccurred())
		_ = tmpFile.Close()

		args := map[string]interface{}{"--token": nil, "--token-file": tmpFile.Name()}
		token, err := resolveToken(args)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal("file-token"))
	})

	t.Run("--token-file takes precedence over --token", func(t *testing.T) {
		RegisterTestingT(t)
		tmpFile, err := os.CreateTemp("", "token-*")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		_, err = tmpFile.WriteString("file-token")
		Expect(err).NotTo(HaveOccurred())
		_ = tmpFile.Close()

		args := map[string]interface{}{"--token": "flag-token", "--token-file": tmpFile.Name()}
		token, err := resolveToken(args)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal("file-token"))
	})

	t.Run("returns error for non-existent token file", func(t *testing.T) {
		RegisterTestingT(t)
		args := map[string]interface{}{"--token": nil, "--token-file": "/nonexistent/path/token"}
		_, err := resolveToken(args)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to read token file"))
	})
}

func TestFetchUnusedPolicies(t *testing.T) {
	RegisterTestingT(t)

	createdAt := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	mockResp := &v1.UnusedPoliciesResponse{
		Policies: []v1.UnusedPolicyEntry{
			{
				Kind:         "NetworkPolicy",
				Namespace:    "default",
				Name:         "deny-all",
				Generation:   1,
				CreationTime: &createdAt,
			},
		},
		Rules: []v1.UnusedRuleEntry{
			{
				Kind:         "GlobalNetworkPolicy",
				Name:         "gnp-partial",
				Generation:   2,
				CreationTime: &createdAt,
				UnusedRules: []v1.UnusedRule{
					{Direction: "egress", Index: "0"},
					{Direction: "ingress", Index: "1"},
				},
			},
		},
	}

	t.Run("fetches and parses response successfully", func(t *testing.T) {
		RegisterTestingT(t)
		var capturedAuth string
		var capturedPath string

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAuth = r.Header.Get("Authorization")
			capturedPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mockResp)
		}))
		defer srv.Close()

		from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		to := time.Date(2026, 2, 25, 0, 0, 0, 0, time.UTC)

		resp, err := fetchUnusedPolicies(srv.URL, "test-token", &from, &to, true)
		Expect(err).NotTo(HaveOccurred())
		Expect(capturedAuth).To(Equal("Bearer test-token"))
		Expect(capturedPath).To(Equal("/tigera-elasticsearch/policies/unused"))

		Expect(resp.Policies).To(HaveLen(1))
		Expect(resp.Policies[0].Kind).To(Equal("NetworkPolicy"))
		Expect(resp.Policies[0].Name).To(Equal("deny-all"))

		Expect(resp.Rules).To(HaveLen(1))
		Expect(resp.Rules[0].Name).To(Equal("gnp-partial"))
		Expect(resp.Rules[0].UnusedRules).To(HaveLen(2))
		Expect(resp.Rules[0].UnusedRules[0].Direction).To(Equal("egress"))
		Expect(resp.Rules[0].UnusedRules[0].Index).To(Equal("0"))
	})

	t.Run("passes from/to query params", func(t *testing.T) {
		RegisterTestingT(t)
		var capturedQuery string

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(&v1.UnusedPoliciesResponse{
				Policies: []v1.UnusedPolicyEntry{},
				Rules:    []v1.UnusedRuleEntry{},
			})
		}))
		defer srv.Close()

		from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		to := time.Date(2026, 2, 25, 0, 0, 0, 0, time.UTC)

		_, err := fetchUnusedPolicies(srv.URL, "token", &from, &to, true)
		Expect(err).NotTo(HaveOccurred())
		Expect(capturedQuery).To(ContainSubstring("from=2026-01-01T00%3A00%3A00Z"))
		Expect(capturedQuery).To(ContainSubstring("to=2026-02-25T00%3A00%3A00Z"))
	})

	t.Run("returns error on non-200 status", func(t *testing.T) {
		RegisterTestingT(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}))
		defer srv.Close()

		_, err := fetchUnusedPolicies(srv.URL, "bad-token", nil, nil, true)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("401"))
	})

	t.Run("returns error on invalid JSON", func(t *testing.T) {
		RegisterTestingT(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer srv.Close()

		_, err := fetchUnusedPolicies(srv.URL, "token", nil, nil, true)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to parse response"))
	})

	t.Run("returns error when server is unreachable", func(t *testing.T) {
		RegisterTestingT(t)
		_, err := fetchUnusedPolicies("http://127.0.0.1:1", "token", nil, nil, true)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to connect"))
	})
}

func TestCountUnusedRules(t *testing.T) {
	RegisterTestingT(t)

	Expect(countUnusedRules(nil)).To(Equal(0))
	Expect(countUnusedRules([]v1.UnusedRuleEntry{})).To(Equal(0))
	Expect(countUnusedRules([]v1.UnusedRuleEntry{
		{UnusedRules: []v1.UnusedRule{{Direction: "ingress", Index: "0"}}},
		{UnusedRules: []v1.UnusedRule{{Direction: "egress", Index: "0"}, {Direction: "egress", Index: "1"}}},
	})).To(Equal(3))
}

// captureStdout redirects os.Stdout to a pipe, runs fn, and returns what was printed.
func captureStdout(fn func()) string {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)
	return string(out)
}

// splitRows splits output into rows of whitespace-delimited fields, skipping empty lines.
func splitRows(output string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			rows = append(rows, fields)
		}
	}
	return rows
}

func TestPrintWarnings(t *testing.T) {
	RegisterTestingT(t)

	t.Run("no warnings when no flags set", func(t *testing.T) {
		RegisterTestingT(t)
		resp := &v1.UnusedPoliciesResponse{
			Policies: []v1.UnusedPolicyEntry{{Kind: "NetworkPolicy", Name: "test"}},
		}
		out := captureStdout(func() { printWarnings(resp) })
		Expect(out).To(BeEmpty())
	})

	t.Run("previous gen warning triggers", func(t *testing.T) {
		RegisterTestingT(t)
		resp := &v1.UnusedPoliciesResponse{
			Policies: []v1.UnusedPolicyEntry{
				{Kind: "NetworkPolicy", Name: "test", EvaluatedAtPreviousGeneration: true},
			},
		}
		out := captureStdout(func() { printWarnings(resp) })
		Expect(out).To(ContainSubstring("WARNING: Previous generations evaluated policy detected!"))
	})
}

func TestPrintText(t *testing.T) {
	RegisterTestingT(t)

	t.Run("renders policy and rule tables", func(t *testing.T) {
		RegisterTestingT(t)
		resp := &v1.UnusedPoliciesResponse{
			Policies: []v1.UnusedPolicyEntry{
				{Kind: "NetworkPolicy", Namespace: "default", Name: "deny-all", Generation: 1},
			},
			Rules: []v1.UnusedRuleEntry{
				{
					Kind: "NetworkPolicy", Namespace: "ns", Name: "partial", Generation: 2,
					UnusedRules: []v1.UnusedRule{
						{Direction: "egress", Index: "0"},
						{Direction: "ingress", Index: "1"},
					},
				},
			},
		}
		out := captureStdout(func() {
			err := printText(resp)
			Expect(err).NotTo(HaveOccurred())
		})

		Expect(out).To(ContainSubstring("Unused Policies (1)"))
		Expect(out).To(ContainSubstring("Unused Rules (2)"))

		rows := splitRows(out)
		// Find policy table row: KIND NAMESPACE NAME GENERATION.
		var policyRow []string
		for _, r := range rows {
			if len(r) >= 4 && r[0] == "NetworkPolicy" && r[2] == "deny-all" {
				policyRow = r
				break
			}
		}
		Expect(policyRow).NotTo(BeNil())
		Expect(policyRow).To(Equal([]string{"NetworkPolicy", "default", "deny-all", "1"}))

		// Find rule table row: KIND NAMESPACE NAME GENERATION DIRECTION INDEX.
		var ruleRow []string
		for _, r := range rows {
			if len(r) >= 6 && r[2] == "partial" && r[4] == "Egress" {
				ruleRow = r
				break
			}
		}
		Expect(ruleRow).NotTo(BeNil())
		Expect(ruleRow).To(Equal([]string{"NetworkPolicy", "ns", "partial", "2", "Egress", "0"}))
	})

	t.Run("renders N/A for empty namespace", func(t *testing.T) {
		RegisterTestingT(t)
		resp := &v1.UnusedPoliciesResponse{
			Policies: []v1.UnusedPolicyEntry{
				{Kind: "GlobalNetworkPolicy", Name: "gnp-test", Generation: 1},
			},
			Rules: []v1.UnusedRuleEntry{},
		}
		out := captureStdout(func() {
			err := printText(resp)
			Expect(err).NotTo(HaveOccurred())
		})
		rows := splitRows(out)
		var policyRow []string
		for _, r := range rows {
			if len(r) >= 4 && r[2] == "gnp-test" {
				policyRow = r
				break
			}
		}
		Expect(policyRow).NotTo(BeNil())
		Expect(policyRow[1]).To(Equal("N/A"))
	})
}

func TestUnusedPoliciesE2E(t *testing.T) {
	RegisterTestingT(t)

	createdAt := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	mockResp := &v1.UnusedPoliciesResponse{
		Policies: []v1.UnusedPolicyEntry{
			{
				Kind:                          "NetworkPolicy",
				Namespace:                     "default",
				Name:                          "deny-all",
				Generation:                    1,
				CreationTime:                  &createdAt,
				EvaluatedAtPreviousGeneration: true,
			},
			{
				Kind:         "GlobalNetworkPolicy",
				Name:         "global-unused",
				Generation:   3,
				CreationTime: &createdAt,
			},
		},
		Rules: []v1.UnusedRuleEntry{
			{
				Kind:       "NetworkPolicy",
				Namespace:  "kube-system",
				Name:       "allow-dns",
				Generation: 1,
				UnusedRules: []v1.UnusedRule{
					{Direction: "egress", Index: "0"},
					{Direction: "ingress", Index: "2"},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token-123" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockResp)
	}))
	defer srv.Close()

	t.Run("full e2e with JSON output", func(t *testing.T) {
		RegisterTestingT(t)
		err := UnusedPolicies([]string{
			"review", "unused-policies",
			"--server", srv.URL,
			"--token", "test-token-123",
			"-t", "30d",
			"-o", "json",
		})
		Expect(err).NotTo(HaveOccurred())
	})

	t.Run("full e2e with text output", func(t *testing.T) {
		RegisterTestingT(t)
		err := UnusedPolicies([]string{
			"review", "unused-policies",
			"--server", srv.URL,
			"--token", "test-token-123",
			"-t", "30d",
			"-o", "ps",
		})
		Expect(err).NotTo(HaveOccurred())
	})

	t.Run("auth failure returns error", func(t *testing.T) {
		RegisterTestingT(t)
		err := UnusedPolicies([]string{
			"review", "unused-policies",
			"--server", srv.URL,
			"--token", "wrong-token",
			"-t", "30d",
			"-o", "json",
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("401"))
	})

	t.Run("missing server returns error", func(t *testing.T) {
		RegisterTestingT(t)
		t.Setenv("CALICO_MANAGER_ADDRESS", "")
		err := UnusedPolicies([]string{
			"review", "unused-policies",
			"--token", "test-token-123",
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no server address"))
	})

	t.Run("missing token returns error", func(t *testing.T) {
		RegisterTestingT(t)
		t.Setenv("SERVICE_ACCOUNT_TOKEN", "")
		err := UnusedPolicies([]string{
			"review", "unused-policies",
			"--server", srv.URL,
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no authentication token"))
	})

	t.Run("invalid duration returns error", func(t *testing.T) {
		RegisterTestingT(t)
		err := UnusedPolicies([]string{
			"review", "unused-policies",
			"--server", srv.URL,
			"--token", "test-token-123",
			"-t", "abc",
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid time duration"))
	})

	t.Run("invalid output format returns error", func(t *testing.T) {
		RegisterTestingT(t)
		err := UnusedPolicies([]string{
			"review", "unused-policies",
			"--server", srv.URL,
			"--token", "test-token-123",
			"-o", "yaml",
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid output format"))
	})

	t.Run("token-file works", func(t *testing.T) {
		RegisterTestingT(t)
		tmpFile, err := os.CreateTemp("", "token-*")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		_, err = tmpFile.WriteString("test-token-123\n")
		Expect(err).NotTo(HaveOccurred())
		_ = tmpFile.Close()

		err = UnusedPolicies([]string{
			"review", "unused-policies",
			"--server", srv.URL,
			"--token-file", tmpFile.Name(),
			"-t", "30d",
			"-o", "json",
		})
		Expect(err).NotTo(HaveOccurred())
	})

	t.Run("env var fallback for server and token", func(t *testing.T) {
		RegisterTestingT(t)
		t.Setenv("CALICO_MANAGER_ADDRESS", srv.URL)
		t.Setenv("SERVICE_ACCOUNT_TOKEN", "test-token-123")
		err := UnusedPolicies([]string{
			"review", "unused-policies",
			"-t", "30d",
			"-o", "json",
		})
		Expect(err).NotTo(HaveOccurred())
	})
}
