// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package config_test

import (
	"os"

	"github.com/kelseyhightower/envconfig"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/voltron/internal/pkg/config"
)

var _ = Describe("Config test", func() {

	const (
		issuer         = "https://example.com"
		jwks           = "https://example.com/.well-known/jwks.json"
		clientid       = "1234"
		enabled        = "true"
		usernameClaim  = "usr"
		groupsClaim    = "grp"
		groupsPrefix   = "g:"
		usernamePrefix = "u:"
	)

	BeforeEach(func() {
		Expect(os.Setenv("VOLTRON_DEX_ENABLED", enabled)).NotTo(HaveOccurred())
		Expect(os.Setenv("VOLTRON_DEX_URL", issuer)).NotTo(HaveOccurred())
		Expect(os.Setenv("VOLTRON_OIDC_AUTH_ISSUER", issuer)).NotTo(HaveOccurred())
		Expect(os.Setenv("VOLTRON_OIDC_AUTH_JWKSURL", jwks)).NotTo(HaveOccurred())
		Expect(os.Setenv("VOLTRON_OIDC_AUTH_CLIENT_ID", clientid)).NotTo(HaveOccurred())
		Expect(os.Setenv("VOLTRON_OIDC_AUTH_USERNAME_CLAIM", usernameClaim)).NotTo(HaveOccurred())
		Expect(os.Setenv("VOLTRON_OIDC_AUTH_USERNAME_PREFIX", usernamePrefix)).NotTo(HaveOccurred())
		Expect(os.Setenv("VOLTRON_OIDC_AUTH_GROUPS_PREFIX", groupsPrefix)).NotTo(HaveOccurred())
		Expect(os.Setenv("VOLTRON_OIDC_AUTH_GROUPS_CLAIM", groupsClaim)).NotTo(HaveOccurred())
		Expect(os.Setenv("VOLTRON_ENABLE_NONCLUSTER_HOST", enabled)).NotTo(HaveOccurred())
	})

	It("should parse the dex config properly", func() {
		cfg := config.Config{}
		err := envconfig.Process("VOLTRON", &cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.DexEnabled).To(BeTrue())
		Expect(cfg.OIDCAuthIssuer).To(Equal(issuer))
		Expect(cfg.DexURL).To(Equal(issuer))
		Expect(cfg.OIDCAuthJWKSURL).To(Equal(jwks))
		Expect(cfg.OIDCAuthClientID).To(Equal(clientid))
		Expect(cfg.OIDCAuthUsernameClaim).To(Equal(usernameClaim))
		Expect(cfg.OIDCAuthUsernamePrefix).To(Equal(usernamePrefix))
		Expect(cfg.OIDCAuthGroupsPrefix).To(Equal(groupsPrefix))
		Expect(cfg.OIDCAuthGroupsClaim).To(Equal(groupsClaim))
	})

	It("should pick up the defaults for client rate limiting", func() {
		cfg := config.Config{}
		err := envconfig.Process("VOLTRON", &cfg)
		var qps float32 = 100.
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.K8sClientQPS).To(Equal(qps))
		Expect(cfg.K8sClientBurst).To(Equal(1000))
	})

	It("should parse the non-cluster host log ingestion environment variable", func() {
		cfg := config.Config{}
		err := envconfig.Process("VOLTRON", &cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.EnableNonclusterHost).To(BeTrue())
	})
})
