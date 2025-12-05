// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package resource

const (
	ElasticsearchConfigMapName     = "tigera-secure-elasticsearch"
	ElasticsearchCertSecret        = "tigera-secure-es-http-certs-public"
	KibanaCertSecret               = "tigera-secure-kb-http-certs-public"
	ESGatewayCertSecret            = "tigera-secure-es-gateway-http-certs-public"
	VoltronLinseedPublicCert       = "calico-voltron-linseed-certs-public"
	LegacyVoltronLinseedPublicCert = "tigera-voltron-linseed-certs-public"
	OperatorNamespace              = "tigera-operator"
	TigeraElasticsearchNamespace   = "tigera-elasticsearch"
	DefaultTSEEInstanceName        = "tigera-secure"
	OIDCUsersConfigMapName         = "tigera-known-oidc-users"
	OIDCUsersEsSecreteName         = "tigera-oidc-users-elasticsearch-credentials"
	LicenseName                    = "default"
	CalicoNamespaceName            = "calico-system"
	ActiveOperatorConfigMapName    = "active-operator"

	// Namespaces for Linseed token
	ComplianceNamespace         = "tigera-compliance"
	IntrusionDetectionNamespace = "tigera-intrusion-detection"
	DPINamespace                = "tigera-dpi"
	FluentdNamespace            = "tigera-fluentd"
)
