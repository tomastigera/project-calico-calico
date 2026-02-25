// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

package nonclusterhost

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverserviceaccount "k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	// TigeraIssuer name should match the value of OperatorCSRSignerName in Tigera operator's certificatemanager.
	// See: https://github.com/tigera/operator/blob/b4c2b9b3e7acef144ef8f38929f1ab3321526a05/pkg/controller/certificatemanager/certificatemanager.go#L50
	TigeraIssuer          = "tigera.io/operator-signer"
	TigeraManagerAudience = "tigera-manager"

	currentContextName        = "noncluster-hosts"
	tigeraOperatorNamespace   = "tigera-operator"
	tigeraCAPrivateSecretName = "tigera-ca-private"
)

type ConfigGeneratorOptions struct {
	KubeConfig *rest.Config

	Namespace      string
	ServiceAccount string
	CertFile       string
}

type ConfigGenerator struct {
	dynamicClient dynamic.Interface
	k8sClient     kubernetes.Interface

	options *ConfigGeneratorOptions

	caKey  []byte
	caCert []byte
}

func NewConfigGenerator(opts *ConfigGeneratorOptions) (*ConfigGenerator, error) {
	dynamicClient, err := dynamic.NewForConfig(opts.KubeConfig)
	if err != nil {
		return nil, err
	}

	k8sClient, err := kubernetes.NewForConfig(opts.KubeConfig)
	if err != nil {
		return nil, err
	}

	return &ConfigGenerator{
		dynamicClient: dynamicClient,
		k8sClient:     k8sClient,
		options:       opts,
	}, nil
}

func (c *ConfigGenerator) Generate(ctx context.Context) ([]byte, error) {
	// Extract non-cluster host ingestion endpoint
	endpoint, err := c.extractEndpoint(ctx)
	if err != nil {
		return nil, err
	}

	// Extract the private CA certificate and key for certificate authority data and token
	if err := c.extractPrivateCA(ctx); err != nil {
		return nil, err
	}

	// Read the certificate authority file
	certAuthData, err := c.readCertificateAuthorityData()
	if err != nil {
		return nil, err
	}

	// Generate a JWT token for the service account to be validated by voltron
	token, err := c.createToken(ctx)
	if err != nil {
		return nil, err
	}

	// write the kubeconfig file
	cluster := clientcmdapi.NewCluster()
	cluster.CertificateAuthorityData = certAuthData
	cluster.Server = endpoint

	context := clientcmdapi.NewContext()
	context.Cluster = currentContextName
	context.AuthInfo = c.options.ServiceAccount

	authInfo := clientcmdapi.NewAuthInfo()
	authInfo.Token = token

	config := clientcmdapi.NewConfig()
	config.Clusters[currentContextName] = cluster
	config.AuthInfos[c.options.ServiceAccount] = authInfo
	config.Contexts[currentContextName] = context
	config.CurrentContext = currentContextName

	return clientcmd.Write(*config)
}

func (c *ConfigGenerator) extractEndpoint(ctx context.Context) (string, error) {
	nch, err := GetNonClusterHost(ctx, c.dynamicClient)
	if err != nil {
		return "", err
	}

	endpoint, err := ExtractFromNonClusterHostSpec(nch, "endpoint", nil)
	if err != nil {
		return "", err
	}

	return endpoint, nil
}

func (c *ConfigGenerator) extractPrivateCA(ctx context.Context) error {
	secret, err := c.k8sClient.CoreV1().Secrets(tigeraOperatorNamespace).Get(ctx, tigeraCAPrivateSecretName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	var ok bool
	c.caCert, ok = secret.Data[corev1.TLSCertKey]
	if !ok {
		return fmt.Errorf("CA certificate not found in secret")
	}
	c.caKey, ok = secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return fmt.Errorf("CA key not found in secret")
	}
	return nil
}

func (c *ConfigGenerator) readCertificateAuthorityData() ([]byte, error) {
	if c.options.CertFile != "" {
		data, err := os.ReadFile(c.options.CertFile)
		if err != nil {
			return nil, err
		}
		return data, nil
	}

	return c.caCert, nil
}

type nonClusterHostJWTClaims struct {
	jwt.RegisteredClaims

	// These claims match the legacy Kubernetes service account JWT format.
	// Reference: https://github.com/kubernetes/kubernetes/blob/091f87c10bc3532041b77a783a5f832de5506dc8/pkg/serviceaccount/legacy.go#L58
	ServiceAccountName string `json:"kubernetes.io/serviceaccount/service-account.name"`
	Namespace          string `json:"kubernetes.io/serviceaccount/namespace"`
}

func (c *ConfigGenerator) createToken(ctx context.Context) (string, error) {
	sa, err := c.k8sClient.CoreV1().ServiceAccounts(c.options.Namespace).Get(ctx, c.options.ServiceAccount, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(c.caKey)
	if block == nil {
		return "", errors.New("failed to decode CA private key PEM")
	}
	var pkey any
	var pkcs1Err error
	if pkey, pkcs1Err = x509.ParsePKCS1PrivateKey(block.Bytes); pkcs1Err != nil {
		var pkcs8Err error
		if pkey, pkcs8Err = x509.ParsePKCS8PrivateKey(block.Bytes); pkcs8Err != nil {
			return "", fmt.Errorf("failed to parse CA private key as PKCS1 (%v) or PKCS8 (%v)", pkcs1Err, pkcs8Err)
		}
	}

	privateKey, ok := pkey.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("CA private key is not an RSA private key")
	}

	now := time.Now()
	claims := &nonClusterHostJWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   apiserverserviceaccount.MakeUsername(sa.Namespace, sa.Name),
			Issuer:    TigeraIssuer,
			Audience:  jwt.ClaimStrings{TigeraManagerAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			// FIXME(jiawei): We intentionally left the ExpiresAt field unset so the JWT token remains long-lived now.
			// We need to revisit this decision and defined an appropriate expiration policy once we have clearer
			// requirements from our customers.
		},
		ServiceAccountName: sa.Name,
		Namespace:          sa.Namespace,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}
