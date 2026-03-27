// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package linseed provides e2e test utilities for querying flow logs via the Linseed API
// instead of hitting Elasticsearch directly.
package linseed

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/utils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

const (
	// linseedNamespace is where the Linseed service is deployed.
	linseedNamespace = "tigera-elasticsearch"
	// linseedService is the name of the Linseed Kubernetes service.
	linseedService = "svc/tigera-linseed"
	// linseedLocalPort is the local port used for port-forwarding to Linseed.
	linseedLocalPort = "8444"
	// linseedRemotePort is the service port Linseed listens on.
	linseedRemotePort = "443"
	// linseedBaseURL is the URL used to reach Linseed via port-forward.
	linseedBaseURL = "https://localhost:8444"

	// tokenSecretNamespace is the namespace containing the service account used for Linseed token requests.
	tokenSecretNamespace = "calico-system"
	// testServiceAccount is the SA created by the test with the minimum RBAC needed to query flow logs.
	testServiceAccount = "linseed-e2e-test"
	// testClusterRoleName is the ClusterRole/Binding name for the test SA.
	testClusterRoleName = "linseed-e2e-test"
	// tokenExpirationSeconds is how long the dynamically-requested token is valid.
	tokenExpirationSeconds = int64(3600)

	// clientCertNamespace is the namespace containing the mTLS client certificate for Linseed.
	clientCertNamespace = "calico-system"
	// clientCertSecretName is the secret holding the client TLS certificate and key for Linseed.
	clientCertSecretName = "policy-recommendation-tls"
	// caBundleNamespace is the namespace containing the Tigera CA bundle configmap.
	caBundleNamespace = "calico-system"
	// caBundleConfigMap is the configmap name holding the Tigera CA bundle.
	caBundleConfigMap = "tigera-ca-bundle"
	// caBundleKey is the key within the configmap that holds the CA bundle PEM.
	caBundleKey = "tigera-ca-bundle.crt"

	// defaultCluster is the cluster ID for single-cluster deployments.
	defaultCluster = "cluster"
)

// Client wraps the Linseed Go client for e2e tests.
type Client struct {
	inner lsclient.Client
}

// PortForward sets up port forwarding to the Linseed service and returns a cancel function.
func PortForward() func() {
	stopCh := make(chan time.Time, 1)
	k := utils.Kubectl{}
	k.PortForwardWithPorts(linseedNamespace, linseedService, linseedLocalPort, linseedRemotePort, "", stopCh)

	return func() {
		stopCh <- time.Now()
		close(stopCh)
	}
}

// InitClient creates a Linseed client by creating a test-specific service
// account with the minimum RBAC needed to query flow logs and requesting a
// short-lived bearer token via the Kubernetes TokenRequest API.
func InitClient(f *framework.Framework) *Client {
	// Create the temp dir once, outside the retry loop, to avoid leaking
	// directories if the Eventually retries.
	tmpDir, err := os.MkdirTemp("", "linseed-e2e-*")
	Expect(err).NotTo(HaveOccurred(), "creating temp dir for Linseed credentials")
	ginkgo.DeferCleanup(os.RemoveAll, tmpDir)

	var (
		tokenPath = filepath.Join(tmpDir, "token")
		certPath  = filepath.Join(tmpDir, "tls.crt")
		keyPath   = filepath.Join(tmpDir, "tls.key")
		caPath    = filepath.Join(tmpDir, "ca.crt")
	)

	Eventually(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Resolve a service account with linseed flowlogs access.
		saName, err := ensureLinseedSA(ctx, f)
		if err != nil {
			return err
		}

		// Request a bearer token from the resolved service account.
		expSec := tokenExpirationSeconds
		tokenReq, err := f.ClientSet.CoreV1().ServiceAccounts(tokenSecretNamespace).CreateToken(
			ctx,
			saName,
			&authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					ExpirationSeconds: &expSec,
				},
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			return fmt.Errorf("creating token for %s/%s: %w", tokenSecretNamespace, saName, err)
		}
		if tokenReq.Status.Token == "" {
			return fmt.Errorf("TokenRequest returned an empty token for %s/%s", tokenSecretNamespace, saName)
		}

		// Load the mTLS client certificate and key.
		clientCertSecret, err := f.ClientSet.CoreV1().Secrets(clientCertNamespace).Get(ctx, clientCertSecretName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("getting client cert secret %s/%s: %w", clientCertNamespace, clientCertSecretName, err)
		}

		// Load the Tigera CA bundle.
		caConfigMap, err := f.ClientSet.CoreV1().ConfigMaps(caBundleNamespace).Get(ctx, caBundleConfigMap, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("getting CA bundle configmap %s/%s: %w", caBundleNamespace, caBundleConfigMap, err)
		}

		// Write credentials to temp files for the Linseed rest client.
		for _, w := range []struct {
			path string
			data []byte
		}{
			{tokenPath, []byte(tokenReq.Status.Token)},
			{certPath, clientCertSecret.Data["tls.crt"]},
			{keyPath, clientCertSecret.Data["tls.key"]},
			{caPath, []byte(caConfigMap.Data[caBundleKey])},
		} {
			if err := os.WriteFile(w.path, w.data, 0600); err != nil {
				return fmt.Errorf("writing %s: %w", w.path, err)
			}
		}

		return nil
	}, 30*time.Second, 2*time.Second).Should(Succeed(),
		"Linseed prerequisites (secret %s/%s, configmap %s/%s) did not become available",
		clientCertNamespace, clientCertSecretName,
		caBundleNamespace, caBundleConfigMap)

	c, err := lsclient.NewClient("", rest.Config{
		URL:            linseedBaseURL,
		CACertPath:     caPath,
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
		ServerName:     "tigera-linseed.tigera-elasticsearch.svc",
	}, rest.WithTokenPath(tokenPath))
	Expect(err).NotTo(HaveOccurred(), "creating Linseed client")

	return &Client{inner: c}
}

// ensureLinseedSA creates a test-specific service account in tokenSecretNamespace
// with the minimum RBAC needed to query flow logs via the Linseed API. All
// creates are idempotent (AlreadyExists is ignored).
func ensureLinseedSA(ctx context.Context, f *framework.Framework) (string, error) {
	_, err := f.ClientSet.CoreV1().ServiceAccounts(tokenSecretNamespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testServiceAccount,
			Namespace: tokenSecretNamespace,
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("creating ServiceAccount %s/%s: %w", tokenSecretNamespace, testServiceAccount, err)
	}
	ginkgo.DeferCleanup(func() {
		_ = f.ClientSet.CoreV1().ServiceAccounts(tokenSecretNamespace).Delete(context.Background(), testServiceAccount, metav1.DeleteOptions{})
	})

	// ClusterRole granting read access to linseed flowlogs.
	_, err = f.ClientSet.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: testClusterRoleName},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"flowlogs"},
			Verbs:     []string{"get"},
		}},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("creating ClusterRole %s: %w", testClusterRoleName, err)
	}
	ginkgo.DeferCleanup(func() {
		_ = f.ClientSet.RbacV1().ClusterRoles().Delete(context.Background(), testClusterRoleName, metav1.DeleteOptions{})
	})

	// Bind the ClusterRole to the test SA.
	_, err = f.ClientSet.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: testClusterRoleName},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      testServiceAccount,
			Namespace: tokenSecretNamespace,
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     testClusterRoleName,
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("creating ClusterRoleBinding %s: %w", testClusterRoleName, err)
	}
	ginkgo.DeferCleanup(func() {
		_ = f.ClientSet.RbacV1().ClusterRoleBindings().Delete(context.Background(), testClusterRoleName, metav1.DeleteOptions{})
	})

	return testServiceAccount, nil
}

// WaitForLinseed waits until Linseed is reachable via the port-forward.
func WaitForLinseed(c *Client) {
	httpClient := c.inner.RESTClient().HTTPClient()
	token, err := c.inner.RESTClient().Token()
	Expect(err).NotTo(HaveOccurred(), "reading Linseed token")

	Eventually(func() error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, c.inner.RESTClient().BaseURL()+"/version", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+string(token))
		req.Header.Set("x-cluster-id", defaultCluster)
		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("linseed health check failed: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("linseed returned status %d", resp.StatusCode)
		}
		return nil
	}, 30*time.Second, 2*time.Second).Should(Succeed(), "Linseed did not become reachable")
}

// QueryFlowLogs returns flow logs matching the given Linseed selector string,
// querying logs from the last 10 minutes. It is a low-level helper intended for
// use inside Gomega Eventually blocks; it makes one request and returns immediately.
func QueryFlowLogs(c *Client, selector string) ([]v1.FlowLog, error) {
	params := &v1.FlowLogParams{}
	params.TimeRange = &lmav1.TimeRange{
		From: time.Now().Add(-10 * time.Minute),
		To:   time.Now(),
	}
	params.MaxPageSize = 100
	if selector != "" {
		params.Selector = selector
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := c.inner.FlowLogs(defaultCluster).List(ctx, params)
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}
