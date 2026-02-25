// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
package http

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/sirupsen/logrus"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/fluent-bit/plugins/out_linseed/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
)

const (
	// tokenExpiration controls how often we renew serviceaccount token for log forwarding.
	tokenExpiration = 24 * time.Hour
	// tokenRenewal controls how early do we want to renew the token when it is close to expiry.
	tokenRenewal = 15 * time.Minute
)

type TokenProvider interface {
	Token() (string, error)
	Refresh() (string, error)
}

type Token struct {
	mu        sync.RWMutex
	clientset kubernetes.Interface

	serviceAccountName string
	expiration         time.Time
	token              string
}

func NewToken(cfg *config.Config) (*Token, error) {
	// get service account from the kubeconfig file
	serviceAccountName, err := extractServiceAccountName(cfg.Kubeconfig)
	if err != nil {
		return nil, err
	}
	logrus.Debugf("service_account=%v", serviceAccountName)

	// initialize kubernetes clients
	clientset, err := kubernetes.NewForConfig(cfg.RestConfig)
	if err != nil {
		return nil, err
	}

	return &Token{
		clientset:          clientset,
		serviceAccountName: serviceAccountName,
	}, nil
}

// Token returns the non-cluster host ServiceAccount token for forwarding logs to a cluster.
// Tokens will be renewed every tokenExpiration interval.
func (c *Token) Token() (string, error) {
	c.mu.RLock()
	exp := c.expiration
	tok := c.token
	c.mu.RUnlock()

	if time.Until(exp) < tokenRenewal {
		logrus.Infof("token for serviceaccount %q is due for renewal (expires in %s)", c.serviceAccountName, time.Until(exp).Round(time.Second))
		return c.Refresh()
	}

	return tok, nil
}

func (c *Token) Refresh() (string, error) {
	// Use a full lock for the entire refresh operation to prevent multiple
	// concurrent goroutines from issuing redundant token requests.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check: another goroutine may have already refreshed the token
	// while we were waiting for the lock.
	if time.Until(c.expiration) >= tokenRenewal {
		return c.token, nil
	}

	token, expiration, err := getServiceAccountToken(c.clientset.CoreV1(), resource.CalicoNamespaceName, c.serviceAccountName)
	if err != nil {
		return "", err
	}

	c.expiration = expiration
	c.token = token

	logrus.Infof("successfully refreshed token for serviceaccount %q", c.serviceAccountName)
	return token, nil
}

func extractServiceAccountName(kubeconfig string) (string, error) {
	config, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		return "", err
	}

	currentContext := config.CurrentContext
	if currentContext == "" {
		return "", fmt.Errorf("no current-context set in kubeconfig")
	}

	ctx, exists := config.Contexts[currentContext]
	if !exists {
		return "", fmt.Errorf("context %q not found in kubeconfig", currentContext)
	}
	return ctx.AuthInfo, nil
}

func getServiceAccountToken(coreV1Client v1.CoreV1Interface, namespace, serviceAccountName string) (string, time.Time, error) {
	seconds := int64(tokenExpiration.Seconds())
	tokenRequest := &authv1.TokenRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: namespace,
		},
		Spec: authv1.TokenRequestSpec{
			Audiences:         []string{},
			ExpirationSeconds: &seconds,
		},
	}

	tokenResponse, err := coreV1Client.ServiceAccounts(namespace).CreateToken(context.Background(), serviceAccountName, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return "", time.Time{}, err
	}
	token := tokenResponse.Status.Token
	expiration := tokenResponse.Status.ExpirationTimestamp.Time

	jwtToken, err := jws.ParseJWT([]byte(token))
	if err != nil {
		return "", time.Time{}, err
	}
	if exp, ok := jwtToken.Claims().Expiration(); ok {
		expiration = exp
	}

	return token, expiration, nil
}
