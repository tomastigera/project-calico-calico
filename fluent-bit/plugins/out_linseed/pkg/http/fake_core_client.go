// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package http

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v4"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	applyconfcorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	rest "k8s.io/client-go/rest"
)

// fakeCoreV1 implement CoreV1Interface
type fakeCoreV1 struct {
}

func (c *fakeCoreV1) ComponentStatuses() v1.ComponentStatusInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) ConfigMaps(namespace string) v1.ConfigMapInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) Endpoints(namespace string) v1.EndpointsInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) Events(namespace string) v1.EventInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) LimitRanges(namespace string) v1.LimitRangeInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) Namespaces() v1.NamespaceInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) Nodes() v1.NodeInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) PersistentVolumes() v1.PersistentVolumeInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) PersistentVolumeClaims(namespace string) v1.PersistentVolumeClaimInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) Pods(namespace string) v1.PodInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) PodTemplates(namespace string) v1.PodTemplateInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) ReplicationControllers(namespace string) v1.ReplicationControllerInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) ResourceQuotas(namespace string) v1.ResourceQuotaInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) Secrets(namespace string) v1.SecretInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) Services(namespace string) v1.ServiceInterface {
	panic("not implemented")
}

func (c *fakeCoreV1) ServiceAccounts(namespace string) v1.ServiceAccountInterface {
	return newFakeServiceAccounts(c, namespace)
}

func (c *fakeCoreV1) RESTClient() rest.Interface {
	return nil
}

// serviceAccounts implements ServiceAccountInterface
type fakeserviceAccounts struct {
	client rest.Interface
	ns     string
}

// newServiceAccounts returns a ServiceAccounts
func newFakeServiceAccounts(c v1.CoreV1Interface, namespace string) *fakeserviceAccounts {
	return &fakeserviceAccounts{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

func (c *fakeserviceAccounts) Get(ctx context.Context, name string, options metav1.GetOptions) (result *corev1.ServiceAccount, err error) {
	panic("not implemented")
}

func (c *fakeserviceAccounts) List(ctx context.Context, opts metav1.ListOptions) (result *corev1.ServiceAccountList, err error) {
	panic("not implemented")
}

func (c *fakeserviceAccounts) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	panic("not implemented")
}

func (c *fakeserviceAccounts) Create(ctx context.Context, serviceAccount *corev1.ServiceAccount, opts metav1.CreateOptions) (result *corev1.ServiceAccount, err error) {
	panic("not implemented")
}

func (c *fakeserviceAccounts) Update(ctx context.Context, serviceAccount *corev1.ServiceAccount, opts metav1.UpdateOptions) (result *corev1.ServiceAccount, err error) {
	panic("not implemented")
}

func (c *fakeserviceAccounts) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	panic("not implemented")
}

func (c *fakeserviceAccounts) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	panic("not implemented")
}

func (c *fakeserviceAccounts) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *corev1.ServiceAccount, err error) {
	panic("not implemented")
}

func (c *fakeserviceAccounts) Apply(ctx context.Context, serviceAccount *applyconfcorev1.ServiceAccountApplyConfiguration, opts metav1.ApplyOptions) (result *corev1.ServiceAccount, err error) {
	panic("not implemented")
}

func (c *fakeserviceAccounts) CreateToken(ctx context.Context, serviceAccountName string, tokenRequest *authenticationv1.TokenRequest, opts metav1.CreateOptions) (result *authenticationv1.TokenRequest, err error) {
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(time.Hour)
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		Issuer:    "some_issuer",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("some_key"))
	if err != nil {
		panic(err)
	}

	return &authenticationv1.TokenRequest{
		Status: authenticationv1.TokenRequestStatus{
			Token: tokenString,
			ExpirationTimestamp: metav1.Time{
				Time: expiresAt,
			},
		},
	}, nil
}
