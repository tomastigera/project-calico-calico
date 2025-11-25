// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package token_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	fakecorev1 "k8s.io/client-go/kubernetes/typed/core/v1/fake"
	k8stesting "k8s.io/client-go/testing"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
	"github.com/projectcalico/calico/linseed/pkg/controller/token"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
	"github.com/projectcalico/calico/lma/pkg/k8s"
)

var (
	cs            clientset.Interface
	ctx           context.Context
	privateKey    *rsa.PrivateKey
	factory       *k8s.MockClientSetFactory
	mockK8sClient *k8sfake.Clientset
	mockClientSet testutils.ClientSetSet
	fakeClient    ctrlclient.WithWatch

	tenantName string

	nilUserPtr *user.DefaultInfo

	// Default values for tokens to be created in the tests.
	issuer             string = "testissuer"
	defaultServiceName string = "servicename"
	defaultNamespace   string = "default"
	tokenName          string = "servicename-testissuer-token"
)

func setup(t *testing.T) func() {
	// Hook logrus into testing.T
	config.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

	// Create fake client sets.
	cs = fake.NewSimpleClientset()

	// Generate a private key for the tests.
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Set up expected mock calls. We expect a clientset to be generated for the
	// managed cluster which will be used to check and create a secret.
	mockK8sClient = k8sfake.NewSimpleClientset()
	mockClientSet = testutils.ClientSetSet{mockK8sClient, cs}

	mockK8sClient.CoreV1().(*fakecorev1.FakeCoreV1).PrependReactor("get", "namespaces", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		name := action.(k8stesting.GetAction).GetName()
		if name == "default" {
			namespace := &corev1.Namespace{
				ObjectMeta: v1.ObjectMeta{
					Name: "default",
				},
			}
			return true, namespace, nil
		}
		return false, nil, nil
	})

	// Set up mock reactions for List namespace action.
	// It populates namespaces to reconcile tokens while creating managedcluster informer
	mockK8sClient.CoreV1().(*fakecorev1.FakeCoreV1).PrependReactor("list", "namespaces", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		namespace := &corev1.Namespace{
			ObjectMeta: v1.ObjectMeta{
				Name: defaultNamespace,
			},
		}
		return true, &corev1.NamespaceList{Items: []corev1.Namespace{*namespace}}, nil
	})

	scheme := kscheme.Scheme
	err = v3.AddToScheme(scheme)
	require.NoError(t, err)
	fakeClient = fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	tenantName = "bogustenant"

	nilUserPtr = nil

	// Set up a mock client set factory for the tests.
	factory = k8s.NewMockClientSetFactory(t)

	return func() {
		logCancel()
		cancel()
	}
}

func TestOptions(t *testing.T) {
	t.Run("Should reject invalid user info with no name", func(t *testing.T) {
		uis := []token.UserInfo{{Name: "", Namespace: defaultNamespace}}
		opt := token.WithUserInfos(uis)
		err := opt(nil)
		require.Error(t, err)
	})

	t.Run("Should reject invalid user info with no namespace", func(t *testing.T) {
		uis := []token.UserInfo{{Name: "service", Namespace: ""}}
		opt := token.WithUserInfos(uis)
		err := opt(nil)
		require.Error(t, err)
	})

	t.Run("Should make a new controller when correct options are given", func(t *testing.T) {
		defer setup(t)()
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestMainlineFunction(t *testing.T) {
	testCases := []struct {
		tenantNamespace string
		tenantID        string
		tenantMode      string
	}{
		{"", "", "zero tenant"},
		{"", "tenantA", "single tenant"},
		{"tenant-a", "tenantA", "multi tenant"},
	}
	for _, tc := range testCases {
		testMainlineFunction(t, tc.tenantNamespace, tc.tenantID, tc.tenantMode)
	}
}

var testMainlineFunction = func(t *testing.T, tenantNamespace, tenantID, tenantMode string) {
	t.Run("provision a secret for a service in a connected managed cluster in "+tenantMode, func(t *testing.T) {
		defer setup(t)()

		// Add a managed cluster.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(context.Background(), &mc)
		require.NoError(t, err)

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
			token.WithNamespace(tenantNamespace),
			token.WithTenant(tenantID),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()

		// Expect a token to have been generated. This happens asynchronously, so we need
		// to wait for the controller to finish processing.
		var secret *corev1.Secret
		secretCreated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
		require.Equal(t, tokenName, secret.Name)
		require.Equal(t, defaultNamespace, secret.Namespace)

		// Check generated token
		require.NotNil(t, secret.Data)
		require.NotNil(t, secret.Data["token"])
		jwtToken, err := jws.ParseJWT(secret.Data["token"])
		require.NoError(t, err)
		subject, hasSubject := jwtToken.Claims().Subject()
		require.True(t, hasSubject)
		require.Equal(t, fmt.Sprintf("%s:%s:%s:%s", tenantID, mc.Name, defaultNamespace, defaultServiceName), subject)
	})

	t.Run("provision a secret for a service with a tenant namespace override in a connected managed cluster in "+tenantMode, func(t *testing.T) {
		defer setup(t)()

		// Add a managed cluster.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(context.Background(), &mc)
		require.NoError(t, err)

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace, TenantNamespaceOverride: tenantNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
			token.WithNamespace(tenantNamespace),
			token.WithTenant(tenantID),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()

		// Expect a token to have been generated. This happens asynchronously, so we need
		// to wait for the controller to finish processing.
		var secret *corev1.Secret
		secretCreated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
		require.Equal(t, tokenName, secret.Name)
		require.Equal(t, defaultNamespace, secret.Namespace)

		// Check generated token
		require.NotNil(t, secret.Data)
		require.NotNil(t, secret.Data["token"])
		jwtToken, err := jws.ParseJWT(secret.Data["token"])
		require.NoError(t, err)
		subject, hasSubject := jwtToken.Claims().Subject()
		require.True(t, hasSubject)
		switch tenantMode {
		case "multi tenant":
			require.Equal(t, fmt.Sprintf("%s:%s:%s:%s", tenantID, mc.Name, tenantNamespace, defaultServiceName), subject)
		case "single tenant":
			require.Equal(t, fmt.Sprintf("%s:%s:%s:%s", tenantID, mc.Name, defaultNamespace, defaultServiceName), subject)
		case "zero tenant":
			require.Equal(t, fmt.Sprintf("%s:%s:%s:%s", tenantID, mc.Name, defaultNamespace, defaultServiceName), subject)
		}
	})

	t.Run("provision a secret for a service when a managed cluster becomes connected in "+tenantMode, func(t *testing.T) {
		defer setup(t)()

		// Add a managed cluster - start it off as not connected. We will expect no secret
		// in this case. Then, we'll connect the cluster and make sure a secret is created.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueFalse,
			},
		}
		err := fakeClient.Create(context.Background(), &mc)
		require.NoError(t, err)

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		// No token should be created yet.
		var secret *corev1.Secret
		secretCreated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			return !errors.IsNotFound(err)
		}
		for i := 0; i < 5; i++ {
			require.False(t, secretCreated())
			// Expect the secret to be empty.
			require.NotNil(t, secret)
			require.Equal(t, *secret, corev1.Secret{})
			time.Sleep(1 * time.Second)
		}

		// Mark the cluster as connected. This should eventually trigger creation of the secret.
		mc.Status.Conditions[0].Status = v3.ManagedClusterStatusValueTrue
		err = fakeClient.Update(context.Background(), &mc)

		require.NoError(t, err)
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
		require.Equal(t, tokenName, secret.Name)
		require.Equal(t, defaultNamespace, secret.Namespace)
	})

	t.Run("skip updating an already valid token in "+tenantMode, func(t *testing.T) {
		defer setup(t)()

		// Add a managed cluster.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),

			// Reconcile quickly, so that we can verify the secret isn't updated
			// across several reconciles.
			token.WithReconcilePeriod(50 * time.Millisecond),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		// Expect a token to have been generated. This happens asynchronously, so we need
		// to wait for the controller to finish processing.
		var secret *corev1.Secret
		secretCreated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
		require.Equal(t, tokenName, secret.Name)
		require.Equal(t, defaultNamespace, secret.Namespace)

		// The token should remain the same across multiple reconciles, since it is still valid.
		oldSecret := *secret
		for i := 0; i < 5; i++ {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			require.NoError(t, err)
			require.NotNil(t, secret)
			require.Equal(t, oldSecret, *secret, "Secret changed unexpectedly")
			time.Sleep(1 * time.Second)
		}
	})

	t.Run("update an existing token that isn't valid in "+tenantMode, func(t *testing.T) {
		defer setup(t)()

		// Add a managed cluster.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),

			// Set the reconcile period to be very small so that the controller can reconcile
			// the changes we make to the token. Ideally, the controller would be watching
			// the secret and we wouldn't need this.
			token.WithReconcilePeriod(10 * time.Millisecond),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		// Expect a token to have been generated. This happens asynchronously, so we need
		// to wait for the controller to finish processing.
		var secret *corev1.Secret
		secretCreated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
		require.Equal(t, tokenName, secret.Name)
		require.Equal(t, defaultNamespace, secret.Namespace)

		// Modify the token so that it's no longer valid. The controller should notice that the token is
		// invalid and replace it.
		invalidSecret := *secret
		invalidSecret.Data["token"] = []byte(fmt.Sprintf("%s-modified", invalidSecret.Data["token"]))
		_, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Update(ctx, &invalidSecret, v1.UpdateOptions{})
		require.NoError(t, err)

		// Eventually the secret should be updated back to a valid token by the controller's normal reconcile loop.
		secretUpdated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			if err != nil {
				return false
			}
			if reflect.DeepEqual(*secret, invalidSecret) {
				return false
			}
			return true
		}
		require.Eventually(t, secretUpdated, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("update secrets before they expire in "+tenantMode, func(t *testing.T) {
		defer setup(t)()

		// Add a managed cluster.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),

			// Configure tokens to expire after 50ms. This means we should see several updates
			// over the course of this test.
			token.WithExpiry(50 * time.Millisecond),

			// Set the reconcile period to be very small so that the controller acts faster than
			// the expiry time of the tokens it creates.
			token.WithReconcilePeriod(10 * time.Millisecond),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		// Expect a token to have been generated. This happens asynchronously, so we need
		// to wait for the controller to finish processing.
		var secret *corev1.Secret
		secretCreated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
		require.Equal(t, tokenName, secret.Name)
		require.Equal(t, defaultNamespace, secret.Namespace)

		// Eventually the secret should be updated to a new token due to the approaching expiry.
		secretUpdated := func() bool {
			newSecret, err := mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			if err != nil {
				return false
			}
			if reflect.DeepEqual(secret, newSecret) {
				return false
			}
			return true
		}
		require.Eventually(t, secretUpdated, 5*time.Second, 50*time.Millisecond)
	})

	t.Run("should not retry indefinitely in "+tenantMode, func(t *testing.T) {
		// If the controller fails to create a secret, it should retry a few times and then give up.
		defer setup(t)()

		// Add a managed cluster.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		// Configure the mock client to fail to create secrets, and keep track of the number of attempts.
		mu := sync.Mutex{}
		count := 0
		increment := func() {
			mu.Lock()
			defer mu.Unlock()
			count += 1
		}
		callsEqual := func(expected int) bool {
			mu.Lock()
			defer mu.Unlock()
			return count == expected
		}

		mockK8sClient.CoreV1().(*fakecorev1.FakeCoreV1).PrependReactor("create", "secrets", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			increment()
			return true, &corev1.Secret{}, fmt.Errorf("Error creating secret")
		})

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithExpiry(30 * time.Minute),
			token.WithReconcilePeriod(1 * time.Minute),
			token.WithK8sClient(mockK8sClient),

			// Set a small initial retry period so that we exaust the retries quickly.
			token.WithBaseRetryPeriod(1 * time.Millisecond),
			token.WithMaxRetries(5),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory. We have one clientset for each managed cluster.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		// We should expect 6 total attempts - 5 retries and 1 initial attempt.
		require.Eventually(t, func() bool {
			return callsEqual(6)
		}, 5*time.Second, 10*time.Millisecond)
		for i := 0; i < 5; i++ {
			require.True(t, callsEqual(6))
			time.Sleep(250 * time.Millisecond)
		}
	})

	t.Run("handle simultaneous periodic and triggered reconciles in "+tenantMode, func(t *testing.T) {
		defer setup(t)()

		// Add two managed clusters.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		mc2 := v3.ManagedCluster{}
		mc2.Name = "test-managed-cluster-2"
		mc2.Namespace = tenantNamespace
		mc2.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err = fakeClient.Create(ctx, &mc2)
		require.NoError(t, err)

		// Configure the client to error on attempts to create secrets in the second managed cluster. Because this is constantly erroring,
		// it will result in the kickChan trigger being called repeatedly.
		mockK8sClient2 := k8sfake.NewSimpleClientset()
		mockClientSet2 := testutils.ClientSetSet{mockK8sClient2, cs}
		mockK8sClient2.CoreV1().(*fakecorev1.FakeCoreV1).PrependReactor("create", "secrets", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &corev1.Secret{}, fmt.Errorf("Error creating secret")
		})

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),

			// Configure tokens to expire after 500ms. This means we should see several updates
			// over the course of this test.
			token.WithExpiry(500 * time.Millisecond),

			// Set the reconcile period to be very small so that the controller acts faster than
			// the expiry time of the tokens it creates.
			token.WithReconcilePeriod(100 * time.Millisecond),

			// Set the retry period to be smaller than either, so that we are constantly triggering
			// the kick channel.
			token.WithBaseRetryPeriod(50 * time.Millisecond),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory. We have one clientset for each managed cluster.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("NewClientSetForApplication", mc2.Name).Return(&mockClientSet2, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		// Expect a token to have been generated for the first cluster.
		// This happens asynchronously, so we need to wait for the controller to finish processing.
		var secret *corev1.Secret
		secretCreated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
		require.Equal(t, tokenName, secret.Name)
		require.Equal(t, defaultNamespace, secret.Namespace)

		// Eventually the secret should be updated to a new token due to the approaching expiry.
		secretUpdated := func() bool {
			newSecret, err := mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			require.NoError(t, err)
			return !reflect.DeepEqual(secret, newSecret)
		}
		require.Eventually(t, secretUpdated, 5*time.Second, 50*time.Millisecond)
	})

	t.Run("should not reconcile the deleted managed cluster in "+tenantMode, func(t *testing.T) {
		defer setup(t)()

		reconcilePeriod := 100 * time.Millisecond
		// Add two managed clusters.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		mc2 := v3.ManagedCluster{}
		mc2.Name = "test-managed-cluster-2"
		mc2.Namespace = tenantNamespace
		mc2.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err = fakeClient.Create(ctx, &mc2)
		require.NoError(t, err)

		// Configure the client to error on attempts to create secrets in the second managed cluster. Because this is constantly erroring,
		// it will result in the kickChan trigger being called repeatedly.
		mockK8sClient2 := k8sfake.NewSimpleClientset()
		mockClientSet2 := testutils.ClientSetSet{mockK8sClient2, cs}
		mockK8sClient2.CoreV1().(*fakecorev1.FakeCoreV1).PrependReactor("create", "secrets", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &corev1.Secret{}, fmt.Errorf("Error creating secret")
		})

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),

			// Configure tokens to expire after 500ms. This means we should see several updates
			// over the course of this test.
			token.WithExpiry(500 * time.Millisecond),

			// Set the reconcile period to be very small so that the controller acts faster than
			// the expiry time of the tokens it creates.
			token.WithReconcilePeriod(reconcilePeriod),

			// Set the retry period to be smaller than either, so that we are constantly triggering
			// the kick channel.
			token.WithBaseRetryPeriod(50 * time.Millisecond),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory. We have one clientset for each managed cluster.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("NewClientSetForApplication", mc2.Name).Return(&mockClientSet2, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		// Expect a token to have been generated for the first cluster.
		// This happens asynchronously, so we need to wait for the controller to finish processing.
		var secret *corev1.Secret
		secretCreated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
		require.Equal(t, tokenName, secret.Name)
		require.Equal(t, defaultNamespace, secret.Namespace)

		// Eventually the secret should be updated to a new token due to the approaching expiry.
		var newSecret *corev1.Secret
		secretUpdated := func() bool {
			newSecret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			require.NoError(t, err)
			return !reflect.DeepEqual(secret, newSecret)
		}
		require.Eventually(t, secretUpdated, 5*time.Second, 50*time.Millisecond)

		err = fakeClient.Delete(ctx, &mc)
		require.NoError(t, err)

		err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-managed-cluster", Namespace: tenantNamespace}, &v3.ManagedCluster{})
		require.Error(t, err)

		// move the newSecret to secret to validate next generated secret is not copied after managed cluster deletion.
		secret = newSecret

		// new secrets will not be copied/reconciled for the deleted cluster
		for i := 0; i < 5; i++ {
			require.False(t, secretUpdated())
			time.Sleep(reconcilePeriod)
		}
	})

	t.Run("should not reconcile the disconnected managed cluster in "+tenantMode, func(t *testing.T) {
		defer setup(t)()

		reconcilePeriod := 100 * time.Millisecond
		// Add two managed clusters.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		mc2 := v3.ManagedCluster{}
		mc2.Name = "test-managed-cluster-2"
		mc2.Namespace = tenantNamespace
		mc2.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err = fakeClient.Create(ctx, &mc2)
		require.NoError(t, err)

		// Configure the client to error on attempts to create secrets in the second managed cluster. Because this is constantly erroring,
		// it will result in the kickChan trigger being called repeatedly.
		mockK8sClient2 := k8sfake.NewSimpleClientset()
		mockClientSet2 := testutils.ClientSetSet{mockK8sClient2, cs}
		mockK8sClient2.CoreV1().(*fakecorev1.FakeCoreV1).PrependReactor("create", "secrets", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &corev1.Secret{}, fmt.Errorf("Error creating secret")
		})

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),

			// Configure tokens to expire after 500ms. This means we should see several updates
			// over the course of this test.
			token.WithExpiry(500 * time.Millisecond),

			// Set the reconcile period to be very small so that the controller acts faster than
			// the expiry time of the tokens it creates.
			token.WithReconcilePeriod(reconcilePeriod),

			// Set the retry period to be smaller than either, so that we are constantly triggering
			// the kick channel.
			token.WithBaseRetryPeriod(50 * time.Millisecond),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory. We have one clientset for each managed cluster.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("NewClientSetForApplication", mc2.Name).Return(&mockClientSet2, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		// Expect a token to have been generated for the first cluster.
		// This happens asynchronously, so we need to wait for the controller to finish processing.
		var secret *corev1.Secret
		secretCreated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
		require.Equal(t, tokenName, secret.Name)
		require.Equal(t, defaultNamespace, secret.Namespace)

		// Eventually the secret should be updated to a new token due to the approaching expiry.
		var newSecret *corev1.Secret
		secretUpdated := func() bool {
			newSecret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			require.NoError(t, err)
			return !reflect.DeepEqual(secret, newSecret)
		}
		require.Eventually(t, secretUpdated, 5*time.Second, 50*time.Millisecond)

		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueFalse,
			},
		}
		err = fakeClient.Update(ctx, &mc)
		require.NoError(t, err)

		// move the newSecret to secret to validate next generated secret is not copied after managed cluster deletion.
		secret = newSecret

		// new secrets will not be copied/reconciled for the disconnected cluster
		for i := 0; i < 5; i++ {
			require.False(t, secretUpdated())
			time.Sleep(reconcilePeriod)
		}
	})

	t.Run("verify VoltronLinseedCert propagation from management cluster to managed cluster due to periodic update in "+tenantMode+"no cluster information present", func(t *testing.T) {
		defer setup(t)()

		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		operatorNS := "test-operator-ns"
		err = os.Setenv("MANAGEMENT_OPERATOR_NS", operatorNS)
		require.NoError(t, err)

		voltronLinseedSecret := corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      resource.VoltronLinseedPublicCert,
				Namespace: operatorNS,
			},
		}
		secretsToCopy := []corev1.Secret{
			voltronLinseedSecret,
		}

		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
			token.WithReconcilePeriod(1 * time.Second),
			token.WithSecretsToCopy(secretsToCopy),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		managedClientSet := testutils.ClientSetSet{
			k8sfake.NewSimpleClientset(),
			fake.NewSimpleClientset(),
		}

		factory.On("NewClientSetForApplication", mc.Name).Return(&managedClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		createdSecret, err := mockK8sClient.CoreV1().Secrets(operatorNS).Create(ctx, &voltronLinseedSecret, v1.CreateOptions{})
		require.NoError(t, err)
		require.NotNil(t, createdSecret)

		// Reconcile
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()

			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()

		managedOperatorNS, err := utils.FetchOperatorNamespace(managedClientSet)
		require.NoError(t, err)

		secretCreated := func() bool {
			_, err = managedClientSet.CoreV1().Secrets(managedOperatorNS).Get(ctx, resource.VoltronLinseedPublicCertOld, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("verify VoltronLinseedCert propagation from management cluster to managed cluster due to periodic update in "+tenantMode+"no version skew", func(t *testing.T) {
		defer setup(t)()

		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		operatorNS := "test-operator-ns"
		err = os.Setenv("MANAGEMENT_OPERATOR_NS", operatorNS)
		require.NoError(t, err)

		voltronLinseedSecret := corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      resource.VoltronLinseedPublicCert,
				Namespace: operatorNS,
			},
		}
		secretsToCopy := []corev1.Secret{
			voltronLinseedSecret,
		}

		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
			token.WithReconcilePeriod(1 * time.Second),
			token.WithSecretsToCopy(secretsToCopy),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		managedClientSet := testutils.ClientSetSet{
			k8sfake.NewSimpleClientset(),
			fake.NewSimpleClientset(),
		}

		factory.On("NewClientSetForApplication", mc.Name).Return(&managedClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		createdSecret, err := mockK8sClient.CoreV1().Secrets(operatorNS).Create(ctx, &voltronLinseedSecret, v1.CreateOptions{})
		require.NoError(t, err)
		require.NotNil(t, createdSecret)

		ci := v3.ClusterInformation{
			ObjectMeta: v1.ObjectMeta{
				Name: "default",
			},
			Spec: v3.ClusterInformationSpec{
				CalicoEnterpriseVersion: "v3.23.0",
			},
		}
		clusterInformation, err := managedClientSet.ProjectcalicoV3().ClusterInformations().Create(ctx, &ci, v1.CreateOptions{})
		require.NoError(t, err)
		require.NotNil(t, clusterInformation)

		// Reconcile
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()

			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()

		managedOperatorNS, err := utils.FetchOperatorNamespace(managedClientSet)
		require.NoError(t, err)

		secretCreated := func() bool {
			_, err = managedClientSet.CoreV1().Secrets(managedOperatorNS).Get(ctx, resource.VoltronLinseedPublicCert, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("verify VoltronLinseedCert propagation from management cluster to managed cluster due to periodic update in "+tenantMode+"with version skew", func(t *testing.T) {
		defer setup(t)()

		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		operatorNS := "test-operator-ns"
		err = os.Setenv("MANAGEMENT_OPERATOR_NS", operatorNS)
		require.NoError(t, err)

		voltronLinseedSecret := corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      resource.VoltronLinseedPublicCert,
				Namespace: operatorNS,
			},
		}
		secretsToCopy := []corev1.Secret{
			voltronLinseedSecret,
		}

		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
			token.WithReconcilePeriod(1 * time.Second),
			token.WithSecretsToCopy(secretsToCopy),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		managedClientSet := testutils.ClientSetSet{
			k8sfake.NewSimpleClientset(),
			fake.NewSimpleClientset(),
		}

		factory.On("NewClientSetForApplication", mc.Name).Return(&managedClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		createdSecret, err := mockK8sClient.CoreV1().Secrets(operatorNS).Create(ctx, &voltronLinseedSecret, v1.CreateOptions{})
		require.NoError(t, err)
		require.NotNil(t, createdSecret)

		ci := v3.ClusterInformation{
			ObjectMeta: v1.ObjectMeta{
				Name: "default",
			},
			Spec: v3.ClusterInformationSpec{
				CalicoEnterpriseVersion: "v3.19.0",
			},
		}
		clusterInformation, err := managedClientSet.ProjectcalicoV3().ClusterInformations().Create(ctx, &ci, v1.CreateOptions{})
		require.NoError(t, err)
		require.NotNil(t, clusterInformation)

		// Reconcile
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()

			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()

		managedOperatorNS, err := utils.FetchOperatorNamespace(managedClientSet)
		require.NoError(t, err)

		secretCreated := func() bool {
			_, err = managedClientSet.CoreV1().Secrets(managedOperatorNS).Get(ctx, resource.VoltronLinseedPublicCertOld, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("verify VoltronLinseedCert propagation from management cluster to managed cluster due to secret update in "+tenantMode+"no cluster information present", func(t *testing.T) {
		defer setup(t)()

		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		operatorNS := "test-operator-ns"
		err = os.Setenv("MANAGEMENT_OPERATOR_NS", operatorNS)
		require.NoError(t, err)

		voltronLinseedSecret := corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      resource.VoltronLinseedPublicCert,
				Namespace: operatorNS,
			},
			StringData: map[string]string{
				"key": "original-data",
			},
		}
		secretsToCopy := []corev1.Secret{
			voltronLinseedSecret,
		}

		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
			token.WithReconcilePeriod(24 * time.Hour), // Make update period long enough that we're guaranteed not to trigger it during test
			token.WithSecretsToCopy(secretsToCopy),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		managedClientSet := testutils.ClientSetSet{
			k8sfake.NewSimpleClientset(),
			fake.NewSimpleClientset(),
		}

		factory.On("NewClientSetForApplication", mc.Name).Return(&managedClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		createdSecret, err := mockK8sClient.CoreV1().Secrets(operatorNS).Create(ctx, &voltronLinseedSecret, v1.CreateOptions{})
		require.NoError(t, err)
		require.NotNil(t, createdSecret)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		managedOperatorNS, err := utils.FetchOperatorNamespace(managedClientSet)
		require.NoError(t, err)

		// The controller will eventually cause the VoltronLinseedPublicCert to get copied into the managed cluster by
		// way of the ManagedCluster creation update. Wait for this to occur then update the data in the secret to make
		// sure we update correctly based on changes to the secret itself.
		originalSecretCreated := func() bool {
			_, err = managedClientSet.CoreV1().Secrets(managedOperatorNS).Get(ctx, resource.VoltronLinseedPublicCertOld, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, originalSecretCreated, 5*time.Second, 100*time.Millisecond)

		// Update voltronLinseedSecret to trigger copy process
		updatedVoltronLinseedSecretData := "updated-data"
		updatedVoltronLinseedSecret := voltronLinseedSecret.DeepCopy()
		updatedVoltronLinseedSecret.StringData["key"] = updatedVoltronLinseedSecretData
		updatedSecret, err := mockK8sClient.CoreV1().Secrets(operatorNS).Update(ctx, updatedVoltronLinseedSecret, v1.UpdateOptions{})
		require.NoError(t, err)
		require.NotNil(t, updatedSecret)

		// Now verify that voltronLinseedSecret has been copied with updated data
		secretUpdated := func() bool {
			updatedSecret, err = managedClientSet.CoreV1().Secrets(managedOperatorNS).Get(ctx, resource.VoltronLinseedPublicCertOld, v1.GetOptions{})
			return updatedSecret.StringData["key"] == updatedVoltronLinseedSecretData
		}
		require.Eventually(t, secretUpdated, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("verify VoltronLinseedCert propagation from management cluster to managed cluster due to secret update in "+tenantMode+"no version skew", func(t *testing.T) {
		defer setup(t)()

		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		operatorNS := "test-operator-ns"
		err = os.Setenv("MANAGEMENT_OPERATOR_NS", operatorNS)
		require.NoError(t, err)

		voltronLinseedSecret := corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      resource.VoltronLinseedPublicCert,
				Namespace: operatorNS,
			},
			StringData: map[string]string{
				"key": "original-data",
			},
		}
		secretsToCopy := []corev1.Secret{
			voltronLinseedSecret,
		}

		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
			token.WithReconcilePeriod(24 * time.Hour), // Make update period long enough that we're guaranteed not to trigger it during test
			token.WithSecretsToCopy(secretsToCopy),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		managedClientSet := testutils.ClientSetSet{
			k8sfake.NewSimpleClientset(),
			fake.NewSimpleClientset(),
		}

		factory.On("NewClientSetForApplication", mc.Name).Return(&managedClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		createdSecret, err := mockK8sClient.CoreV1().Secrets(operatorNS).Create(ctx, &voltronLinseedSecret, v1.CreateOptions{})
		require.NoError(t, err)
		require.NotNil(t, createdSecret)

		ci := v3.ClusterInformation{
			ObjectMeta: v1.ObjectMeta{
				Name: "default",
			},
			Spec: v3.ClusterInformationSpec{
				CalicoEnterpriseVersion: "v3.23.0",
			},
		}
		clusterInformation, err := managedClientSet.ProjectcalicoV3().ClusterInformations().Create(ctx, &ci, v1.CreateOptions{})
		require.NoError(t, err)
		require.NotNil(t, clusterInformation)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		managedOperatorNS, err := utils.FetchOperatorNamespace(managedClientSet)
		require.NoError(t, err)

		// The controller will eventually cause the VoltronLinseedPublicCert to get copied into the managed cluster by
		// way of the ManagedCluster creation update. Wait for this to occur then update the data in the secret to make
		// sure we update correctly based on changes to the secret itself.
		originalSecretCreated := func() bool {
			_, err = managedClientSet.CoreV1().Secrets(managedOperatorNS).Get(ctx, resource.VoltronLinseedPublicCert, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, originalSecretCreated, 5*time.Second, 100*time.Millisecond)

		// Update voltronLinseedSecret to trigger copy process
		updatedVoltronLinseedSecretData := "updated-data"
		updatedVoltronLinseedSecret := voltronLinseedSecret.DeepCopy()
		updatedVoltronLinseedSecret.StringData["key"] = updatedVoltronLinseedSecretData
		updatedSecret, err := mockK8sClient.CoreV1().Secrets(operatorNS).Update(ctx, updatedVoltronLinseedSecret, v1.UpdateOptions{})
		require.NoError(t, err)
		require.NotNil(t, updatedSecret)

		// Now verify that voltronLinseedSecret has been copied with updated data
		secretUpdated := func() bool {
			updatedSecret, err = managedClientSet.CoreV1().Secrets(managedOperatorNS).Get(ctx, resource.VoltronLinseedPublicCert, v1.GetOptions{})
			return updatedSecret.StringData["key"] == updatedVoltronLinseedSecretData
		}
		require.Eventually(t, secretUpdated, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("verify VoltronLinseedCert propagation from management cluster to managed cluster due to secret update in "+tenantMode+"with version skew", func(t *testing.T) {
		defer setup(t)()

		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		operatorNS := "test-operator-ns"
		err = os.Setenv("MANAGEMENT_OPERATOR_NS", operatorNS)
		require.NoError(t, err)

		voltronLinseedSecret := corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      resource.VoltronLinseedPublicCert,
				Namespace: operatorNS,
			},
			StringData: map[string]string{
				"key": "original-data",
			},
		}
		secretsToCopy := []corev1.Secret{
			voltronLinseedSecret,
		}

		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
			token.WithReconcilePeriod(24 * time.Hour), // Make update period long enough that we're guaranteed not to trigger it during test
			token.WithSecretsToCopy(secretsToCopy),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		managedClientSet := testutils.ClientSetSet{
			k8sfake.NewSimpleClientset(),
			fake.NewSimpleClientset(),
		}

		factory.On("NewClientSetForApplication", mc.Name).Return(&managedClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		createdSecret, err := mockK8sClient.CoreV1().Secrets(operatorNS).Create(ctx, &voltronLinseedSecret, v1.CreateOptions{})
		require.NoError(t, err)
		require.NotNil(t, createdSecret)

		ci := v3.ClusterInformation{
			ObjectMeta: v1.ObjectMeta{
				Name: "default",
			},
			Spec: v3.ClusterInformationSpec{
				CalicoEnterpriseVersion: "v3.19.0",
			},
		}
		clusterInformation, err := managedClientSet.ProjectcalicoV3().ClusterInformations().Create(ctx, &ci, v1.CreateOptions{})
		require.NoError(t, err)
		require.NotNil(t, clusterInformation)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		managedOperatorNS, err := utils.FetchOperatorNamespace(managedClientSet)
		require.NoError(t, err)

		// The controller will eventually cause the VoltronLinseedPublicCert to get copied into the managed cluster by
		// way of the ManagedCluster creation update. Wait for this to occur then update the data in the secret to make
		// sure we update correctly based on changes to the secret itself.
		originalSecretCreated := func() bool {
			_, err = managedClientSet.CoreV1().Secrets(managedOperatorNS).Get(ctx, resource.VoltronLinseedPublicCertOld, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, originalSecretCreated, 5*time.Second, 100*time.Millisecond)

		// Update voltronLinseedSecret to trigger copy process
		updatedVoltronLinseedSecretData := "updated-data"
		updatedVoltronLinseedSecret := voltronLinseedSecret.DeepCopy()
		updatedVoltronLinseedSecret.StringData["key"] = updatedVoltronLinseedSecretData
		updatedSecret, err := mockK8sClient.CoreV1().Secrets(operatorNS).Update(ctx, updatedVoltronLinseedSecret, v1.UpdateOptions{})
		require.NoError(t, err)
		require.NotNil(t, updatedSecret)

		// Now verify that voltronLinseedSecret has been copied with updated data
		secretUpdated := func() bool {
			updatedSecret, err = managedClientSet.CoreV1().Secrets(managedOperatorNS).Get(ctx, resource.VoltronLinseedPublicCertOld, v1.GetOptions{})
			return updatedSecret.StringData["key"] == updatedVoltronLinseedSecretData
		}
		require.Eventually(t, secretUpdated, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("update token for service if it contains outdated subject"+tenantMode, func(t *testing.T) {
		defer setup(t)()

		// Add a managed cluster.
		oldManagedCluster := v3.ManagedCluster{}
		oldManagedCluster.Name = "old-managed-cluster"
		oldManagedCluster.Namespace = tenantNamespace
		oldManagedCluster.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &oldManagedCluster)
		require.NoError(t, err)

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),

			// Set the reconcile period to be very small so that the controller can reconcile
			// the changes we make to the ManagedClusters
			token.WithReconcilePeriod(10 * time.Millisecond),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{defaultNamespace}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory.
		factory.On("NewClientSetForApplication", oldManagedCluster.Name).Return(&mockClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		// Expect a token to have been generated. This happens asynchronously, so we need
		// to wait for the controller to finish processing.
		var secret *corev1.Secret
		secretCreated := func() bool {
			secret, err = mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			return err == nil
		}
		require.Eventually(t, secretCreated, 5*time.Second, 100*time.Millisecond)

		tokenBytes := secret.Data["token"]
		tkn, err := jws.ParseJWT(tokenBytes)
		require.NoError(t, err)

		expectedTokenSubject := fmt.Sprintf("%s:%s:%s:%s", "", oldManagedCluster.Name, defaultNamespace, defaultServiceName)

		subj, ok := tkn.Claims().Subject()
		require.True(t, ok)
		require.Equal(t, subj, expectedTokenSubject)
		require.Equal(t, tokenName, secret.Name)
		require.Equal(t, defaultNamespace, secret.Namespace)

		// Now delete the ManagedCluster
		err = fakeClient.Delete(ctx, &oldManagedCluster)
		require.NoError(t, err)

		newManagedCluster := v3.ManagedCluster{}
		newManagedCluster.Name = "new-managed-cluster"
		newManagedCluster.Namespace = tenantNamespace
		newManagedCluster.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		factory.On("NewClientSetForApplication", newManagedCluster.Name).Return(&mockClientSet, nil)
		err = fakeClient.Create(ctx, &newManagedCluster)
		require.NoError(t, err)

		tokenUpdated := func() bool {
			tokenSecret, err := mockK8sClient.CoreV1().Secrets(defaultNamespace).Get(ctx, tokenName, v1.GetOptions{})
			require.NoError(t, err)
			tokenBytes = tokenSecret.Data["token"]
			jwt, err := jws.ParseJWT(tokenBytes)
			require.NoError(t, err)

			newTokenSubject := token.GenerateSubjectLinseed("", newManagedCluster.Name, defaultNamespace, defaultServiceName, "")
			subj, ok = jwt.Claims().Subject()
			require.True(t, ok)
			return subj == newTokenSubject
		}
		require.Eventually(t, tokenUpdated, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("provision multiple secrets for different services in a connected managed cluster in"+tenantMode, func(t *testing.T) {
		defer setup(t)()

		// Add a managed cluster.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = tenantNamespace
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(context.Background(), &mc)
		require.NoError(t, err)

		tokens := []token.UserInfo{
			{Name: "secret-a", Namespace: "ns-a"},
			{Name: "failing-secret-b", Namespace: "ns-b"},
			{Name: "secret-c", Namespace: "ns-c"},
		}

		mockK8sClient.CoreV1().(*fakecorev1.FakeCoreV1).PrependReactor("get", "namespaces", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			name := action.(k8stesting.GetAction).GetName()

			if name == "ns-a" || name == "ns-b" || name == "ns-c" {
				namespace := &corev1.Namespace{
					ObjectMeta: v1.ObjectMeta{
						Name: name,
					},
				}
				return true, namespace, nil
			}
			return false, nil, nil
		})

		mockK8sClient.CoreV1().(*fakecorev1.FakeCoreV1).PrependReactor("get", "secrets", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			name := action.(k8stesting.GetAction).GetName()

			// We configure a failure when creating the second secret
			if name == "failing-secret-b-testissuer-token" {
				return true, nil, fmt.Errorf("Error getting secret")
			}

			return false, &corev1.Secret{}, nil
		})

		mockK8sClient.CoreV1().(*fakecorev1.FakeCoreV1).PrependReactor("list", "namespaces", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			namespaceNames := []string{"ns-a", "ns-b", "ns-c"}
			namespaces := []corev1.Namespace{}

			for _, name := range namespaceNames {
				namespace := corev1.Namespace{
					ObjectMeta: v1.ObjectMeta{
						Name: name,
					},
				}
				namespaces = append(namespaces, namespace)
			}

			namespaceList := &corev1.NamespaceList{
				Items: namespaces,
			}

			// Return the mocked response
			return true, namespaceList, nil
		})

		// Make a new controller.
		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos(tokens),
			token.WithFactory(factory),
			token.WithK8sClient(mockK8sClient),
			token.WithNamespace(tenantNamespace),
			token.WithLinseedTokenTargetNamespaces([]string{"ns-a", "ns-b", "ns-c"}),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		// Set the mock client set as the return value for the factory.
		factory.On("NewClientSetForApplication", mc.Name).Return(&mockClientSet, nil)
		factory.On("Impersonate", nilUserPtr).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		// Expect a token to have been generated. This happens asynchronously, so we need
		// to wait for the controller to finish processing.
		secretCreated := func(ns, name string) bool {
			_, err = mockK8sClient.CoreV1().Secrets(ns).Get(ctx, name, v1.GetOptions{})
			return err == nil
		}

		require.Eventually(t, func() bool {
			return secretCreated("ns-a", "secret-a-testissuer-token")
		}, 5*time.Minute, 100*time.Millisecond)
		require.Eventually(t, func() bool {
			return secretCreated("ns-c", "secret-c-testissuer-token")
		}, 5*time.Second, 100*time.Millisecond)
		require.Eventually(t, func() bool {
			return !secretCreated("ns-b", "failing-secret-b-testissuer-token")
		}, 5*time.Second, 100*time.Millisecond)

	})
}

func TestMultiTenant(t *testing.T) {
	t.Run("verify Impersonation headers are added", func(t *testing.T) {
		defer setup(t)()

		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		mc.Namespace = "tenant-a"
		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}
		err := fakeClient.Create(ctx, &mc)
		require.NoError(t, err)

		impersonationInfo := user.DefaultInfo{
			Name: tenantName,
			Groups: []string{
				serviceaccount.AllServiceAccountsGroup,
				"system:authenticated",
				fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, "tigera-elasticsearch"),
			},
		}

		operatorNS := "test-operator-ns"
		err = os.Setenv("MANAGEMENT_OPERATOR_NS", operatorNS)
		require.NoError(t, err)

		opts := []token.ControllerOption{
			token.WithControllerRuntimeClient(fakeClient),
			token.WithPrivateKey(privateKey),
			token.WithIssuer(issuer),
			token.WithIssuerName(issuer),
			token.WithUserInfos([]token.UserInfo{{Name: defaultServiceName, Namespace: defaultNamespace}}),
			token.WithFactory(factory),
			token.WithTenant(tenantName),
			token.WithK8sClient(mockK8sClient),
			token.WithImpersonation(&impersonationInfo),
			token.WithNamespace("tenant-a"),
		}
		controller, err := token.NewController(opts...)
		require.NoError(t, err)
		require.NotNil(t, controller)

		managedClientSet := testutils.ClientSetSet{
			k8sfake.NewSimpleClientset(),
			fake.NewSimpleClientset(),
		}

		factory.On("NewClientSetForApplication", mc.Name).Return(&managedClientSet, nil)
		factory.On("Impersonate", &impersonationInfo).Return(factory)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go func() {
			t.Helper()
			err := controller.Run(stopCh)
			require.NoError(t, err)
		}()
		time.Sleep(5 * time.Second)
		// Verify that "NewClientSetForApplication" and "Impersonate" have been called at least once. We only really
		// care about "Impersonate" for the purposes of this particular test.
		factory.AssertExpectations(t)
	})
}
