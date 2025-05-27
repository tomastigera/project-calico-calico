// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package managedcluster

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	tigeraapi "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	calicofake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var (
	managedCalicoCLI clientset.Interface
	ctx              context.Context
	fakeClient       ctrlclient.WithWatch
)

func setup(t *testing.T) func() {

	logCancel := logutils.RedirectLogrusToTestingT(t)

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

	managedCalicoCLI = calicofake.NewSimpleClientset()

	scheme := kscheme.Scheme
	err := v3.AddToScheme(scheme)
	require.NoError(t, err)
	fakeClient = fakeclient.NewClientBuilder().WithScheme(scheme).Build()

	return func() {
		logCancel()
		cancel()
	}
}

func TestMainlineFunction(t *testing.T) {
	testCases := []struct {
		tenantNamespace string
		tenantID        string
		tenantMode      string
	}{
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

		// Create a Cluster Information in the managed cluster.
		ci := v3.ClusterInformation{}
		ci.Name = "default"
		ci.Spec = v3.ClusterInformationSpec{
			CalicoVersion: "v3.29.1",
			ClusterGUID:   "clusterGuid",
			ClusterType:   "typha,kdd,k8s,operator,bgp,kubeadm",
			CNXVersion:    "v3.22.0-1.0",
		}
		_, err := managedCalicoCLI.ProjectcalicoV3().ClusterInformations().Create(context.Background(), &ci, metav1.CreateOptions{})
		require.NoError(t, err)

		// Make a new controller.
		cc := func(clustername string) (kubernetes.Interface, tigeraapi.Interface, error) {
			return nil, managedCalicoCLI, nil
		}

		cfg := config.ManagedClusterControllerConfig{
			GenericControllerConfig: config.GenericControllerConfig{
				ReconcilerPeriod: 1 * time.Second,
			},
		}
		if tenantNamespace != "" {
			cfg.TenantNamespace = tenantNamespace
		}

		opts := []ControllerOption{
			WithManagedClusterControllerConfig(cfg),
			WithControllerRuntimeClient(fakeClient),
			WithCreateManagedK8sCLI(cc),
		}

		clusterController, err := NewClusterInfoController(opts...)
		require.NoError(t, err)
		require.NotNil(t, clusterController)

		// Reconcile.
		stopCh := make(chan struct{})
		defer close(stopCh)
		go clusterController.Run(stopCh)

		// Add a managed cluster.
		mc := v3.ManagedCluster{}
		mc.Name = "test-managed-cluster"
		if tenantNamespace != "" {
			mc.Namespace = tenantNamespace
		}

		mc.Status.Conditions = []v3.ManagedClusterStatusCondition{
			{
				Type:   v3.ManagedClusterStatusTypeConnected,
				Status: v3.ManagedClusterStatusValueTrue,
			},
		}

		err = fakeClient.Create(context.Background(), &mc)
		require.NoError(t, err)

		// Check the managed cluster CR for the version update
		mcUpd := &v3.ManagedCluster{}
		mcUpdated := func() bool {
			err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-managed-cluster", Namespace: tenantNamespace}, mcUpd)
			return err == nil && mcUpd.Status.Version != ""
		}
		require.Eventually(t, mcUpdated, 10*time.Second, 100*time.Millisecond)
		require.NoError(t, err)
		require.Equal(t, "v3.22.0-1.0", mcUpd.Status.Version)

	})
}
