// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package authzreview

import (
	"context"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

// NewCalculator creates an rbac.Calculator from separate Kubernetes and Calico clientsets.
func NewCalculator(k8sClient kubernetes.Interface, calicoClient clientset.Interface) rbac.Calculator {
	return rbac.NewCalculator(
		k8sClient.Discovery(),
		newK8sClusterRoleGetter(k8sClient),
		newK8sClusterRoleBindingLister(k8sClient),
		newK8sRoleGetter(k8sClient),
		newK8sRoleBindingLister(k8sClient),
		newK8sNamespaceLister(k8sClient),
		newCalicoResourceLister(calicoClient),
		0,
	)
}

// newCalculatorForClientSet creates an rbac.Calculator from a managed cluster's ClientSet.
// lmak8s.ClientSet satisfies both kubernetes.Interface and clientset.Interface, so it can
// be used for all K8s RBAC adapters and the Calico resource lister.
func newCalculatorForClientSet(cs lmak8s.ClientSet) rbac.Calculator {
	return NewCalculator(cs, cs)
}

// newK8sRoleGetter returns a RoleGetter backed by a Kubernetes clientset.
func newK8sRoleGetter(cs kubernetes.Interface) rbac.RoleGetter {
	return &k8sRoleGetter{cs: cs}
}

// newK8sRoleBindingLister returns a RoleBindingLister backed by a Kubernetes clientset.
func newK8sRoleBindingLister(cs kubernetes.Interface) rbac.RoleBindingLister {
	return &k8sRoleBindingLister{cs: cs}
}

// newK8sClusterRoleGetter returns a ClusterRoleGetter backed by a Kubernetes clientset.
func newK8sClusterRoleGetter(cs kubernetes.Interface) rbac.ClusterRoleGetter {
	return &k8sClusterRoleGetter{cs: cs}
}

// newK8sClusterRoleBindingLister returns a ClusterRoleBindingLister backed by a Kubernetes clientset.
func newK8sClusterRoleBindingLister(cs kubernetes.Interface) rbac.ClusterRoleBindingLister {
	return &k8sClusterRoleBindingLister{cs: cs}
}

// newK8sNamespaceLister returns a NamespaceLister backed by a Kubernetes clientset.
func newK8sNamespaceLister(cs kubernetes.Interface) rbac.NamespaceLister {
	return &k8sNamespaceLister{cs: cs}
}

// newCalicoResourceLister returns a CalicoResourceLister backed by a Calico clientset.
func newCalicoResourceLister(calico clientset.Interface) rbac.CalicoResourceLister {
	return &calicoResourceLister{calico: calico}
}

// k8sRoleGetter implements the rbac.RoleGetter interface.
type k8sRoleGetter struct {
	cs kubernetes.Interface
}

func (r *k8sRoleGetter) GetRole(ctx context.Context, namespace, name string) (*rbacv1.Role, error) {
	return r.cs.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
}

// k8sRoleBindingLister implements the rbac.RoleBindingLister interface.
type k8sRoleBindingLister struct {
	cs kubernetes.Interface
}

func (r *k8sRoleBindingLister) ListRoleBindings(ctx context.Context, namespace string) ([]*rbacv1.RoleBinding, error) {
	list, err := r.cs.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*rbacv1.RoleBinding, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}

// k8sClusterRoleGetter implements the rbac.ClusterRoleGetter interface.
type k8sClusterRoleGetter struct {
	cs kubernetes.Interface
}

func (r *k8sClusterRoleGetter) GetClusterRole(ctx context.Context, name string) (*rbacv1.ClusterRole, error) {
	return r.cs.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
}

// k8sClusterRoleBindingLister implements the rbac.ClusterRoleBindingLister interface.
type k8sClusterRoleBindingLister struct {
	cs kubernetes.Interface
}

func (r *k8sClusterRoleBindingLister) ListClusterRoleBindings(ctx context.Context) ([]*rbacv1.ClusterRoleBinding, error) {
	list, err := r.cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*rbacv1.ClusterRoleBinding, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}

// k8sNamespaceLister implements the rbac.NamespaceLister interface.
type k8sNamespaceLister struct {
	cs kubernetes.Interface
}

func (n *k8sNamespaceLister) ListNamespaces() ([]*corev1.Namespace, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := n.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*corev1.Namespace, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}

// calicoResourceLister implements the rbac.CalicoResourceLister interface.
type calicoResourceLister struct {
	calico clientset.Interface
}

func (t *calicoResourceLister) ListTiers() ([]*v3.Tier, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := t.calico.ProjectcalicoV3().Tiers().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*v3.Tier, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}

func (t *calicoResourceLister) ListUISettingsGroups() ([]*v3.UISettingsGroup, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := t.calico.ProjectcalicoV3().UISettingsGroups().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*v3.UISettingsGroup, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}

func (t *calicoResourceLister) ListManagedClusters() ([]*v3.ManagedCluster, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := t.calico.ProjectcalicoV3().ManagedClusters().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*v3.ManagedCluster, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}
