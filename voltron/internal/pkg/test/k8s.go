package test

import (
	calicofake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	clientv3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type k8sFake = fake.Clientset
type calicoFake = clientv3.ProjectcalicoV3Interface

// K8sFakeClient is the actual client
type K8sFakeClient struct {
	*k8sFake
	calicoFake

	calicoFakeCtrl *k8stesting.Fake
}

// NewK8sSimpleFakeClient returns a new aggregated fake client that satisfies
// server.K8sClient interface to access both k8s and calico resources
func NewK8sSimpleFakeClient(k8sObj []runtime.Object, calicoObj []runtime.Object) *K8sFakeClient {
	calico := calicofake.NewClientset(calicoObj...)

	fake := &K8sFakeClient{
		k8sFake:        fake.NewClientset(k8sObj...),
		calicoFake:     calico.ProjectcalicoV3(),
		calicoFakeCtrl: &calico.Fake,
	}
	return fake
}
