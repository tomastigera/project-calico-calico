package managedcluster

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientsetfake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeK8s "k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/globalalert/controllers/waf"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

var _ = Describe("Managed Cluster Reconcile", func() {
	var (
		mcr             managedClusterReconciler
		clusterName     = "test-cluster"
		clusterName2    = "test-cluster-2"
		wafClusterName  = "WAF-test-cluster"
		wafClusterName2 = "WAF-test-cluster-2"
		namespace       = "default"
	)

	BeforeEach(func() {
		mockClient := waf.NewMockClient()
		mockLmaK8sClientSet := lmak8s.MockClientSet{}
		mockLmaK8sClientFactory := &lmak8s.MockClientSetFactory{}
		mockLmaK8sClientFactory.On("NewClientSetForApplication", mock.Anything).Return(&mockLmaK8sClientSet, nil)
		mockLmaK8sClientSet.On("ProjectcalicoV3").Return(clientsetfake.NewSimpleClientset().ProjectcalicoV3())
		mockLmaK8sClientSet.On("CoreV1").Return(fakeK8s.NewSimpleClientset().CoreV1())

		mcr = managedClusterReconciler{
			client:                          MockClientWithWatch{},
			alertNameToAlertControllerState: map[string]alertControllerState{},
			clientSetFactory:                mockLmaK8sClientFactory,
			lsClient:                        mockClient,
		}

	})

	It("Managed Cluster Reconcile: reconcile cluster add connected cluster", func() {

		Expect(mcr.alertNameToAlertControllerState[clusterName].alertController).To(BeNil())
		Expect(mcr.alertNameToAlertControllerState[wafClusterName].alertController).To(BeNil())

		Expect(mcr.alertNameToAlertControllerState[clusterName2].alertController).To(BeNil())
		Expect(mcr.alertNameToAlertControllerState[wafClusterName2].alertController).To(BeNil())

		err := mcr.Reconcile(types.NamespacedName{Name: clusterName, Namespace: namespace})

		Expect(err).To(BeNil())

		Expect(mcr.alertNameToAlertControllerState[clusterName]).To(Not(BeNil()))
		Expect(mcr.alertNameToAlertControllerState[wafClusterName]).To(Not(BeNil()))

		err = mcr.Reconcile(types.NamespacedName{Name: clusterName2, Namespace: namespace})

		Expect(err).To(BeNil())

		Expect(mcr.alertNameToAlertControllerState[clusterName2]).To(Not(BeNil()))
		Expect(mcr.alertNameToAlertControllerState[wafClusterName2]).To(Not(BeNil()))

		// change the conditions of the managedcluster struct to say it's disconnected
		for _, cluster := range Clusters {
			if cluster.Name == clusterName || cluster.Name == wafClusterName {
				*cluster = v3.ManagedCluster{
					ObjectMeta: v1.ObjectMeta{
						Name:      cluster.Name,
						Namespace: cluster.Namespace,
					},
					Status: v3.ManagedClusterStatus{
						Conditions: []v3.ManagedClusterStatusCondition{
							{
								Status: v3.ManagedClusterStatusValueFalse,
							},
						},
					},
				}
			}
		}

		err = mcr.Reconcile(types.NamespacedName{Name: clusterName, Namespace: namespace})

		Expect(err).To(BeNil())
		Expect(mcr.alertNameToAlertControllerState[clusterName].alertController).To(BeNil())
		Expect(mcr.alertNameToAlertControllerState[wafClusterName].alertController).To(BeNil())

		Expect(mcr.alertNameToAlertControllerState[clusterName2]).To(Not(BeNil()))
		Expect(mcr.alertNameToAlertControllerState[wafClusterName2]).To(Not(BeNil()))

	})

})
