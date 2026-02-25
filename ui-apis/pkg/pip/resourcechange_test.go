package pip_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/ui-apis/pkg/pip"
)

var (
	// NP and GNP with no spec.Tier specified
	r1 = &v3.NetworkPolicy{
		TypeMeta: resources.TypeCalicoNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name: "default.np",
		},
		Spec: v3.NetworkPolicySpec{
			Selector: "foobarbaz",
		},
	}
	r2 = &v3.GlobalNetworkPolicy{
		TypeMeta: resources.TypeCalicoGlobalNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name: "default.gnp",
		},
		Spec: v3.GlobalNetworkPolicySpec{
			Selector: "foobazbar",
		},
	}
	// NP and GNP with matching spec.Tier specified
	r3 = &v3.NetworkPolicy{
		TypeMeta: resources.TypeCalicoNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name: "tier1.np",
		},
		Spec: v3.NetworkPolicySpec{
			Tier:     "tier1",
			Selector: "foobarbaz",
		},
	}
	r4 = &v3.GlobalNetworkPolicy{
		TypeMeta: resources.TypeCalicoGlobalNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name: "tier2.gnp",
		},
		Spec: v3.GlobalNetworkPolicySpec{
			Tier:     "tier2",
			Selector: "foobazbar",
		},
	}
	// k8s resources.
	r5 = &networkingv1.NetworkPolicy{
		TypeMeta: resources.TypeK8sNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name: "k8s-np",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}
	r6 = &corev1.Namespace{
		TypeMeta: resources.TypeK8sNamespaces,
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace",
		},
	}
)

var _ = Describe("Test resourcechange unmarshaling and marshaling", func() {
	It("handles flag checks correctly", func() {
		r1Copy := r1.DeepCopy()
		r2Copy := r2.DeepCopy()
		test := []pip.ResourceChange{
			{
				Action:   "update",
				Resource: r1Copy,
			},
			{
				Action:   "create",
				Resource: r2Copy,
			},
			{
				Action:   "delete",
				Resource: r3,
			},
			{
				Action:   "exterminate",
				Resource: r4,
			},
			{
				Action:   "exterminate",
				Resource: r5,
			},
			{
				Action:   "exterminate",
				Resource: r6,
			},
		}

		By("Marshalling a slice of ResourceChange structs")
		j, err := json.Marshal(test)
		Expect(err).NotTo(HaveOccurred())

		By("Unmarshalling the json output")
		var output []pip.ResourceChange
		err = json.Unmarshal(j, &output)
		Expect(err).NotTo(HaveOccurred())

		By("Setting the undefaulted tiers in the test data and then comparing to the parsed data")
		r1Copy.Spec.Tier = "default"
		r2Copy.Spec.Tier = "default"
		Expect(output).To(Equal(test))
	})
})
