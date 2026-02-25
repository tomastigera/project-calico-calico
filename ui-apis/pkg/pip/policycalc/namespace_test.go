package policycalc

import (
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/lma/pkg/api"
)

var _ = Describe("Namespace handler tests", func() {
	It("handles namespace selector caching", func() {
		nh := NewNamespaceHandler(nil, nil)

		By("creating a namespace selector")
		m1 := nh.GetNamespaceSelectorEndpointMatcher("all()")
		Expect(m1).NotTo(BeNil())

		By("creating the same namespace selector and checking the cache size")
		m2 := nh.GetNamespaceSelectorEndpointMatcher("all()")
		Expect(m2).NotTo(BeNil())
		Expect(reflect.ValueOf(m2)).To(Equal(reflect.ValueOf(m1)))
		Expect(nh.selectorMatchers).To(HaveLen(1))

		By("checking a different selector returns a different matcher function")
		m3 := nh.GetNamespaceSelectorEndpointMatcher("vegetable == 'turnip'")
		Expect(m3).NotTo(BeNil())
		Expect(reflect.ValueOf(m3)).NotTo(Equal(reflect.ValueOf(m1)))
		Expect(nh.selectorMatchers).To(HaveLen(2))
	})

	It("handles namespace selection", func() {
		nh := NewNamespaceHandler([]*corev1.Namespace{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ns1",
					Labels: map[string]string{
						"vegetable": "turnip",
						"protein":   "chicken",
						"carb":      "potato",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ns2",
					Labels: map[string]string{
						"vegetable": "turnip",
						"protein":   "beef",
						"carb":      "rice",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ns3",
					Labels: map[string]string{
						"vegetable": "carrot",
						"protein":   "beef",
						"carb":      "rice",
					},
				},
			},
		}, nil)

		By("Creating a matcher on ns1 and ns2")
		m1 := nh.GetNamespaceSelectorEndpointMatcher("vegetable == 'turnip'")
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeNs, Namespace: "ns1"}, nil, nil)).To(Equal(MatchTypeTrue))
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep, Namespace: "ns2"}, nil, nil)).To(Equal(MatchTypeTrue))
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns3"}, nil, nil)).To(Equal(MatchTypeFalse))
		// Shouldn't be possible to have type "Net" with Namespace - but check for negative match.
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeNet, Namespace: "ns1"}, nil, nil)).To(Equal(MatchTypeFalse))

		By("Creating a matching on namespace name ns1")
		m1 = nh.GetNamespaceSelectorEndpointMatcher("projectcalico.org/name == 'ns1'")
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeNs, Namespace: "ns1"}, nil, nil)).To(Equal(MatchTypeTrue))
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep, Namespace: "ns2"}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns3"}, nil, nil)).To(Equal(MatchTypeFalse))

		By("Creating a matcher on ns2 and ns3")
		m2 := nh.GetNamespaceSelectorEndpointMatcher("protein == 'beef' && carb == 'rice'")
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeNs, Namespace: "ns1"}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeNs, Namespace: "ns2"}, nil, nil)).To(Equal(MatchTypeTrue))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeNs, Namespace: "ns3"}, nil, nil)).To(Equal(MatchTypeTrue))

		By("Getting the same selector matchers and rechecking")
		m1 = nh.GetNamespaceSelectorEndpointMatcher("vegetable == 'turnip'")
		m2 = nh.GetNamespaceSelectorEndpointMatcher("protein == 'beef' && carb == 'rice'")

		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep, Namespace: "ns1"}, nil, nil)).To(Equal(MatchTypeTrue))
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep, Namespace: "ns2"}, nil, nil)).To(Equal(MatchTypeTrue))
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep, Namespace: "ns3"}, nil, nil)).To(Equal(MatchTypeFalse))

		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns1"}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns2"}, nil, nil)).To(Equal(MatchTypeTrue))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns3"}, nil, nil)).To(Equal(MatchTypeTrue))

		By("Check for !all(), no namespace exists")
		m2 = nh.GetNamespaceSelectorEndpointMatcher("!all()")
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns1"}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns2"}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns3"}, nil, nil)).To(Equal(MatchTypeFalse))

		By("Check for global(), no namespace exists")
		m2 = nh.GetNamespaceSelectorEndpointMatcher("global()")
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns1"}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns2"}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns3"}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep, Namespace: "__global__"}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep, Namespace: ""}, nil, nil)).To(Equal(MatchTypeTrue))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeNet, Namespace: ""}, nil, nil)).To(Equal(MatchTypeFalse))

		m2 = nh.GetNamespaceSelectorEndpointMatcher("global() && vegetable=='turnip'")
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep, Namespace: "ns1"}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m2(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep, Namespace: ""}, nil, nil)).To(Equal(MatchTypeFalse))

		By("Checking the size of the selector cache")
		Expect(nh.selectorMatchers).To(HaveLen(6))
	})

	It("handles service account population", func() {
		nh := NewNamespaceHandler(nil, []*corev1.ServiceAccount{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sa1",
					Namespace: "ns1",
					Labels: map[string]string{
						"vegetable": "turnip",
						"protein":   "chicken",
						"carb":      "potato",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sa1",
					Namespace: "ns2",
					Labels: map[string]string{
						"vegetable": "turnip",
						"protein":   "beef",
						"carb":      "rice",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sa2",
					Namespace: "ns2",
					Labels: map[string]string{
						"vegetable": "carrot",
						"protein":   "beef",
						"carb":      "rice",
					},
				},
			},
		})

		By("Checking the number of namespaces created implicitly")
		Expect(nh.namespaces).To(HaveLen(3))

		By("Checking the number of service accounts cached")
		Expect(nh.namespaces["ns1"].serviceAccountLabels).To(HaveLen(1))
		Expect(nh.namespaces["ns2"].serviceAccountLabels).To(HaveLen(2))

		By("Creating a service account matcher by name and checking for matches")
		m1 := nh.GetServiceAccountEndpointMatchers(&v3.ServiceAccountMatch{
			Names: []string{"sa1"},
		})
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m1(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep}, nil, nil)).To(Equal(MatchTypeUncertain))
		s := "sa1"
		Expect(m1(nil, &api.FlowEndpointData{
			Type:           api.EndpointTypeWep,
			Namespace:      "ns1",
			ServiceAccount: &s,
		}, nil, nil)).To(Equal(MatchTypeTrue))

		By("Asking for the same matcher and verifying we get the same response")
		m2 := nh.GetServiceAccountEndpointMatchers(&v3.ServiceAccountMatch{
			Names: []string{"sa1"},
		})
		Expect(reflect.ValueOf(m2)).To(Equal(reflect.ValueOf(m1)))
		Expect(nh.serviceAccountMatchers).To(HaveLen(1))

		By("Creating a service account matcher by label and checking for matches")
		m3 := nh.GetServiceAccountEndpointMatchers(&v3.ServiceAccountMatch{
			Selector: "vegetable == 'carrot'",
		})
		Expect(m3(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m3(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep}, nil, nil)).To(Equal(MatchTypeUncertain))
		s = "sa1"
		Expect(m3(nil, &api.FlowEndpointData{
			Type:           api.EndpointTypeWep,
			Namespace:      "ns2",
			ServiceAccount: &s,
		}, nil, nil)).To(Equal(MatchTypeFalse))
		s = "sa2"
		Expect(m3(nil, &api.FlowEndpointData{
			Type:           api.EndpointTypeWep,
			Namespace:      "ns2",
			ServiceAccount: &s,
		}, nil, nil)).To(Equal(MatchTypeTrue))

		By("Asking for the same matcher and verifying we get the same response")
		m4 := nh.GetServiceAccountEndpointMatchers(&v3.ServiceAccountMatch{
			Selector: "vegetable == 'carrot'",
		})
		Expect(reflect.ValueOf(m4)).To(Equal(reflect.ValueOf(m3)))
		Expect(reflect.ValueOf(m4)).NotTo(Equal(reflect.ValueOf(m2)))
		Expect(nh.serviceAccountMatchers).To(HaveLen(2))

		By("Creating a service account matcher by name and label and checking for matches")
		m5 := nh.GetServiceAccountEndpointMatchers(&v3.ServiceAccountMatch{
			Names:    []string{"sa1"},
			Selector: "carb == 'rice'",
		})
		Expect(m5(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m5(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep}, nil, nil)).To(Equal(MatchTypeUncertain))
		s = "sa1"
		Expect(m5(nil, &api.FlowEndpointData{
			Type:           api.EndpointTypeWep,
			Namespace:      "ns1",
			ServiceAccount: &s,
		}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m5(nil, &api.FlowEndpointData{
			Type:           api.EndpointTypeWep,
			Namespace:      "ns2",
			ServiceAccount: &s,
		}, nil, nil)).To(Equal(MatchTypeTrue))

		By("Creating a service account matcher that doesn't match anything")
		m6 := nh.GetServiceAccountEndpointMatchers(&v3.ServiceAccountMatch{
			Names:    []string{"sa1"},
			Selector: "protein == 'tofu'",
		})
		Expect(m6(nil, &api.FlowEndpointData{Type: api.EndpointTypeHep}, nil, nil)).To(Equal(MatchTypeFalse))
		Expect(m6(nil, &api.FlowEndpointData{Type: api.EndpointTypeWep}, nil, nil)).To(Equal(MatchTypeFalse))
	})
})
