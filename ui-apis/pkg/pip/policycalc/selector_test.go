package policycalc

import (
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/lma/pkg/api"
)

var _ = Describe("Selector handler tests", func() {
	It("handles endpoint selector and results caching", func() {
		sh := NewEndpointSelectorHandler()

		By("creating an endpoints selector")
		m1 := sh.GetSelectorEndpointMatcher("all()")
		Expect(m1).NotTo(BeNil())

		By("creating the same endpoints selector and checking the cache size")
		m2 := sh.GetSelectorEndpointMatcher("all()")
		Expect(m2).NotTo(BeNil())
		Expect(reflect.ValueOf(m2)).To(Equal(reflect.ValueOf(m1)))
		Expect(sh.selectorMatchers).To(HaveLen(1))

		By("checking a different selector returns a different matcher function")
		m3 := sh.GetSelectorEndpointMatcher("vegetable == 'turnip'")
		Expect(m3).NotTo(BeNil())
		Expect(reflect.ValueOf(m3)).NotTo(Equal(reflect.ValueOf(m1)))
		Expect(sh.selectorMatchers).To(HaveLen(2))

		By("matching endpoint against the two selectors (both successfully)")
		ed := &api.FlowEndpointData{
			Type: api.EndpointTypeHep,
			Labels: uniquelabels.Make(map[string]string{
				"vegetable": "turnip",
			}),
		}
		epc := endpointCache{selectors: sh.CreateSelectorCache()}

		Expect(epc.selectors).To(HaveLen(2))
		Expect(epc.selectors[0]).To(Equal(MatchTypeUnknown))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m1(nil, ed, nil, &epc)).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[0]).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m2(nil, ed, nil, &epc)).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[0]).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m3(nil, ed, nil, &epc)).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[0]).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[1]).To(Equal(MatchTypeTrue))

		By("matching endpoint against the two selectors (only one successfully)")
		ed = &api.FlowEndpointData{
			Type: api.EndpointTypeNs,
			Labels: uniquelabels.Make(map[string]string{
				"vegetable": "parsnip",
			}),
		}
		epc = endpointCache{selectors: sh.CreateSelectorCache()}

		Expect(epc.selectors).To(HaveLen(2))
		Expect(epc.selectors[0]).To(Equal(MatchTypeUnknown))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m1(nil, ed, nil, &epc)).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[0]).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m2(nil, ed, nil, &epc)).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[0]).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m3(nil, ed, nil, &epc)).To(Equal(MatchTypeFalse))
		Expect(epc.selectors[0]).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[1]).To(Equal(MatchTypeFalse))

		By("matching endpoint where labels are unknown")
		ed = &api.FlowEndpointData{
			Type:   api.EndpointTypeHep,
			Labels: uniquelabels.Nil,
		}
		epc = endpointCache{selectors: sh.CreateSelectorCache()}

		Expect(epc.selectors).To(HaveLen(2))
		Expect(epc.selectors[0]).To(Equal(MatchTypeUnknown))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m1(nil, ed, nil, &epc)).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[0]).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m2(nil, ed, nil, &epc)).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[0]).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m3(nil, ed, nil, &epc)).To(Equal(MatchTypeUncertain))
		Expect(epc.selectors[0]).To(Equal(MatchTypeTrue))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUncertain))

		By("matching endpoint where labels are not supported")
		ed = &api.FlowEndpointData{
			Type:   api.EndpointTypeNet,
			Labels: uniquelabels.Nil,
		}
		epc = endpointCache{selectors: sh.CreateSelectorCache()}

		Expect(epc.selectors).To(HaveLen(2))
		Expect(epc.selectors[0]).To(Equal(MatchTypeUnknown))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m1(nil, ed, nil, &epc)).To(Equal(MatchTypeFalse))
		Expect(epc.selectors[0]).To(Equal(MatchTypeFalse))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m2(nil, ed, nil, &epc)).To(Equal(MatchTypeFalse))
		Expect(epc.selectors[0]).To(Equal(MatchTypeFalse))
		Expect(epc.selectors[1]).To(Equal(MatchTypeUnknown))

		Expect(m3(nil, ed, nil, &epc)).To(Equal(MatchTypeFalse))
		Expect(epc.selectors[0]).To(Equal(MatchTypeFalse))
		Expect(epc.selectors[1]).To(Equal(MatchTypeFalse))
	})
})
