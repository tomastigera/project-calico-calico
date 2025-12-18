// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
package api_test

import (
	"fmt"
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lma/pkg/api"
)

type testPolicyHit struct {
	action      api.Action
	index       int
	name        string
	flowLogName string
	namespace   string
	tier        string
	isKNP       bool
	isKNS       bool
	isStaged    bool
	count       int64
	ruleIdIndex *int
}

var _ = Describe("PolicyHitFromFlowLogPolicyString", func() {
	DescribeTable("Successful PolicyHit parsing",
		func(policyStr string, docCount int, expectedPolicyHit testPolicyHit, expectedPolicyString string) {
			policyHit, err := api.PolicyHitFromFlowLogPolicyString(policyStr, int64(docCount))
			Expect(err).ShouldNot(HaveOccurred())

			Expect(policyHit.Action()).Should(Equal(expectedPolicyHit.action))
			Expect(policyHit.Index()).Should(Equal(expectedPolicyHit.index))
			Expect(policyHit.Tier()).Should(Equal(expectedPolicyHit.tier))
			Expect(policyHit.RuleIdIndex()).Should(Equal(expectedPolicyHit.ruleIdIndex))
			Expect(policyHit.FlowLogName()).Should(Equal(expectedPolicyHit.flowLogName))
			Expect(policyHit.Namespace()).Should(Equal(expectedPolicyHit.namespace))
			Expect(policyHit.Count()).Should(Equal(expectedPolicyHit.count))
			Expect(policyHit.IsKubernetes()).Should(Equal(expectedPolicyHit.isKNP))
			Expect(policyHit.IsProfile()).Should(Equal(expectedPolicyHit.isKNS))
			Expect(policyHit.IsStaged()).Should(Equal(expectedPolicyHit.isStaged))
			Expect(policyHit.ToFlowLogPolicyString()).Should(Equal(expectedPolicyString))
		},
		Entry(
			"properly handles a network policy",
			"4|tierName|namespaceName/tierName.policyName|allow",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "policyName",
				flowLogName: "namespaceName/tierName.policyName", namespace: "namespaceName",
				ruleIdIndex: nil, count: 5, isKNP: false, isKNS: false, isStaged: false,
			},
			"4|tierName|namespaceName/tierName.policyName|allow|-",
		),

		// Older versions of Calico used tier.staged:name, but newer versions do not include
		// the tier in the ID section of the policy string. This test reads the old style but
		// the policy hit code now outputs the new style.
		Entry(
			"properly handles a (legacy) staged network policy",
			"4|tierName|namespaceName/tierName.staged:policyName|deny",
			5,
			testPolicyHit{
				action: api.ActionDeny, index: 4, tier: "tierName", name: "policyName",
				flowLogName: "namespaceName/tierName.staged:tierName.policyName", namespace: "namespaceName",
				ruleIdIndex: nil, count: 5, isKNP: false, isKNS: false, isStaged: true,
			},
			"4|tierName|namespaceName/tierName.staged:tierName.policyName|deny|-",
		),
		Entry(
			"properly handles a (legacy) staged global network policy",
			"4|tierName|tierName.staged:policyName|allow",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "policyName",
				flowLogName: "tierName.staged:tierName.policyName", namespace: "", ruleIdIndex: nil, count: 5,
				isKNP: false, isKNS: false, isStaged: true,
			},
			"4|tierName|tierName.staged:tierName.policyName|allow|-",
		),
		Entry(
			"properly handles a (legacy) staged network policy",
			"4|tierName|namespaceName/tierName.staged:policyName|deny|-1",
			5,
			testPolicyHit{
				action: api.ActionDeny, index: 4, tier: "tierName", name: "policyName",
				flowLogName: "namespaceName/tierName.staged:tierName.policyName", namespace: "namespaceName",
				ruleIdIndex: getRefToInt(-1), count: 5, isKNP: false, isKNS: false, isStaged: true,
			},
			"4|tierName|namespaceName/tierName.staged:tierName.policyName|deny|-1",
		),
		Entry(
			"properly handles a (legacy) staged global network policy",
			"4|tierName|tierName.staged:policyName|allow|1",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "policyName",
				flowLogName: "tierName.staged:tierName.policyName", namespace: "", ruleIdIndex: getRefToInt(1), count: 5,
				isKNP: false, isKNS: false, isStaged: true,
			},
			"4|tierName|tierName.staged:tierName.policyName|allow|1",
		),

		// Same test from above, but with new style input - should give us the same output.
		Entry(
			"properly handles a staged network policy",
			"4|tierName|namespaceName/tierName.staged:tierName.policyName|deny",
			5,
			testPolicyHit{
				action: api.ActionDeny, index: 4, tier: "tierName", name: "policyName",
				flowLogName: "namespaceName/tierName.staged:tierName.policyName", namespace: "namespaceName",
				ruleIdIndex: nil, count: 5, isKNP: false, isKNS: false, isStaged: true,
			},
			"4|tierName|namespaceName/tierName.staged:tierName.policyName|deny|-",
		),

		Entry(
			"properly handles a global network policy",
			"4|tierName|tierName.policyName|allow",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "policyName",
				flowLogName: "tierName.policyName", namespace: "", ruleIdIndex: nil, count: 5, isKNP: false,
				isKNS: false, isStaged: false,
			},
			"4|tierName|tierName.policyName|allow|-",
		),
		Entry(
			"properly handles a kubernetes network policy",
			"4|default|namespaceName/knp.default.policyName|allow",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "default", name: "policyName",
				flowLogName: "namespaceName/knp.default.policyName", namespace: "namespaceName",
				ruleIdIndex: nil, count: 5, isKNP: true, isStaged: false,
			},
			"4|default|namespaceName/knp.default.policyName|allow|-",
		),
		Entry(
			"properly handles a staged kubernetes network policy",
			"4|default|namespaceName/staged:knp.default.policyName|deny",
			5,
			testPolicyHit{
				action: api.ActionDeny, index: 4, tier: "default", name: "policyName",
				flowLogName: "namespaceName/staged:knp.default.policyName", namespace: "namespaceName",
				ruleIdIndex: nil, count: 5, isKNP: true, isKNS: false, isStaged: true,
			},
			"4|default|namespaceName/staged:knp.default.policyName|deny|-",
		),
		Entry(
			"properly handles a kubernetes namespace profile",
			"4|__PROFILE__|__PROFILE__.kns.namespaceName|allow",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "__PROFILE__", name: "namespaceName",
				flowLogName: "__PROFILE__.kns.namespaceName", namespace: "", ruleIdIndex: nil, count: 5,
				isKNP: false, isKNS: true, isStaged: false,
			},
			"4|__PROFILE__|__PROFILE__.kns.namespaceName|allow|-",
		),
		Entry(
			"properly handles a kubernetes namespace profile",
			"4|__PROFILE__|__PROFILE__.kns.namespaceName|allow",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "__PROFILE__", name: "namespaceName",
				flowLogName: "__PROFILE__.kns.namespaceName", namespace: "", ruleIdIndex: nil, count: 5,
				isKNP: false, isKNS: true, isStaged: false,
			},
			"4|__PROFILE__|__PROFILE__.kns.namespaceName|allow|-",
		),
		Entry(
			"properly handles a network policy",
			"4|tierName|namespaceName/tierName.policyName|allow|1",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "policyName",
				flowLogName: "namespaceName/tierName.policyName", namespace: "namespaceName",
				ruleIdIndex: getRefToInt(1), count: 5, isKNP: false, isKNS: false, isStaged: false,
			},
			"4|tierName|namespaceName/tierName.policyName|allow|1",
		),
		Entry(
			"properly handles a global network policy",
			"4|tierName|tierName.policyName|allow|0",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "policyName",
				flowLogName: "tierName.policyName", namespace: "", ruleIdIndex: getRefToInt(0), count: 5,
				isKNP: false, isKNS: false, isStaged: false,
			},
			"4|tierName|tierName.policyName|allow|0",
		),
		Entry(
			"properly handles a kubernetes network policy",
			"4|default|namespaceName/knp.default.policyName|allow|2",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "default", name: "policyName",
				flowLogName: "namespaceName/knp.default.policyName", namespace: "namespaceName",
				ruleIdIndex: getRefToInt(2), count: 5, isKNP: true, isStaged: false,
			},
			"4|default|namespaceName/knp.default.policyName|allow|2",
		),
		Entry(
			"properly handles a staged kubernetes network policy",
			"4|default|namespaceName/staged:knp.default.policyName|deny|10",
			5,
			testPolicyHit{
				action: api.ActionDeny, index: 4, tier: "default", name: "policyName",
				flowLogName: "namespaceName/staged:knp.default.policyName", namespace: "namespaceName",
				ruleIdIndex: getRefToInt(10), count: 5, isKNP: true, isKNS: false, isStaged: true,
			},
			"4|default|namespaceName/staged:knp.default.policyName|deny|10",
		),
		Entry(
			"properly handles a kubernetes namespace profile",
			"4|__PROFILE__|__PROFILE__.kns.namespaceName|allow|4",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "__PROFILE__", name: "namespaceName",
				flowLogName: "__PROFILE__.kns.namespaceName", namespace: "", ruleIdIndex: getRefToInt(4),
				count: 5, isKNP: false, isKNS: true, isStaged: false,
			},
			"4|__PROFILE__|__PROFILE__.kns.namespaceName|allow|4",
		),
		Entry(
			"properly handles a kubernetes namespace profile",
			"4|__PROFILE__|__PROFILE__.kns.namespaceName|allow|-",
			5,
			testPolicyHit{
				action: api.ActionAllow, index: 4, tier: "__PROFILE__", name: "namespaceName",
				flowLogName: "__PROFILE__.kns.namespaceName", namespace: "", ruleIdIndex: nil, count: 5,
				isKNP: false, isKNS: true, isStaged: false,
			},
			"4|__PROFILE__|__PROFILE__.kns.namespaceName|allow|-",
		),
	)

	DescribeTable("Unsuccessful PolicyHit parsing",
		func(policyStr string, docCount int, expectedErr error) {
			_, err := api.PolicyHitFromFlowLogPolicyString(policyStr, int64(docCount))
			Expect(err).Should(Equal(expectedErr))
		},
		Entry(
			"fails to parse a policy string with extra pipes",
			"4|tier1|namespace1/policy1|allow|0|extra",
			5,
			fmt.Errorf("invalid policy string '4|tier1|namespace1/policy1|allow|0|extra': pipe "+
				"count must equal 5 for a new or 4 for an old version of the policy string"),
		),
		Entry(
			"fails to parse a policy string with extra pipes",
			"4|tier1|namespace1/policy1|allow|0|extra|extra",
			5,
			fmt.Errorf("invalid policy string '4|tier1|namespace1/policy1|allow|0|extra|extra': pipe "+
				"count must equal 5 for a new or 4 for an old version of the policy string"),
		),
		Entry(
			"fails to parse a policy string with extra pipes",
			"4|tier1|namespace1/policy1",
			5,
			fmt.Errorf("invalid policy string '4|tier1|namespace1/policy1': pipe "+
				"count must equal 5 for a new or 4 for an old version of the policy string"),
		),
		Entry(
			"fails to parse a policy string with an invalid index",
			"x|tier1|namespace1/policy1|allow|0", 5,
			fmt.Errorf("invalid policy index: %w",
				&strconv.NumError{Func: "Atoi", Num: "x", Err: fmt.Errorf("invalid syntax")}),
		),
		Entry(
			"fails to parse a policy string with an invalid index",
			"4|tier1|namespace1/policy1|badaction|0", 5,
			fmt.Errorf("invalid action 'badaction'"),
		),
		Entry(
			"fails to parse a policy string with extra pipes",
			"4|tier1|namespace1/policy1|",
			5,
			fmt.Errorf("invalid action ''"),
		),
		Entry(
			"fails to parse a policy string with an invalid rule id index index",
			"4|tier1|namespace1/policy1|deny|x", 5,
			fmt.Errorf("invalid policy rule id index: %w",
				&strconv.NumError{Func: "Atoi", Num: "x", Err: fmt.Errorf("invalid syntax")}),
		),
		Entry(
			"fails to parse a policy string with an invalid rule id index index",
			"4|tier1|namespace1/policy1|deny|", 5,
			fmt.Errorf("invalid policy rule id index: %w",
				&strconv.NumError{Func: "Atoi", Num: "", Err: fmt.Errorf("invalid syntax")}),
		),
	)

	When("changing fields with the Set functions", func() {
		It("returns an updated copy of the original PolicyHit, created from an old policy string "+
			"(parts size==4), while keep the original unmodified", func() {
			policyHit, err := api.PolicyHitFromFlowLogPolicyString(
				"4|tierName|namespaceName/tierName.policyName|allow", int64(7),
			)
			Expect(err).ShouldNot(HaveOccurred())

			updatedPolicyHit := policyHit.SetIndex(2).SetAction(api.ActionDeny).SetCount(20)

			Expect(updatedPolicyHit.Index()).Should(Equal(2))
			Expect(updatedPolicyHit.Action()).Should(Equal(api.ActionDeny))
			Expect(updatedPolicyHit.Count()).Should(Equal(int64(20)))

			Expect(policyHit.Index()).Should(Equal(4))
			Expect(policyHit.Action()).Should(Equal(api.ActionAllow))
			Expect(policyHit.Count()).Should(Equal(int64(7)))

			var nilpointer *int
			Expect(policyHit.RuleIdIndex()).Should(Equal(nilpointer))
		})

		It("returns an updated copy of the original PolicyHit, created from a new policy string "+
			"(parts size==5), while keep the original unmodified", func() {
			policyHit, err := api.PolicyHitFromFlowLogPolicyString(
				"4|tierName|namespaceName/tierName.policyName|allow|-1", int64(7),
			)
			Expect(err).ShouldNot(HaveOccurred())

			updatedPolicyHit := policyHit.SetIndex(2).SetAction(api.ActionDeny).SetCount(20)

			Expect(updatedPolicyHit.Index()).Should(Equal(2))
			Expect(updatedPolicyHit.Action()).Should(Equal(api.ActionDeny))
			Expect(updatedPolicyHit.Count()).Should(Equal(int64(20)))

			Expect(policyHit.Index()).Should(Equal(4))
			Expect(policyHit.Action()).Should(Equal(api.ActionAllow))
			Expect(policyHit.Count()).Should(Equal(int64(7)))
			Expect(*policyHit.RuleIdIndex()).Should(Equal(int(-1)))
		})
	})
})

var _ = Describe("NewPolicyHit", func() {
	DescribeTable("Creating a valid policy hit", func(
		action api.Action, count int, index int, isStaged bool, name, namespace, tier string,
		ruleIdIndex *int, fullName, policyString string,
	) {
		policyHit, err := api.NewPolicyHit(action, int64(count), index, isStaged, name, namespace, tier, ruleIdIndex)
		Expect(err).ShouldNot(HaveOccurred())

		Expect(policyHit.FlowLogName()).Should(Equal(fullName))
		polstr := policyHit.ToFlowLogPolicyString()
		Expect(polstr).Should(Equal(policyString))
		Expect(policyHit.Count()).Should(Equal(int64(count)))
	},
		Entry(
			"properly handles a network policy",
			api.ActionAllow, 5, 4, false, "foo.policyName", "namespaceName", "tierName",
			getRefToInt(0), "namespaceName/foo.policyName",
			"4|tierName|namespaceName/foo.policyName|allow|0",
		),

		// Older versions of Calico used tier.staged:name, but newer versions do not include
		// the tier in the ID section of the policy string. This test reads the old style but
		// the policy hit code now outputs the new style.
		Entry(
			"properly handles a staged network policy",
			api.ActionDeny, 5, 4, true, "tierName.staged:policyName", "namespaceName", "tierName",
			getRefToInt(-1), "namespaceName/tierName.staged:tierName.policyName",
			"4|tierName|namespaceName/tierName.staged:tierName.policyName|deny|-1",
		),
		Entry(
			"properly handles a staged global network policy",
			api.ActionAllow, 5, 4, true, "tierName.policyName", "", "tierName", getRefToInt(2),
			"tierName.staged:tierName.policyName", "4|tierName|tierName.staged:tierName.policyName|allow|2",
		),

		Entry(
			"properly handles a global network policy",
			api.ActionAllow, 5, 4, false, "policyName", "", "tierName", getRefToInt(1),
			"policyName", "4|tierName|policyName|allow|1",
		),
		Entry(
			"properly handles a kubernetes network policy",
			api.ActionAllow, 5, 4, false, "knp.default.policyName", "namespaceName", "default",
			getRefToInt(3), "namespaceName/knp.default.policyName",
			"4|default|namespaceName/knp.default.policyName|allow|3",
		),
		Entry(
			"properly handles a staged kubernetes network policy",
			api.ActionDeny, 5, 4, true, "knp.default.policyName", "namespaceName", "default",
			getRefToInt(-1), "namespaceName/staged:knp.default.policyName",
			"4|default|namespaceName/staged:knp.default.policyName|deny|-1",
		),
		Entry(
			"properly handles a kubernetes namespace profile",
			api.ActionAllow, 5, 4, false, "__PROFILE__.kns.namespaceName", "", "__PROFILE__",
			getRefToInt(0), "__PROFILE__.kns.namespaceName",
			"4|__PROFILE__|__PROFILE__.kns.namespaceName|allow|0",
		),
		Entry(
			"properly handles a kubernetes namespace profile",
			api.ActionAllow, 5, 4, false, "__PROFILE__.kns.namespaceName", "", "__PROFILE__", nil,
			"__PROFILE__.kns.namespaceName", "4|__PROFILE__|__PROFILE__.kns.namespaceName|allow|-",
		),
	)

	DescribeTable("Creating an invalid policy hit", func(
		action api.Action, count int, index int, isStaged bool, name, namespace, tier string,
		ruleIdIndex *int, expectedErr error,
	) {
		_, err := api.NewPolicyHit(action, int64(count), index, isStaged, name, namespace, tier, ruleIdIndex)
		Expect(err).Should(Equal(expectedErr))
	},
		Entry(
			"returns an error when action the is empty",
			api.ActionInvalid, 5, 4, false, "tierName.policyName", "namespaceName", "tierName",
			getRefToInt(0),
			fmt.Errorf("a none empty Action must be provided"),
		),
		Entry(
			"returns an error when the index is negative",
			api.ActionDeny, 5, -1, false, "tierName.policyName", "namespaceName", "tierName",
			getRefToInt(-1),
			fmt.Errorf("index must be a positive integer"),
		),
		Entry(
			"returns an error when the count is negative",
			api.ActionAllow, -1, 4, false, "policyName", "namespaceName", "tierName", getRefToInt(1),
			fmt.Errorf("count must be a positive integer"),
		),
		Entry(
			"returns an error when the rule id index is not -1 and negative",
			api.ActionAllow, 5, 4, false, "policyName", "namespaceName", "tierName", getRefToInt(-2),
			fmt.Errorf("rule id index must be a positive integer or -1"),
		),
	)
	When("comparing PolicyHits (mixed of old and new policy string types)", func() {
		var pstrings1 [10]string
		var pstrings2 [10]string

		BeforeEach(func() {
			// Two lists of policy strings with a mixed of
			pstrings1 = [10]string{
				"0|tierName3|ns1/tierName3.p1|allow",
				"1|tierName1|ns2/tierName1.p3|deny|-1",
				"2|tierName0|ns3/tierName0.p0|pass|0",
				"1|tierName1|ns2/tierName1.staged:p3.|allow|2",
				"0|tierName3|ns1/tierName3.p5|allow|2",
				"3|tierName1|ns4/tierName1.p7|pass|-1",
				"5|tierName5|ns4/tierName5.p8|deny",
				"6|tierName6|ns3/tierName6.p0|allow|-1",
				"4|tierName6|ns5/tierName6.p4|deny|3",
				"1|tierName1|ns2/tierName1.p3|allow",
			}
			pstrings2 = [10]string{
				"0|tierName3|ns1/tierName3.p1|allow|-",
				"1|tierName1|ns2/tierName1.p3|deny|-1",
				"2|tierName0|ns3/tierName0.p0|pass|0",
				"1|tierName1|ns2/tierName1.staged:p3.|allow|2",
				"0|tierName3|ns1/tierName3.p5|allow|2",
				"3|tierName1|ns4/tierName1.p7|pass|-1",
				"5|tierName5|ns4/tierName5.p8|deny|-",
				"6|tierName6|ns3/tierName6.p0|allow|-1",
				"4|tierName6|ns5/tierName6.p4|deny|3",
				"1|tierName1|ns2/tierName1.p3|allow|-",
			}
		})

		It("compares two equal lists of policyHits", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(true))
		})

		It("compares unequal lists of policyHits, where the difference lies in the index", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|pass|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("4|tierName1|ns4/tierName1.p7|pass|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})

		It("compares unequal lists of policyHits, where the difference lies in the tier", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|pass|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName2|ns4/tierName2.p7|pass|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})

		It("compares unequal lists of policyHits, where the difference lies in the namespace", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|pass|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns3/tierName1.p7|pass|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})

		It("compares unequal lists of policyHits, where the difference lies in the name", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|pass|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p8|pass|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})

		It("compares unequal lists of policyHits, where the difference lies in the action", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|pass|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|deny|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})

		It("compares unequal lists of policyHits, where the difference lies in the rule id index", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps, 0)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|deny|-1", 0)
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|deny|1", 0)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})
	})

	When("sorting PolicyHits (mixed of old and new policy string types)", func() {
		var policyStrings [10]string
		var expectedSortedPolicyStrings [10]string
		var expectedSortedPolicyHits []api.PolicyHit
		var expectedCounts [10]int64

		BeforeEach(func() {
			policyStrings = [10]string{
				"0|tierName3|ns1/tierName3.p1|allow",
				"1|tierName1|ns2/tierName1.p3|deny|-1",
				"2|tierName0|ns3/tierName0.p0|pass|0",
				"1|tierName1|ns2/tierName1.staged:p3.|allow|2",
				"0|tierName3|ns1/tierName3.p5|allow|2",
				"3|tierName1|ns4/tierName1.p7|pass|-1",
				"5|tierName5|ns4/tierName5.p8|deny",
				"6|tierName6|ns3/tierName6.p0|allow|-1",
				"4|tierName6|ns5/tierName6.p4|deny|3",
				"1|tierName1|ns2/tierName1.p3|allow|2",
			}

			expectedCounts = [10]int64{1, 19, 0, 1, 19, 0, 7, 5, 18, 16}
			expectedSortedPolicyStrings = [10]string{
				"0|tierName3|ns1/tierName3.p1|allow|-",
				"1|tierName3|ns1/tierName3.p5|allow|2",
				"2|tierName1|ns2/tierName1.p3|allow|2",
				"3|tierName1|ns2/tierName1.p3|deny|-1",
				"4|tierName1|ns2/tierName1.staged:tierName1.p3.|allow|2",
				"5|tierName0|ns3/tierName0.p0|pass|0",
				"6|tierName1|ns4/tierName1.p7|pass|-1",
				"7|tierName6|ns5/tierName6.p4|deny|3",
				"8|tierName5|ns4/tierName5.p8|deny|-",
				"9|tierName6|ns3/tierName6.p0|allow|-1",
			}

			By("creating expected sorted policy hits from a list of sorted policy strings")
			for i, spstring := range expectedSortedPolicyStrings {
				sphit, err := api.PolicyHitFromFlowLogPolicyString(spstring, expectedCounts[i])
				Expect(err).ShouldNot(HaveOccurred())
				expectedSortedPolicyHits = append(expectedSortedPolicyHits, sphit)
			}
		})

		It("returns the sorted list of PolicyHits", func() {
			By("creating new policy hits from a list of policy strings")
			var policyHits []api.PolicyHit
			counts := [10]int64{1, 1, 0, 19, 19, 7, 18, 16, 5, 0}
			for i, pstrings := range policyStrings {
				phit, err := api.PolicyHitFromFlowLogPolicyString(pstrings, counts[i])
				Expect(err).ShouldNot(HaveOccurred())
				policyHits = append(policyHits, phit)
			}

			By("creating new sorted list of policy hits from policy hits")
			var sortablePolicyHits api.SortablePolicyHits
			for _, pol := range policyHits {
				sortablePolicyHits = append(sortablePolicyHits, pol)
			}

			// Sort the policy hits
			By("sorting the sortablePolicyHits")
			sortablePolicyHits.SortAndRenumber()

			By("verifying the sorted list of policy strings")
			for i, sphit := range expectedSortedPolicyStrings {
				Expect(sortablePolicyHits[i].ToFlowLogPolicyString()).Should(Equal(sphit))
			}

			By("verifying the sorted list of policy hits")

			for i, sphit := range sortablePolicyHits {
				Expect(sphit.Action()).Should(Equal(expectedSortedPolicyHits[i].Action()))
				Expect(sphit.Count()).Should(Equal(expectedSortedPolicyHits[i].Count()))
				Expect(sphit.FlowLogName()).Should(Equal(expectedSortedPolicyHits[i].FlowLogName()))
				Expect(sphit.IsKubernetes()).Should(Equal(expectedSortedPolicyHits[i].IsKubernetes()))
				Expect(sphit.IsProfile()).Should(Equal(expectedSortedPolicyHits[i].IsProfile()))
				Expect(sphit.IsStaged()).Should(Equal(expectedSortedPolicyHits[i].IsStaged()))
				Expect(sphit.Name()).Should(Equal(expectedSortedPolicyHits[i].Name()))
				Expect(sphit.Namespace()).Should(Equal(expectedSortedPolicyHits[i].Namespace()))
				Expect(sphit.RuleIdIndex()).Should(Equal(expectedSortedPolicyHits[i].RuleIdIndex()))
				Expect(sphit.Tier()).Should(Equal(expectedSortedPolicyHits[i].Tier()))
			}
		})
	})
})

func getRefToInt(input int) *int {
	return &input
}
