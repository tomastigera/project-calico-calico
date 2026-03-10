// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
package api_test

import (
	"fmt"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/lma/pkg/api"
)

type expectedHit struct {
	name        string
	namespace   string
	kind        string
	tier        string
	action      api.Action
	index       int
	flowLogName string
	isKNP       bool
	isProfile   bool
	isStaged    bool
	ruleIndex   *int
}

var _ = Describe("PolicyHitFromFlowLogPolicyString", func() {
	DescribeTable("Successful PolicyHit parsing",
		func(policyStr string, expected expectedHit, expectedPolicyString string) {
			// Parse the policy string.
			policyHit, err := api.PolicyHitFromFlowLogPolicyString(policyStr)
			Expect(err).ShouldNot(HaveOccurred())

			// Verify the fields.
			Expect(policyHit.Name()).Should(Equal(expected.name), policyStr)
			Expect(policyHit.Action()).Should(Equal(expected.action), policyStr)
			Expect(policyHit.Index()).Should(Equal(expected.index), policyStr)
			Expect(policyHit.Tier()).Should(Equal(expected.tier), policyStr)
			Expect(policyHit.RuleIndex()).Should(Equal(expected.ruleIndex), policyStr)
			Expect(api.HitFlowLogName(policyHit)).Should(Equal(expected.flowLogName), policyStr)
			Expect(policyHit.Namespace()).Should(Equal(expected.namespace), policyStr)
			Expect(api.IsKubernetes(policyHit.Kind())).Should(Equal(expected.isKNP), policyStr)
			Expect(api.IsProfile(policyHit.Kind())).Should(Equal(expected.isProfile), policyStr)
			Expect(api.IsStaged(policyHit.Kind())).Should(Equal(expected.isStaged), policyStr)
			Expect(api.ToFlowLogPolicyString(policyHit)).Should(Equal(expectedPolicyString), policyStr)
			Expect(policyHit.Kind()).Should(Equal(expected.kind), policyStr)
		},

		Entry(
			"properly handles a (legacy) network policy",
			"4|tierName|namespaceName/tierName.policyName|allow",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "tierName.policyName", kind: v3.KindNetworkPolicy,
				flowLogName: "np:namespaceName/tierName.policyName", namespace: "namespaceName",
				ruleIndex: nil, isKNP: false, isProfile: false, isStaged: false,
			},
			"4|tierName|np:namespaceName/tierName.policyName|allow|-",
		),

		// Older versions of Calico used tier.staged:name, but newer versions do not include
		// the tier in the ID section of the policy string. This test reads the old style but
		// the policy hit code now outputs the new style.
		Entry(
			"properly handles a (legacy) staged network policy",
			"4|tierName|namespaceName/tierName.staged:policyName|deny",
			expectedHit{
				action: api.ActionDeny, index: 4, tier: "tierName", name: "tierName.policyName", kind: v3.KindStagedNetworkPolicy,
				flowLogName: "snp:namespaceName/tierName.policyName", namespace: "namespaceName",
				ruleIndex: nil, isKNP: false, isProfile: false, isStaged: true,
			},
			"4|tierName|snp:namespaceName/tierName.policyName|deny|-",
		),
		Entry(
			"properly handles a (legacy) staged global network policy",
			"4|tierName|tierName.staged:policyName|allow",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "tierName.policyName", kind: v3.KindStagedGlobalNetworkPolicy,
				flowLogName: "sgnp:tierName.policyName", namespace: "", ruleIndex: nil,
				isKNP: false, isProfile: false, isStaged: true,
			},
			"4|tierName|sgnp:tierName.policyName|allow|-",
		),
		Entry(
			"properly handles a (legacy) staged network policy",
			"4|tierName|namespaceName/tierName.staged:policyName|deny|-1",
			expectedHit{
				action: api.ActionDeny, index: 4, tier: "tierName", name: "tierName.policyName", kind: v3.KindStagedNetworkPolicy,
				flowLogName: "snp:namespaceName/tierName.policyName", namespace: "namespaceName",
				ruleIndex: ptr.To(-1), isKNP: false, isProfile: false, isStaged: true,
			},
			"4|tierName|snp:namespaceName/tierName.policyName|deny|-1",
		),
		Entry(
			"properly handles a (legacy) staged global network policy",
			"4|tierName|tierName.staged:policyName|allow|1",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "tierName.policyName", kind: v3.KindStagedGlobalNetworkPolicy,
				flowLogName: "sgnp:tierName.policyName", namespace: "", ruleIndex: ptr.To(1),
				isKNP: false, isProfile: false, isStaged: true,
			},
			"4|tierName|sgnp:tierName.policyName|allow|1",
		),

		// Same tests from above, but with new style input - should give us the same output.
		Entry(
			"properly handles a staged network policy",
			"4|tierName|snp:namespaceName/tierName.policyName|deny",
			expectedHit{
				action: api.ActionDeny, index: 4, tier: "tierName", name: "tierName.policyName", kind: v3.KindStagedNetworkPolicy,
				flowLogName: "snp:namespaceName/tierName.policyName", namespace: "namespaceName",
				ruleIndex: nil, isKNP: false, isProfile: false, isStaged: true,
			},
			"4|tierName|snp:namespaceName/tierName.policyName|deny|-",
		),

		Entry(
			"properly handles a global network policy",
			"4|tierName|gnp:tierName.policyName|allow",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "tierName.policyName", kind: v3.KindGlobalNetworkPolicy,
				flowLogName: "gnp:tierName.policyName", namespace: "", ruleIndex: nil, isKNP: false,
				isProfile: false, isStaged: false,
			},
			"4|tierName|gnp:tierName.policyName|allow|-",
		),
		Entry(
			"properly handles a kubernetes network policy",
			"4|default|knp:namespaceName/policyName|allow",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "default", name: "policyName", kind: model.KindKubernetesNetworkPolicy,
				flowLogName: "knp:namespaceName/policyName", namespace: "namespaceName",
				ruleIndex: nil, isKNP: true, isStaged: false,
			},
			"4|default|knp:namespaceName/policyName|allow|-",
		),
		Entry(
			"properly handles a staged kubernetes network policy",
			"4|default|sknp:namespaceName/policyName|deny",
			expectedHit{
				action: api.ActionDeny, index: 4, tier: "default", name: "policyName", kind: v3.KindStagedKubernetesNetworkPolicy,
				flowLogName: "sknp:namespaceName/policyName", namespace: "namespaceName",
				ruleIndex: nil, isKNP: true, isProfile: false, isStaged: true,
			},
			"4|default|sknp:namespaceName/policyName|deny|-",
		),
		Entry(
			"properly handles a kubernetes namespace profile",
			"4|__PROFILE__|pro:kns.namespaceName|allow",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "__PROFILE__", name: "kns.namespaceName", kind: v3.KindProfile,
				flowLogName: "pro:kns.namespaceName", namespace: "", ruleIndex: nil,
				isKNP: false, isProfile: true, isStaged: false,
			},
			"4|__PROFILE__|pro:kns.namespaceName|allow|-",
		),
		Entry(
			"properly handles a network policy",
			"4|tierName|np:namespaceName/policyName|allow|1",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "policyName", kind: v3.KindNetworkPolicy,
				flowLogName: "np:namespaceName/policyName", namespace: "namespaceName",
				ruleIndex: ptr.To(1), isKNP: false, isProfile: false, isStaged: false,
			},
			"4|tierName|np:namespaceName/policyName|allow|1",
		),
		Entry(
			"properly handles a global network policy",
			"4|tierName|gnp:policyName|allow|0",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "tierName", name: "policyName", kind: v3.KindGlobalNetworkPolicy,
				flowLogName: "gnp:policyName", namespace: "", ruleIndex: ptr.To(0),
				isKNP: false, isProfile: false, isStaged: false,
			},
			"4|tierName|gnp:policyName|allow|0",
		),
		Entry(
			"properly handles a kubernetes network policy",
			"4|default|knp:namespaceName/policyName|allow|2",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "default", name: "policyName", kind: model.KindKubernetesNetworkPolicy,
				flowLogName: "knp:namespaceName/policyName", namespace: "namespaceName",
				ruleIndex: ptr.To(2), isKNP: true, isStaged: false,
			},
			"4|default|knp:namespaceName/policyName|allow|2",
		),
		Entry(
			"properly handles a staged kubernetes network policy",
			"4|default|sknp:namespaceName/policyName|deny|10",
			expectedHit{
				action: api.ActionDeny, index: 4, tier: "default", name: "policyName", kind: v3.KindStagedKubernetesNetworkPolicy,
				flowLogName: "sknp:namespaceName/policyName", namespace: "namespaceName",
				ruleIndex: ptr.To(10), isKNP: true, isProfile: false, isStaged: true,
			},
			"4|default|sknp:namespaceName/policyName|deny|10",
		),
		Entry(
			"properly handles a kubernetes namespace profile",
			"4|__PROFILE__|pro:kns.namespaceName|allow|4",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "__PROFILE__", name: "kns.namespaceName", kind: v3.KindProfile,
				flowLogName: "pro:kns.namespaceName", namespace: "", ruleIndex: ptr.To(4),
				isKNP: false, isProfile: true, isStaged: false,
			},
			"4|__PROFILE__|pro:kns.namespaceName|allow|4",
		),
		Entry(
			"properly handles a kubernetes namespace profile",
			"4|__PROFILE__|pro:kns.namespaceName|allow|-",
			expectedHit{
				action: api.ActionAllow, index: 4, tier: "__PROFILE__", name: "kns.namespaceName", kind: v3.KindProfile,
				flowLogName: "pro:kns.namespaceName", namespace: "", ruleIndex: nil,
				isKNP: false, isProfile: true, isStaged: false,
			},
			"4|__PROFILE__|pro:kns.namespaceName|allow|-",
		),
	)

	DescribeTable("Unsuccessful PolicyHit parsing",
		func(policyStr string, expectedErr error) {
			_, err := api.PolicyHitFromFlowLogPolicyString(policyStr)
			Expect(err).Should(Equal(expectedErr))
		},
		Entry(
			"fails to parse a policy string with extra pipes",
			"4|tier1|namespace1/policy1|allow|0|extra",
			fmt.Errorf("invalid policy string '4|tier1|namespace1/policy1|allow|0|extra': pipe "+
				"count must equal 5 for a new or 4 for an old version of the policy string"),
		),
		Entry(
			"fails to parse a policy string with extra pipes",
			"4|tier1|namespace1/policy1|allow|0|extra|extra",
			fmt.Errorf("invalid policy string '4|tier1|namespace1/policy1|allow|0|extra|extra': pipe "+
				"count must equal 5 for a new or 4 for an old version of the policy string"),
		),
		Entry(
			"fails to parse a policy string with extra pipes",
			"4|tier1|namespace1/policy1",
			fmt.Errorf("invalid policy string '4|tier1|namespace1/policy1': pipe "+
				"count must equal 5 for a new or 4 for an old version of the policy string"),
		),
		Entry(
			"fails to parse a policy string with an invalid index",
			"x|tier1|namespace1/policy1|allow|0",
			fmt.Errorf("invalid policy index: %w",
				&strconv.NumError{Func: "Atoi", Num: "x", Err: fmt.Errorf("invalid syntax")}),
		),
		Entry(
			"fails to parse a policy string with an invalid index",
			"4|tier1|namespace1/policy1|badaction|0",
			fmt.Errorf("invalid action 'badaction'"),
		),
		Entry(
			"fails to parse a policy string with extra pipes",
			"4|tier1|namespace1/policy1|",
			fmt.Errorf("invalid action ''"),
		),
		Entry(
			"fails to parse a policy string with an invalid rule index",
			"4|tier1|namespace1/policy1|deny|x",
			fmt.Errorf("invalid policy rule index: %w",
				&strconv.NumError{Func: "Atoi", Num: "x", Err: fmt.Errorf("invalid syntax")}),
		),
		Entry(
			"fails to parse a policy string with an invalid rule index",
			"4|tier1|namespace1/policy1|deny|",
			fmt.Errorf("invalid policy rule index: %w",
				&strconv.NumError{Func: "Atoi", Num: "", Err: fmt.Errorf("invalid syntax")}),
		),
	)
})

var _ = Describe("NewPolicyHit", func() {
	DescribeTable("Creating a valid policy hit", func(
		action api.Action, index int, name, namespace, kind, tier string,
		ruleIndex *int, fullName, policyString string,
	) {
		policyHit, err := api.NewPolicyHit(action, index, name, namespace, kind, tier, ruleIndex)
		Expect(err).ShouldNot(HaveOccurred())

		Expect(api.HitFlowLogName(policyHit)).Should(Equal(fullName))
		polstr := api.ToFlowLogPolicyString(policyHit)
		Expect(polstr).Should(Equal(policyString))
	},
		Entry(
			"properly handles a network policy",
			api.ActionAllow, 4, "foo.policyName", "namespaceName", v3.KindNetworkPolicy, "tierName", ptr.To(0),
			"np:namespaceName/foo.policyName",
			"4|tierName|np:namespaceName/foo.policyName|allow|0",
		),
		Entry(
			"properly handles a staged network policy",
			api.ActionDeny, 4, "tierName.policyName", "namespaceName", v3.KindStagedNetworkPolicy, "tierName", ptr.To(-1),
			"snp:namespaceName/tierName.policyName",
			"4|tierName|snp:namespaceName/tierName.policyName|deny|-1",
		),
		Entry(
			"properly handles a staged global network policy",
			api.ActionAllow, 4, "tierName.policyName", "", v3.KindStagedGlobalNetworkPolicy, "tierName", ptr.To(2),
			"sgnp:tierName.policyName",
			"4|tierName|sgnp:tierName.policyName|allow|2",
		),
		Entry(
			"properly handles a global network policy",
			api.ActionAllow, 4, "policyName", "", v3.KindGlobalNetworkPolicy, "tierName", ptr.To(1),
			"gnp:policyName",
			"4|tierName|gnp:policyName|allow|1",
		),
		Entry(
			"properly handles a kubernetes network policy",
			api.ActionAllow, 4, "policyName", "namespaceName", model.KindKubernetesNetworkPolicy, "default", ptr.To(3),
			"knp:namespaceName/policyName",
			"4|default|knp:namespaceName/policyName|allow|3",
		),
		Entry(
			"properly handles a staged kubernetes network policy",
			api.ActionDeny, 4, "policyName", "namespaceName", v3.KindStagedKubernetesNetworkPolicy, "default",
			ptr.To(-1), "sknp:namespaceName/policyName",
			"4|default|sknp:namespaceName/policyName|deny|-1",
		),
		Entry(
			"properly handles a kubernetes namespace profile",
			api.ActionAllow, 4, "kns.namespaceName", "", v3.KindProfile, "__PROFILE__", ptr.To(0),
			"pro:kns.namespaceName",
			"4|__PROFILE__|pro:kns.namespaceName|allow|0",
		),
		Entry(
			"properly handles a kubernetes namespace profile with no rule index",
			api.ActionAllow, 4, "kns.namespaceName", "", v3.KindProfile, "__PROFILE__", nil,
			"pro:kns.namespaceName",
			"4|__PROFILE__|pro:kns.namespaceName|allow|-",
		),
	)

	DescribeTable("Creating an invalid policy hit", func(
		action api.Action, index int, name, namespace, kind, tier string,
		ruleIndex *int, expectedErr error,
	) {
		_, err := api.NewPolicyHit(action, index, name, namespace, kind, tier, ruleIndex)
		Expect(err).Should(Equal(expectedErr))
	},
		Entry(
			"returns an error when action the is empty",
			api.ActionInvalid, 4, "tierName.policyName", "namespaceName", v3.KindNetworkPolicy, "tierName",
			ptr.To(0),
			fmt.Errorf("a none empty Action must be provided"),
		),
		Entry(
			"returns an error when the index is negative",
			api.ActionDeny, -1, "tierName.policyName", "namespaceName", v3.KindNetworkPolicy, "tierName",
			ptr.To(-1),
			fmt.Errorf("index must be a positive integer"),
		),
		Entry(
			"returns an error when the rule index is not -1 and negative",
			api.ActionAllow, 4, "policyName", "namespaceName", v3.KindNetworkPolicy, "tierName", ptr.To(-2),
			fmt.Errorf("rule index must be a positive integer or -1"),
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
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(true))
		})

		It("compares unequal lists of policyHits, where the difference lies in the index", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|pass|-1")
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("4|tierName1|ns4/tierName1.p7|pass|-1")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})

		It("compares unequal lists of policyHits, where the difference lies in the tier", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|pass|-1")
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName2|ns4/tierName2.p7|pass|-1")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})

		It("compares unequal lists of policyHits, where the difference lies in the namespace", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|pass|-1")
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns3/tierName1.p7|pass|-1")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})

		It("compares unequal lists of policyHits, where the difference lies in the name", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|pass|-1")
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p8|pass|-1")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})

		It("compares unequal lists of policyHits, where the difference lies in the action", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|pass|-1")
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|deny|-1")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})

		It("compares unequal lists of policyHits, where the difference lies in the rule index", func() {
			var policyHits1 []api.PolicyHit
			var policyHits2 []api.PolicyHit
			for _, ps := range pstrings1 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits1 = append(policyHits1, ph)
			}
			for _, ps := range pstrings2 {
				ph, err := api.PolicyHitFromFlowLogPolicyString(ps)
				Expect(err).ShouldNot(HaveOccurred())
				policyHits2 = append(policyHits2, ph)
			}

			var err error
			policyHits1[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|deny|-1")
			Expect(err).ShouldNot(HaveOccurred())
			policyHits2[5], err = api.PolicyHitFromFlowLogPolicyString("3|tierName1|ns4/tierName1.p7|deny|1")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(api.PolicyHitsEqual(policyHits1, policyHits2)).Should(Equal(false))
		})
	})

	When("sorting PolicyHits (mixed of old and new policy string types)", func() {
		var policyStrings [10]string
		var expectedSortedPolicyStrings [10]string
		var expectedSortedPolicyHits []api.PolicyHit

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

			expectedSortedPolicyStrings = [10]string{
				"0|tierName3|np:ns1/tierName3.p1|allow|-",
				"1|tierName3|np:ns1/tierName3.p5|allow|2",
				"2|tierName1|np:ns2/tierName1.p3|allow|2",
				"3|tierName1|np:ns2/tierName1.p3|deny|-1",
				"4|tierName1|snp:ns2/tierName1.p3.|allow|2",
				"5|tierName0|np:ns3/tierName0.p0|pass|0",
				"6|tierName1|np:ns4/tierName1.p7|pass|-1",
				"7|tierName6|np:ns5/tierName6.p4|deny|3",
				"8|tierName5|np:ns4/tierName5.p8|deny|-",
				"9|tierName6|np:ns3/tierName6.p0|allow|-1",
			}

			By("creating expected sorted policy hits from a list of sorted policy strings")
			for _, spstring := range expectedSortedPolicyStrings {
				sphit, err := api.PolicyHitFromFlowLogPolicyString(spstring)
				Expect(err).ShouldNot(HaveOccurred())
				expectedSortedPolicyHits = append(expectedSortedPolicyHits, sphit)
			}
		})

		It("returns the sorted list of PolicyHits", func() {
			By("creating new policy hits from a list of policy strings")
			var policyHits []api.PolicyHit
			for _, pstrings := range policyStrings {
				phit, err := api.PolicyHitFromFlowLogPolicyString(pstrings)
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
				Expect(api.ToFlowLogPolicyString(sortablePolicyHits[i])).Should(Equal(sphit))
			}

			By("verifying the sorted list of policy hits")

			for i, sphit := range sortablePolicyHits {
				Expect(sphit.Action()).Should(Equal(expectedSortedPolicyHits[i].Action()))
				Expect(api.HitFlowLogName(sphit)).Should(Equal(api.HitFlowLogName(expectedSortedPolicyHits[i])))
				Expect(api.IsKubernetes(sphit.Kind())).Should(Equal(api.IsKubernetes(expectedSortedPolicyHits[i].Kind())))
				Expect(api.IsProfile(sphit.Kind())).Should(Equal(api.IsProfile(expectedSortedPolicyHits[i].Kind())))
				Expect(api.IsStaged(sphit.Kind())).Should(Equal(api.IsStaged(expectedSortedPolicyHits[i].Kind())))
				Expect(sphit.Name()).Should(Equal(expectedSortedPolicyHits[i].Name()))
				Expect(sphit.Namespace()).Should(Equal(expectedSortedPolicyHits[i].Namespace()))
				Expect(sphit.RuleIndex()).Should(Equal(expectedSortedPolicyHits[i].RuleIndex()))
				Expect(sphit.Tier()).Should(Equal(expectedSortedPolicyHits[i].Tier()))
			}
		})
	})
})
