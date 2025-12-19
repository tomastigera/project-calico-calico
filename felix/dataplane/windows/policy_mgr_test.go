// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package windataplane

import (
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/dataplane/windows/hns"
	"github.com/projectcalico/calico/felix/dataplane/windows/policysets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

func TestPolicyManager(t *testing.T) {
	RegisterTestingT(t)

	h := mockHNS{}

	ipsc := mockIPSetCache{
		IPSets: map[string][]string{},
	}

	ps := policysets.NewPolicySets(&h, []policysets.IPSetCache{&ipsc}, mockReader(""))
	policyMgr := newPolicyManager(ps)

	pol1ID := proto.PolicyID{Name: "pol1", Kind: v3.KindGlobalNetworkPolicy}
	pol1TID := types.PolicyID{Name: "pol1", Kind: v3.KindGlobalNetworkPolicy}

	// Apply policy update
	policyMgr.OnUpdate(&proto.ActivePolicyUpdate{
		Id: &pol1ID,
		Policy: &proto.Policy{
			Tier: "tier1",
			InboundRules: []*proto.Rule{
				{Action: "deny"},
			},
			OutboundRules: []*proto.Rule{
				{Action: "allow"},
			},
		},
	})

	// assertion for ingress rules
	Expect(ps.GetPolicySetRules([]types.IDMaker{&pol1TID}, true, true)).To(Equal([]*hns.ACLPolicy{
		// policy-pol1 deny rule should be present
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: hns.Block, Direction: hns.In, RuleType: hns.Switch, Priority: 1000},
		// Default deny rule.
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: hns.Block, Direction: hns.In, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned for ingress rules update for policy-pol1")

	// assertion for ingress rules with endOfTierDrop disabled
	Expect(ps.GetPolicySetRules([]types.IDMaker{&pol1TID}, true, false)).To(Equal([]*hns.ACLPolicy{
		// policy-pol1 deny rule should be present
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: hns.Block, Direction: hns.In, RuleType: hns.Switch, Priority: 1000},
		// Default deny rule.
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: policysets.ActionPass, Direction: hns.In, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned for ingress rules update for policy-pol1")

	// assertion for egress rules
	Expect(ps.GetPolicySetRules([]types.IDMaker{&pol1TID}, false, true)).To(Equal([]*hns.ACLPolicy{
		// policy-pol1 allow rule should be present
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: hns.Allow, Direction: hns.Out, RuleType: hns.Switch, Priority: 1000},
		// Default deny rule.
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: hns.Block, Direction: hns.Out, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned for egress rules update for policy-pol1")

	// assertion for egress rules with endOfTierDrop disabled
	Expect(ps.GetPolicySetRules([]types.IDMaker{&pol1TID}, false, false)).To(Equal([]*hns.ACLPolicy{
		// policy-pol1 allow rule should be present
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: hns.Allow, Direction: hns.Out, RuleType: hns.Switch, Priority: 1000},
		// Default deny rule.
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: policysets.ActionPass, Direction: hns.Out, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned for egress rules update for policy-pol1")

	// remove policy here
	policyMgr.OnUpdate(&proto.ActivePolicyRemove{
		Id: &proto.PolicyID{Name: "pol1", Kind: v3.KindGlobalNetworkPolicy},
	})

	Expect(ps.GetPolicySetRules([]types.IDMaker{&pol1TID}, true, true)).To(Equal([]*hns.ACLPolicy{
		// Default deny rule.
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: hns.Block, Direction: hns.In, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned after ActivePolicyRemove event for policy-pol1")

	// default ingress rule with endOfTierDrop disabled
	Expect(ps.GetPolicySetRules([]types.IDMaker{&pol1TID}, true, false)).To(Equal([]*hns.ACLPolicy{
		// Default pass rule.
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: policysets.ActionPass, Direction: hns.In, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned after ActivePolicyRemove event for policy-pol1")

	// default egress rule
	Expect(ps.GetPolicySetRules([]types.IDMaker{&pol1TID}, false, true)).To(Equal([]*hns.ACLPolicy{
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: hns.Block, Direction: hns.Out, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned after ActivePolicyRemove event for policy-pol1")

	// default egress rule with endOfTierDrop disabled
	Expect(ps.GetPolicySetRules([]types.IDMaker{&pol1TID}, false, false)).To(Equal([]*hns.ACLPolicy{
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: policysets.ActionPass, Direction: hns.Out, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned after ActivePolicyRemove event for policy-pol1")

	// Apply profile update
	policyMgr.OnUpdate(&proto.ActiveProfileUpdate{
		Id: &proto.ProfileID{Name: "prof1"},
		Profile: &proto.Profile{
			InboundRules: []*proto.Rule{
				{Action: "deny"},
			},
			OutboundRules: []*proto.Rule{
				{Action: "allow"},
			},
		},
	})

	// assertion for ingress rules
	Expect(ps.GetPolicySetRules([]types.IDMaker{types.ProfileID{Name: "prof1"}}, true, true)).To(Equal([]*hns.ACLPolicy{
		// profile-prof1 deny rule should be present
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: hns.Block, Direction: hns.In, RuleType: hns.Switch, Priority: 1000},
		// Default deny rule.
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: hns.Block, Direction: hns.In, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned for ingress rules update for profile-prof1")

	// assertion for ingress rules with endOfTierDrop disabled
	Expect(ps.GetPolicySetRules([]types.IDMaker{types.ProfileID{Name: "prof1"}}, true, false)).To(Equal([]*hns.ACLPolicy{
		// profile-prof1 deny rule should be present
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: hns.Block, Direction: hns.In, RuleType: hns.Switch, Priority: 1000},
		// Default deny rule.
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: policysets.ActionPass, Direction: hns.In, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned for ingress rules update for profile-prof1")

	// assertion for egress rules
	Expect(ps.GetPolicySetRules([]types.IDMaker{types.ProfileID{Name: "prof1"}}, false, true)).To(Equal([]*hns.ACLPolicy{
		// profile-pol1 allow rule should be present
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: hns.Allow, Direction: hns.Out, RuleType: hns.Switch, Priority: 1000},
		// Default deny rule.
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: hns.Block, Direction: hns.Out, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned for egress rules update for profile-prof1")

	// assertion for egress rules
	Expect(ps.GetPolicySetRules([]types.IDMaker{types.ProfileID{Name: "prof1"}}, false, false)).To(Equal([]*hns.ACLPolicy{
		// profile-pol1 allow rule should be present
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: hns.Allow, Direction: hns.Out, RuleType: hns.Switch, Priority: 1000},
		// Default deny rule.
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: policysets.ActionPass, Direction: hns.Out, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned for egress rules update for profile-prof1")

	// remove profile update
	policyMgr.OnUpdate(&proto.ActiveProfileRemove{
		Id: &proto.ProfileID{Name: "prof1"},
	})

	// default ingress rule
	Expect(ps.GetPolicySetRules([]types.IDMaker{types.ProfileID{Name: "prof1"}}, true, true)).To(Equal([]*hns.ACLPolicy{
		// Default deny rule.
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: hns.Block, Direction: hns.In, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned after ActiveProfileRemove event for profile-prof1")

	// Should skip staged policy
	// Apply policy update
	policyMgr.OnUpdate(&proto.ActivePolicyUpdate{
		Id: &proto.PolicyID{Name: "pol1", Kind: v3.KindStagedGlobalNetworkPolicy},
		Policy: &proto.Policy{
			Tier: "tier1",
			InboundRules: []*proto.Rule{
				{Action: "allow"},
			},
		},
	})

	// assertion for ingress rules
	Expect(ps.GetPolicySetRules([]types.IDMaker{types.PolicyID{Name: "policypol1", Kind: v3.KindStagedGlobalNetworkPolicy}}, true, true)).To(Equal([]*hns.ACLPolicy{
		// Default deny rule.
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: hns.Block, Direction: hns.In, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned for ingress rules update for policy-staged:pol1")
	// default ingress rule with endOfTierDrop disabled
	Expect(ps.GetPolicySetRules([]types.IDMaker{types.ProfileID{Name: "prof1"}}, true, false)).To(Equal([]*hns.ACLPolicy{
		// Default pass rule.
		{Type: hns.ACL, Id: "DRI", Protocol: 256, Action: policysets.ActionPass, Direction: hns.In, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned after ActiveProfileRemove event for profile-prof1")

	// default egress rule
	Expect(ps.GetPolicySetRules([]types.IDMaker{types.ProfileID{Name: "prof1"}}, false, true)).To(Equal([]*hns.ACLPolicy{
		// Default deny rule.
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: hns.Block, Direction: hns.Out, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned after ActiveProfileRemove event for profile-prof1")

	// default egress rule with endOfTierDrop disabled
	Expect(ps.GetPolicySetRules([]types.IDMaker{types.ProfileID{Name: "prof1"}}, false, false)).To(Equal([]*hns.ACLPolicy{
		// Default pass rule.
		{Type: hns.ACL, Id: "DRE", Protocol: 256, Action: policysets.ActionPass, Direction: hns.Out, RuleType: hns.Switch, Priority: 1001},
	}), "unexpected rules returned after ActiveProfileRemove event for profile-prof1")
}

type mockHNS struct {
	SupportedFeatures hns.HNSSupportedFeatures
}

func (h *mockHNS) GetHNSSupportedFeatures() hns.HNSSupportedFeatures {
	return h.SupportedFeatures
}

type mockIPSetCache struct {
	IPSets map[string][]string
}

func (c *mockIPSetCache) GetIPSetMembers(ipsetID string) []string {
	return c.IPSets[ipsetID]
}

type mockReader string

func (m mockReader) ReadData() ([]byte, error) {
	if len(m) == 0 {
		return []byte{}, policysets.ErrNoRuleSpecified
	}
	return []byte(string(m)), nil
}
