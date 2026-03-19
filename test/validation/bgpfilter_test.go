// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package validation_test

import (
	"testing"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func communityVal(s string) *v3.BGPCommunityValue {
	v := v3.BGPCommunityValue(s)
	return &v
}

func TestBGPFilter_V4_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "V4 cidr without matchOperator is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{CIDR: "10.0.0.0/24", Action: v3.Accept},
					},
				},
			},
			wantErr: "cidr and matchOperator must both be set or both be empty",
		},
		{
			name: "V4 matchOperator without cidr is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					},
				},
			},
			wantErr: "cidr and matchOperator must both be set or both be empty",
		},
		{
			name: "V4 prefixLength without cidr is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{
							PrefixLength: &v3.BGPFilterPrefixLengthV4{Min: ptr.To[int32](24)},
							Action:       v3.Accept,
						},
					},
				},
			},
			wantErr: "cidr is required when prefixLength is set",
		},
		{
			name: "V4 cidr + matchOperator is accepted",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{CIDR: "10.0.0.0/24", MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					},
				},
			},
		},
		{
			name: "V4 invalid action is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{CIDR: "10.0.0.0/24", MatchOperator: v3.MatchOperatorEqual, Action: "InvalidAction"},
					},
				},
			},
			wantErr: "spec.exportV4[0].action",
		},
		{
			name: "V4 invalid CIDR format is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ImportV4: []v3.BGPFilterRuleV4{
						{CIDR: "invalid-cidr", MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					},
				},
			},
			wantErr: "spec.importV4[0].cidr",
		},
		{
			name: "V4 invalid matchOperator is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{CIDR: "10.0.0.0/24", MatchOperator: "InvalidOperator", Action: v3.Accept},
					},
				},
			},
			wantErr: "spec.exportV4[0].matchOperator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

func TestBGPFilter_V6_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "V6 cidr without matchOperator is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{CIDR: "fd00::/64", Action: v3.Accept},
					},
				},
			},
			wantErr: "cidr and matchOperator must both be set or both be empty",
		},
		{
			name: "V6 matchOperator without cidr is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					},
				},
			},
			wantErr: "cidr and matchOperator must both be set or both be empty",
		},
		{
			name: "V6 prefixLength without cidr is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{
							PrefixLength: &v3.BGPFilterPrefixLengthV6{Min: ptr.To[int32](64)},
							Action:       v3.Accept,
						},
					},
				},
			},
			wantErr: "cidr is required when prefixLength is set",
		},
		{
			name: "V6 cidr + matchOperator is accepted",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{CIDR: "fd00::/64", MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					},
				},
			},
		},
		{
			name: "V6 invalid matchOperator is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{CIDR: "fd00::/64", MatchOperator: "InvalidOperator", Action: v3.Reject},
					},
				},
			},
			wantErr: "spec.exportV6[0].matchOperator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

func TestBGPFilter_Operations_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "operations with Accept action is accepted",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{SetPriority: &v3.BGPFilterSetPriority{Value: ptr.To(100)}},
						},
					},
				}},
			},
		},
		{
			name: "operations with Reject action V4 is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Reject,
						Operations: []v3.BGPFilterOperation{
							{SetPriority: &v3.BGPFilterSetPriority{Value: ptr.To(100)}},
						},
					},
				}},
			},
			wantErr: "operations may only be used with action Accept",
		},
		{
			name: "operations with Reject action V6 is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{
					{
						Action: v3.Reject,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: communityVal("65000:100")}},
						},
					},
				}},
			},
			wantErr: "operations may only be used with action Accept",
		},
		{
			name: "single addCommunity operation is accepted",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: communityVal("65000:100")}},
						},
					},
				}},
			},
		},
		{
			name: "two operation fields set is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{
								AddCommunity: &v3.BGPFilterAddCommunity{Value: communityVal("65000:100")},
								SetPriority:  &v3.BGPFilterSetPriority{Value: ptr.To(100)},
							},
						},
					},
				}},
			},
			wantErr: "must have at most 1",
		},
		{
			name: "all three operation fields set is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{
								AddCommunity:  &v3.BGPFilterAddCommunity{Value: communityVal("65000:100")},
								PrependASPath: &v3.BGPFilterPrependASPath{Prefix: []numorstring.ASNumber{65000}},
								SetPriority:   &v3.BGPFilterSetPriority{Value: ptr.To(100)},
							},
						},
					},
				}},
			},
			wantErr: "must have at most 1",
		},
		{
			name: "source RemotePeers on export rule is accepted",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Source: v3.BGPFilterSourceRemotePeers, Action: v3.Accept},
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

func TestBGPFilter_Community_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "valid standard community in match",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{
						Action:      v3.Accept,
						Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:100"}},
					},
				}},
			},
		},
		{
			name: "valid large community in match",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{
						Action:      v3.Accept,
						Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:100:200"}},
					},
				}},
			},
		},
		{
			name: "invalid standard community with value > 65535",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{
						Action:      v3.Accept,
						Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"70000:100"}},
					},
				}},
			},
			wantErr: "Invalid value",
		},
		{
			name: "invalid community with bad format",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{
						Action:      v3.Accept,
						Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"not-a-community"}},
					},
				}},
			},
			wantErr: "Invalid value",
		},
		{
			name: "valid standard community in AddCommunity",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: communityVal("100:200")}},
						},
					},
				}},
			},
		},
		{
			name: "valid large community in AddCommunity",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: communityVal("65000:100:200")}},
						},
					},
				}},
			},
		},
		{
			name: "invalid AddCommunity with value > 65535",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: communityVal("65536:100")}},
						},
					},
				}},
			},
			wantErr: "Invalid value",
		},
		{
			name: "invalid AddCommunity with bad format",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: communityVal("garbage")}},
						},
					},
				}},
			},
			wantErr: "Invalid value",
		},
		{
			name: "standard community 0:0 (minimum)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"0:0"}}},
				}},
			},
		},
		{
			name: "standard community 65535:65535 (maximum)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65535:65535"}}},
				}},
			},
		},
		{
			name: "invalid standard community 65536:0 (over 16-bit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65536:0"}}},
				}},
			},
			wantErr: "Invalid value",
		},
		{
			name: "large community max 4294967295:4294967295:4294967295",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"4294967295:4294967295:4294967295"}}},
				}},
			},
		},
		{
			name: "invalid large community 4294967296:0:0 (over 32-bit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"4294967296:0:0"}}},
				}},
			},
			wantErr: "Invalid value",
		},
		{
			name: "invalid community: single number",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"12345"}}},
				}},
			},
			wantErr: "Invalid value",
		},
		{
			name: "invalid community: four colons",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"1:2:3:4"}}},
				}},
			},
			wantErr: "Invalid value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}
