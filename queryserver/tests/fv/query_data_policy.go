// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.
package fv

import (
	"net/http"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/client"
)

const (
	// Get the maximum value of an int - we use this for some high limit testing.
	maxUint = ^uint(0)
	maxInt  = int(maxUint >> 1)
)

func policyTestQueryData() []testQueryData {
	// Create the query Policy resources for the tier 1 policies that have some selectors in the rules.  We create them
	// and tweak the rule counts to adjust for the selectors that are not all().
	qcPolicy_gnp2_t1_all_res := qcPolicy(gnp2_t1_o4, 4, 4, 0, 0)
	qcPolicy_gnp2_t1_all_res.IngressRules[0].Destination.NumHostEndpoints = 2
	qcPolicy_gnp2_t1_all_res.IngressRules[0].Destination.NumWorkloadEndpoints = 0
	qcPolicy_gnp2_t1_all_res.IngressRules[1].Destination.NumHostEndpoints = 2
	qcPolicy_gnp2_t1_all_res.IngressRules[1].Destination.NumWorkloadEndpoints = 1
	qcPolicy_gnp2_t1_all_res.IngressRules[1].Source.NumHostEndpoints = 4
	qcPolicy_gnp2_t1_all_res.IngressRules[1].Source.NumWorkloadEndpoints = 4
	qcPolicy_gnp2_t1_all_res.EgressRules[0].Source.NumHostEndpoints = 4
	qcPolicy_gnp2_t1_all_res.EgressRules[0].Source.NumWorkloadEndpoints = 2
	qcPolicy_gnp2_t1_all_res.EgressRules[1].Source.NumHostEndpoints = 1
	qcPolicy_gnp2_t1_all_res.EgressRules[1].Source.NumWorkloadEndpoints = 1

	qcPolicy_sgnp2_t1_all_res := qcPolicy(sgnp2_t1_o4, 4, 4, 0, 0)
	qcPolicy_sgnp2_t1_all_res.IngressRules[0].Destination.NumHostEndpoints = 2
	qcPolicy_sgnp2_t1_all_res.IngressRules[0].Destination.NumWorkloadEndpoints = 0
	qcPolicy_sgnp2_t1_all_res.IngressRules[1].Destination.NumHostEndpoints = 2
	qcPolicy_sgnp2_t1_all_res.IngressRules[1].Destination.NumWorkloadEndpoints = 1
	qcPolicy_sgnp2_t1_all_res.IngressRules[1].Source.NumHostEndpoints = 4
	qcPolicy_sgnp2_t1_all_res.IngressRules[1].Source.NumWorkloadEndpoints = 4
	qcPolicy_sgnp2_t1_all_res.EgressRules[0].Source.NumHostEndpoints = 4
	qcPolicy_sgnp2_t1_all_res.EgressRules[0].Source.NumWorkloadEndpoints = 2
	qcPolicy_sgnp2_t1_all_res.EgressRules[1].Source.NumHostEndpoints = 1
	qcPolicy_sgnp2_t1_all_res.EgressRules[1].Source.NumWorkloadEndpoints = 1

	qcPolicy_gnp1_t1_all_res_more := qcPolicy(gnp1_t1_o4_more_rules, 1, 3, 0, 0)
	qcPolicy_gnp1_t1_all_res_more.IngressRules[0].Destination.NumHostEndpoints = 2
	qcPolicy_gnp1_t1_all_res_more.IngressRules[0].Destination.NumWorkloadEndpoints = 0
	// qcPolicy_gnp1_t1_all_res_more.IngressRules[0].Source.NumHostEndpoints = 4
	// qcPolicy_gnp1_t1_all_res_more.IngressRules[0].Source.NumWorkloadEndpoints = 4
	qcPolicy_gnp1_t1_all_res_more.EgressRules[0].Source.NumHostEndpoints = 4
	qcPolicy_gnp1_t1_all_res_more.EgressRules[0].Source.NumWorkloadEndpoints = 2

	qcPolicy_gnp2_t1_all_res_fewer := qcPolicy(gnp2_t1_o3_fewer_rules, 4, 4, 0, 0)
	qcPolicy_gnp2_t1_all_res_fewer.IngressRules[0].Destination.NumHostEndpoints = 2
	qcPolicy_gnp2_t1_all_res_fewer.IngressRules[0].Destination.NumWorkloadEndpoints = 1
	qcPolicy_gnp2_t1_all_res_fewer.IngressRules[0].Source.NumHostEndpoints = 4
	qcPolicy_gnp2_t1_all_res_fewer.IngressRules[0].Source.NumWorkloadEndpoints = 4
	qcPolicy_gnp2_t1_all_res_fewer.EgressRules[0].Source.NumHostEndpoints = 1
	qcPolicy_gnp2_t1_all_res_fewer.EgressRules[0].Source.NumWorkloadEndpoints = 1

	qcPolicy_gnp1_t1_all_res_more_updated_wep1 := qcPolicy(gnp1_t1_o4_more_rules, 1, 2, 0, 0)
	qcPolicy_gnp1_t1_all_res_more_updated_wep1.IngressRules[0].Destination.NumHostEndpoints = 2
	qcPolicy_gnp1_t1_all_res_more_updated_wep1.IngressRules[0].Destination.NumWorkloadEndpoints = 1
	qcPolicy_gnp1_t1_all_res_more_updated_wep1.EgressRules[0].Source.NumHostEndpoints = 4
	qcPolicy_gnp1_t1_all_res_more_updated_wep1.EgressRules[0].Source.NumWorkloadEndpoints = 3

	qcPolicy_gnp2_t1_all_res_fewer_updated_wep1 := qcPolicy(gnp2_t1_o3_fewer_rules, 4, 4, 0, 0)
	qcPolicy_gnp2_t1_all_res_fewer_updated_wep1.IngressRules[0].Destination.NumHostEndpoints = 2
	qcPolicy_gnp2_t1_all_res_fewer_updated_wep1.IngressRules[0].Destination.NumWorkloadEndpoints = 1
	qcPolicy_gnp2_t1_all_res_fewer_updated_wep1.IngressRules[0].Source.NumHostEndpoints = 4
	qcPolicy_gnp2_t1_all_res_fewer_updated_wep1.IngressRules[0].Source.NumWorkloadEndpoints = 4
	qcPolicy_gnp2_t1_all_res_fewer_updated_wep1.EgressRules[0].Source.NumHostEndpoints = 1
	qcPolicy_gnp2_t1_all_res_fewer_updated_wep1.EgressRules[0].Source.NumWorkloadEndpoints = 1

	qcPolicy_gnp2_t1_no_ns2_no_rackless := qcPolicy(gnp2_t1_o4, 3, 2, 0, 0)
	qcPolicy_gnp2_t1_no_ns2_no_rackless.IngressRules[0].Destination.NumHostEndpoints = 2
	qcPolicy_gnp2_t1_no_ns2_no_rackless.IngressRules[0].Destination.NumWorkloadEndpoints = 0
	qcPolicy_gnp2_t1_no_ns2_no_rackless.IngressRules[1].Destination.NumHostEndpoints = 1
	qcPolicy_gnp2_t1_no_ns2_no_rackless.IngressRules[1].Destination.NumWorkloadEndpoints = 0
	qcPolicy_gnp2_t1_no_ns2_no_rackless.IngressRules[1].Source.NumHostEndpoints = 3
	qcPolicy_gnp2_t1_no_ns2_no_rackless.IngressRules[1].Source.NumWorkloadEndpoints = 2
	qcPolicy_gnp2_t1_no_ns2_no_rackless.EgressRules[0].Source.NumHostEndpoints = 3
	qcPolicy_gnp2_t1_no_ns2_no_rackless.EgressRules[0].Source.NumWorkloadEndpoints = 1
	qcPolicy_gnp2_t1_no_ns2_no_rackless.EgressRules[1].Source.NumHostEndpoints = 1
	qcPolicy_gnp2_t1_no_ns2_no_rackless.EgressRules[1].Source.NumWorkloadEndpoints = 1

	qcPolicy_gnp2_t1_all_res_with_index := qcPolicyWithIdx(gnp2_t1_o4, 3, 4, 4, 0, 0)
	qcPolicy_gnp2_t1_all_res_with_index.IngressRules[0].Destination.NumHostEndpoints = 2
	qcPolicy_gnp2_t1_all_res_with_index.IngressRules[0].Destination.NumWorkloadEndpoints = 0
	qcPolicy_gnp2_t1_all_res_with_index.IngressRules[1].Destination.NumHostEndpoints = 2
	qcPolicy_gnp2_t1_all_res_with_index.IngressRules[1].Destination.NumWorkloadEndpoints = 1
	qcPolicy_gnp2_t1_all_res_with_index.IngressRules[1].Source.NumHostEndpoints = 4
	qcPolicy_gnp2_t1_all_res_with_index.IngressRules[1].Source.NumWorkloadEndpoints = 4
	qcPolicy_gnp2_t1_all_res_with_index.EgressRules[0].Source.NumHostEndpoints = 4
	qcPolicy_gnp2_t1_all_res_with_index.EgressRules[0].Source.NumWorkloadEndpoints = 2
	qcPolicy_gnp2_t1_all_res_with_index.EgressRules[1].Source.NumHostEndpoints = 1
	qcPolicy_gnp2_t1_all_res_with_index.EgressRules[1].Source.NumWorkloadEndpoints = 1

	qcPolicy_sgnp2_t1_all_res_with_index := qcPolicyWithIdx(sgnp2_t1_o4, 3, 4, 4, 0, 0)
	qcPolicy_sgnp2_t1_all_res_with_index.IngressRules[0].Destination.NumHostEndpoints = 2
	qcPolicy_sgnp2_t1_all_res_with_index.IngressRules[0].Destination.NumWorkloadEndpoints = 0
	qcPolicy_sgnp2_t1_all_res_with_index.IngressRules[1].Destination.NumHostEndpoints = 2
	qcPolicy_sgnp2_t1_all_res_with_index.IngressRules[1].Destination.NumWorkloadEndpoints = 1
	qcPolicy_sgnp2_t1_all_res_with_index.IngressRules[1].Source.NumHostEndpoints = 4
	qcPolicy_sgnp2_t1_all_res_with_index.IngressRules[1].Source.NumWorkloadEndpoints = 4
	qcPolicy_sgnp2_t1_all_res_with_index.EgressRules[0].Source.NumHostEndpoints = 4
	qcPolicy_sgnp2_t1_all_res_with_index.EgressRules[0].Source.NumWorkloadEndpoints = 2
	qcPolicy_sgnp2_t1_all_res_with_index.EgressRules[1].Source.NumHostEndpoints = 1
	qcPolicy_sgnp2_t1_all_res_with_index.EgressRules[1].Source.NumWorkloadEndpoints = 1

	qcpolicy_gnp2_t1_o4_rack2_only_networkset := qcPolicy(gnp2_t1_o4_rack2_only, 1, 0, 1, 0)
	qcpolicy_gnp2_t1_o4_rack2_only_networkset.IngressRules[0].Source.NumHostEndpoints = 0
	qcpolicy_gnp2_t1_o4_rack2_only_networkset.IngressRules[0].Source.NumWorkloadEndpoints = 0
	qcpolicy_gnp2_t1_o4_rack2_only_networkset.EgressRules[1].Destination.NumHostEndpoints = 0
	qcpolicy_gnp2_t1_o4_rack2_only_networkset.EgressRules[1].Destination.NumWorkloadEndpoints = 0

	qcpolicy_sgnp2_t1_o4_rack2_only_networkset := qcPolicy(sgnp2_t1_o4_rack2_only, 1, 0, 1, 0)
	qcpolicy_sgnp2_t1_o4_rack2_only_networkset.IngressRules[0].Source.NumHostEndpoints = 0
	qcpolicy_sgnp2_t1_o4_rack2_only_networkset.IngressRules[0].Source.NumWorkloadEndpoints = 0
	qcpolicy_sgnp2_t1_o4_rack2_only_networkset.EgressRules[1].Destination.NumHostEndpoints = 0
	qcpolicy_sgnp2_t1_o4_rack2_only_networkset.EgressRules[1].Destination.NumWorkloadEndpoints = 0

	qcpolicy_np2_t1_o4_rack2_no_tier := qcPolicy(np2_t1_o4_rack2_no_tier, 0, 0, 0, 0)

	// Define a bunch of test query data for policies that test results returned in the policy appication index order.
	// We tweak this data after to assign the policy index so that we don't have to specify it in every test here.
	tqds := []testQueryData{
		{
			description: "no tier is set in the policy - it should return \"default\" as the tier",
			resources: []resourcemgr.ResourceObject{
				tier_default, np2_t1_o4_rack2_no_tier,
			},
			query: client.QueryPoliciesReq{},
			response: &client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{qcpolicy_np2_t1_o4_rack2_no_tier},
			},
		},
		{
			"multiple gnps and nps, no endpoints - query exact np, does not exist",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryPoliciesReq{
				Policy: model.ResourceKey{
					Kind:      apiv3.KindNetworkPolicy,
					Name:      "foobarbaz",
					Namespace: "not-a-namespace",
				},
			},
			errorResponse{
				text: "Error: resource does not exist: NetworkPolicy(not-a-namespace/foobarbaz) with error: <nil>",
				code: http.StatusNotFound,
			},
		},
		{
			"multiple gnps and nps, no endpoints - query exact gnp, does not exist",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryPoliciesReq{
				Policy: model.ResourceKey{
					Kind: apiv3.KindGlobalNetworkPolicy,
					Name: "foobarbaz",
				},
			},
			errorResponse{
				text: "Error: resource does not exist: GlobalNetworkPolicy(foobarbaz) with error: <nil>",
				code: http.StatusNotFound,
			},
		},
		{
			"multiple gnps and nps, no endpoints - query invalid np, get format error message",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			// The slash in the name will get rendered into the URL so we can test the URL parsing.
			client.QueryPoliciesReq{
				Policy: model.ResourceKey{
					Kind:      apiv3.KindNetworkPolicy,
					Name:      "foobarbaz",
					Namespace: "invalid/slash",
				},
			},
			errorResponse{
				text: "Error: invalid policy name format, expected kind/name or kind/namespace/name",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple gnps and nps, no endpoints - query exact np",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Policy: resourceKey(np1_t2_o1_ns1),
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0)},
			},
		},
		{
			"multiple gnps and nps/snps, no endpoints - query exact snp",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Policy: resourceKey(snp1_t2_o1_ns1),
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{qcPolicy(snp1_t2_o1_ns1, 0, 0, 0, 0)},
			},
		},
		{
			"multiple gnps and nps/snps, no endpoints - query invalid, delete staged are ignored, get format error message",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1_delete, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Policy: resourceKey(snp1_t2_o1_ns1_delete),
			},
			errorResponse{
				text: "Error: resource does not exist: StagedNetworkPolicy(namespace-1/aaa-tier2.snp1-t2-o1-ns1-delete) with error: <nil>",
				code: http.StatusNotFound,
			},
		},
		{
			"multiple gnps and nps, no endpoints - query exact gnp",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Policy: resourceKey(gnp1_t1_o3),
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{qcPolicy(gnp1_t1_o3, 0, 0, 0, 0)},
			},
		},
		{
			"multiple gnps and nps/snps, no endpoints - query exact gnp",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Policy: resourceKey(gnp1_t1_o3),
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{qcPolicy(gnp1_t1_o3, 0, 0, 0, 0)},
			},
		},
		{
			"multiple sgnps, gnps and nps, no endpoints - query exact sgnp",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Policy: resourceKey(sgnp1_t1_o3),
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{qcPolicy(sgnp1_t1_o3, 0, 0, 0, 0)},
			},
		},
		{
			"multiple gnps and nps, no endpoints - query all of them",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t1_o3, 0, 0, 0, 0), qcPolicy(gnp2_t1_o4, 0, 0, 0, 0),
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps sknps and nps, no endpoints - query all of them",
			[]resourcemgr.ResourceObject{
				tier1, sknp1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t1_o3, 0, 0, 0, 0), qcPolicy(gnp2_t1_o4, 0, 0, 0, 0),
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
					qcPolicy(sknp1_t1_o1_ns1, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps/snps, no endpoints - query all of them",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t1_o3, 0, 0, 0, 0), qcPolicy(gnp2_t1_o4, 0, 0, 0, 0),
					qcPolicy(snp1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(snp2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, no endpoints - query all of them",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(sgnp1_t1_o3, 0, 0, 0, 0), qcPolicy(sgnp2_t1_o4, 0, 0, 0, 0),
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps, no endpoints - query 5 - page 0 of 2",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    0,
					NumPerPage: 5,
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t1_o3, 0, 0, 0, 0), qcPolicy(gnp2_t1_o4, 0, 0, 0, 0),
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps/snps, no endpoints - query 5 - page 0 of 2",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    0,
					NumPerPage: 5,
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t1_o3, 0, 0, 0, 0), qcPolicy(gnp2_t1_o4, 0, 0, 0, 0),
					qcPolicy(snp1_t2_o1_ns1, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps sknps and nps, no endpoints - query 5 - page 0 of 2",
			[]resourcemgr.ResourceObject{
				tier1, sknp1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    0,
					NumPerPage: 5,
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t1_o3, 0, 0, 0, 0), qcPolicy(gnp2_t1_o4, 0, 0, 0, 0),
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, no endpoints - query 5 - page 0 of 2",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    0,
					NumPerPage: 5,
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(sgnp1_t1_o3, 0, 0, 0, 0), qcPolicy(sgnp2_t1_o4, 0, 0, 0, 0),
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps, no endpoints - query 5 - page 1 of 2",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    1,
					NumPerPage: 5,
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps/snps, no endpoints - query 5 - page 1 of 2",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    1,
					NumPerPage: 5,
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(snp2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps, no endpoints - query 5 - page 3 of 2",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    2,
					NumPerPage: 5,
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{},
			},
		},
		{
			"multiple gnps and nps, no endpoints - testing large page num",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    maxInt,
					NumPerPage: maxInt,
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{},
			},
		},
		{
			"multiple gnps and nps, no endpoints - testing negative page number",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    -1,
					NumPerPage: 2,
				},
			},
			errorResponse{
				text: "Error: page number should be an integer >=0, requested number: -1",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple gnps and snps/nps, no endpoints - testing negative page number",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    -1,
					NumPerPage: 2,
				},
			},
			errorResponse{
				text: "Error: page number should be an integer >=0, requested number: -1",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple gnps and nps, no endpoints - requesting zero results per page",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    0,
					NumPerPage: 0,
				},
			},
			errorResponse{
				text: "Error: number of results must be >0, requested number: 0",
				code: http.StatusBadRequest,
			},
		},

		{
			"multiple gnps and snps/nps, no endpoints - requesting zero results per page",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    0,
					NumPerPage: 0,
				},
			},
			errorResponse{
				text: "Error: number of results must be >0, requested number: 0",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple sgnps, gnps and nps, no endpoints - requesting zero results per page",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    0,
					NumPerPage: 0,
				},
			},
			errorResponse{
				text: "Error: number of results must be >0, requested number: 0",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple gnps and nps, no endpoints - requesting negative results per page",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{
				Page: &client.Page{
					PageNum:    10,
					NumPerPage: -10,
				},
			},
			errorResponse{
				text: "Error: number of results must be >0, requested number: -10",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple gnps and nps, no endpoints, reordered tiers - query all of them",
			[]resourcemgr.ResourceObject{
				tier1_o2, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2_o1, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t1_o3, 0, 0, 0, 0), qcPolicy(gnp2_t1_o4, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps/snps, no endpoints, reordered tiers - query all of them",
			[]resourcemgr.ResourceObject{
				tier1_o2, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2_o1, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(snp1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(snp2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t1_o3, 0, 0, 0, 0), qcPolicy(gnp2_t1_o4, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps/sknps, no endpoints, reordered tiers - query all of them",
			[]resourcemgr.ResourceObject{
				tier1_o2, sknp1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2_o1, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
					qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0), qcPolicy(gnp1_t1_o3, 0, 0, 0, 0),
					qcPolicy(gnp2_t1_o4, 0, 0, 0, 0), qcPolicy(sknp1_t1_o1_ns1, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, no endpoints, reordered tiers - query all of them",
			[]resourcemgr.ResourceObject{
				tier1_o2, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2_o1, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(sgnp1_t1_o3, 0, 0, 0, 0), qcPolicy(sgnp2_t1_o4, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps, no policies, reordered policies - query all of them",
			[]resourcemgr.ResourceObject{
				tier1_o2, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules, gnp2_t1_o3_fewer_rules,
				tier2_o1, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp2_t1_o3_fewer_rules, 0, 0, 0, 0), qcPolicy(gnp1_t1_o4_more_rules, 0, 0, 0, 0),
				},
			},
		},
		{
			"multiple gnps sknps and nps, no policies, reordered policies - query all of them",
			[]resourcemgr.ResourceObject{
				tier1_o2, sknp1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules, gnp2_t1_o3_fewer_rules,
				tier2_o1, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t2_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 0, 0, 0, 0),
					qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0), qcPolicy(gnp2_t1_o3_fewer_rules, 0, 0, 0, 0),
					qcPolicy(gnp1_t1_o4_more_rules, 0, 0, 0, 0), qcPolicy(sknp1_t1_o1_ns1, 0, 0, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier2 policies (rules selectors are all()) - query all of them",
			[]resourcemgr.ResourceObject{
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier2 policies (rules selectors are all()) - query all of them (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(snp1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(snp2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier2 policies - filter in wep2",
			[]resourcemgr.ResourceObject{
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_in,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 5, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier2 policies - filter in wep2 (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_in,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(snp1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(snp2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 5, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query all of them (gnp2 has rule selectors)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res,
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query all of them (gnp2 has rule selectors) (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res,
					qcPolicy(snp1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(snp2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query all of them (gnp2 has rule selectors) (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy(sgnp1_t1_o3, 1, 3, 0, 0), qcPolicy_sgnp2_t1_all_res,
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query tier 2",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Tier: []string{tier2.Name},
			},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query tier 1",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, globalnetset1,
			},
			client.QueryPoliciesReq{
				Tier: []string{tier1.Name},
			},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res,
				},
			},
		},
		{
			"bunch of endpoints and tier1 and tier2 policies - query tier1 and tier2",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, globalnetset1,
			},
			client.QueryPoliciesReq{
				Tier: []string{tier1.Name, tier2.Name},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0),
					qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0),
					qcPolicy_gnp2_t1_all_res,
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0),
					qcPolicy(np2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0),
					qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query empty tier",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, globalnetset1,
			},
			client.QueryPoliciesReq{
				Tier: []string{},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0),
					qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0),
					qcPolicy_gnp2_t1_all_res,
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0),
					qcPolicy(np2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0),
					qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query tier 1 (with namespaced networkset)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, namespacednetset1,
			},
			client.QueryPoliciesReq{
				Tier: []string{tier1.Name},
			},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res,
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query tier 2 (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Tier: []string{tier2.Name},
			},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(snp1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(snp2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query tier 1 (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, snp1_t2_o1_ns1, snp2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, globalnetset1,
			},
			client.QueryPoliciesReq{
				Tier: []string{tier1.Name},
			},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res,
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query tier 1 (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, globalnetset1,
			},
			client.QueryPoliciesReq{
				Tier: []string{tier1.Name},
			},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy(sgnp1_t1_o3, 1, 3, 0, 0), qcPolicy_sgnp2_t1_all_res,
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query policies matching labels",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Labels: map[string]string{
					"projectcalico.org/namespace": "namespace-1",
					"rack":                        "001",
					"server":                      "1",
				},
			},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0), qcPolicy(gnp1_t1_o3, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res,
					qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query policies matching endpoint",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, globalnetset1,
			},
			client.QueryPoliciesReq{
				Endpoint: resourceKey(wep4_n2_ns1),
			},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res,
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query policies matching endpoint (with namespaced networkset)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, namespacednetset1,
			},
			client.QueryPoliciesReq{
				Endpoint: resourceKey(wep4_n2_ns1),
			},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res,
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query policies matching endpoint and unmatched (invalid query)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Endpoint:  resourceKey(wep4_n2_ns1),
				Unmatched: true,
			},
			errorResponse{
				text: "Error: invalid query: specify only one of endpoint or unmatched",
				code: http.StatusBadRequest,
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query policies matching non-existent endpoint",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Endpoint: model.ResourceKey{
					Kind:      v3.KindWorkloadEndpoint,
					Namespace: "this-does-not-exist",
					Name:      "neither-does-this",
				},
			},
			errorResponse{
				text: "Error: resource does not exist: WorkloadEndpoint(this-does-not-exist/neither-does-this) with error: <nil>",
				code: http.StatusBadRequest,
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query policies matching invalid endpoint",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			// The slash in the name will get rendered into the query string and so we can test the parsing of the
			// resource name.
			client.QueryPoliciesReq{
				Endpoint: model.ResourceKey{
					Kind:      v3.KindWorkloadEndpoint,
					Name:      "this/is",
					Namespace: "not.valid",
				},
			},
			errorResponse{
				text: "Error: invalid query: the endpoint name is not valid; it should be of the format <HostEndpoint name> or " +
					"<namespace>/<WorkloadEndpoint name>",
				code: http.StatusBadRequest,
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query policies matching labels and endpoint",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, globalnetset1,
			},
			client.QueryPoliciesReq{
				Labels: map[string]string{
					"projectcalico.org/namespace": "namespace-1",
					"rack":                        "001",
					"server":                      "1",
				},
				Endpoint: resourceKey(wep4_n2_ns1),
			},
			&client.QueryPoliciesResp{
				Count: 3,
				Items: []client.Policy{
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res,
					qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query policies matching labels and endpoint (with namespaced networkset)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, namespacednetset1,
			},
			client.QueryPoliciesReq{
				Labels: map[string]string{
					"projectcalico.org/namespace": "namespace-1",
					"rack":                        "001",
					"server":                      "1",
				},
				Endpoint: resourceKey(wep4_n2_ns1),
			},
			&client.QueryPoliciesResp{
				Count: 3,
				Items: []client.Policy{
					qcPolicy(gnp1_t1_o3, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res,
					qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query policies matching labels, endpoint and tier",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, globalnetset1,
			},
			client.QueryPoliciesReq{
				Labels: map[string]string{
					"projectcalico.org/namespace": "namespace-1",
					"rack":                        "001",
					"server":                      "1",
				},
				Endpoint: resourceKey(wep4_n2_ns1),
				Tier:     []string{tier2.Name},
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{
					qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"bunch of endpoints and tier 1 and tier2 policies - query policies matching labels, endpoint and tier (with namespaced networkset)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out, namespacednetset1,
			},
			client.QueryPoliciesReq{
				Labels: map[string]string{
					"projectcalico.org/namespace": "namespace-1",
					"rack":                        "001",
					"server":                      "1",
				},
				Endpoint: resourceKey(wep4_n2_ns1),
				Tier:     []string{tier2.Name},
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{
					qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"gnp1 and gnp2 #rules and order updated - query all of them",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules, gnp2_t1_o3_fewer_rules,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy_gnp2_t1_all_res_fewer, qcPolicy_gnp1_t1_all_res_more,
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"gnp1 and gnp2 #rules and order updated, updated WEP1 profile - query all of them",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules, gnp2_t1_o3_fewer_rules,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_099,
				wep1_n1_ns1_updated_profile, wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 0, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 2, 0, 0),
					qcPolicy_gnp2_t1_all_res_fewer_updated_wep1, qcPolicy_gnp1_t1_all_res_more_updated_wep1,
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 2, 0, 0),
					qcPolicy(gnp1_t2_o3, 1, 1, 0, 0), qcPolicy(gnp2_t2_o4, 4, 4, 0, 0),
				},
			},
		},
		{
			"tier1 and tier2 policies, but no namespace-2 endpoints and no rackless endpoints; some policies unmatched",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, wep4_n2_ns1, profile_rack_001, wep1_n1_ns1,
				wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t1_o3, 1, 2, 0, 0), qcPolicy_gnp2_t1_no_ns2_no_rackless,
					qcPolicy(np1_t2_o1_ns1, 0, 1, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0), qcPolicy(gnp2_t2_o4, 3, 2, 0, 0),
				},
			},
		},
		{
			"tier1 and tier2 policies, but no namespace-2 endpoints and no rackless endpoints; some policies unmatched; filter on unmatched",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, wep4_n2_ns1, profile_rack_001, wep1_n1_ns1,
				wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Unmatched: true,
			},
			&client.QueryPoliciesResp{
				Count: 3,
				Items: []client.Policy{
					qcPolicy(np2_t1_o2_ns2, 0, 0, 0, 0), qcPolicy(np2_t2_o2_ns2, 0, 0, 0, 0),
					qcPolicy(gnp1_t2_o3, 0, 0, 0, 0),
				},
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset (matches multiple rules in same policy)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, gnp2_t1_o4_rack2_only, gnp3_t2_o5_rack2_only, globalnetset1,
				np1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1, np1_t2_o1_ns1_rack2_only,
			},
			client.QueryPoliciesReq{
				NetworkSet: model.ResourceKey{
					Kind: apiv3.KindGlobalNetworkSet,
					Name: "globalnetset1",
				},
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{
					qcPolicy(gnp2_t1_o4_rack2_only, 0, 0, 0, 0),
				},
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset (matches multiple rules in same policy) (with namespaced networkset)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, gnp2_t1_o4_rack2_only, gnp3_t2_o5_rack2_only, namespacednetset1,
				np1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1, np1_t2_o1_ns1_rack2_only,
			},
			client.QueryPoliciesReq{
				NetworkSet: model.ResourceKey{
					Kind:      apiv3.KindNetworkSet,
					Name:      "namespacednetset1",
					Namespace: "namespace-1",
				},
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{
					qcPolicy(gnp2_t1_o4_rack2_only, 0, 0, 0, 0),
				},
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset (matches multiple rules in same policy) (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, sgnp2_t1_o4_rack2_only, sgnp3_t2_o5_rack2_only, globalnetset1,
				snp1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1, snp1_t2_o1_ns1_rack2_only,
			},
			client.QueryPoliciesReq{
				NetworkSet: model.ResourceKey{
					Kind: apiv3.KindGlobalNetworkSet,
					Name: "globalnetset1",
				},
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{
					qcPolicy(sgnp2_t1_o4_rack2_only, 0, 0, 0, 0),
				},
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset (matches multiple policies)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, gnp2_t1_o4_rack2_only, gnp3_t2_o5_rack2_only, globalnetset2,
				np1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1_not_rack1_src, np1_t2_o1_ns1_rack2_only,
			},
			client.QueryPoliciesReq{
				NetworkSet: model.ResourceKey{
					Kind: apiv3.KindGlobalNetworkSet,
					Name: "globalnetset2",
				},
			},
			&client.QueryPoliciesResp{
				Count: 2,
				Items: []client.Policy{
					qcPolicy(gnp2_t1_o4_rack2_only, 0, 0, 0, 0),
					qcPolicy(gnp3_t2_o5_rack2_only, 0, 0, 0, 0),
				},
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset (matches multiple policies) (with namespaced networkset)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, gnp2_t1_o4_rack2_only, gnp3_t2_o5_rack2_only, namespacednetset2,
				np1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1_not_rack1_src, np1_t2_o1_ns1_rack2_only,
			},
			client.QueryPoliciesReq{
				NetworkSet: model.ResourceKey{
					Kind:      apiv3.KindNetworkSet,
					Name:      "namespacednetset2",
					Namespace: "namespace-1",
				},
			},
			&client.QueryPoliciesResp{
				Count: 4,
				Items: []client.Policy{
					qcPolicy(np1_t1_o1_ns1_not_rack1_src, 0, 0, 0, 0),
					qcPolicy(gnp2_t1_o4_rack2_only, 0, 0, 0, 0),
					qcPolicy(np1_t2_o1_ns1_rack2_only, 0, 0, 0, 0),
					qcPolicy(gnp3_t2_o5_rack2_only, 0, 0, 0, 0),
				},
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset (matches multiple policies) (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, sgnp2_t1_o4_rack2_only, sgnp3_t2_o5_rack2_only, globalnetset2,
				snp1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1_not_rack1_src, snp1_t2_o1_ns1_rack2_only,
			},
			client.QueryPoliciesReq{
				NetworkSet: model.ResourceKey{
					Kind: apiv3.KindGlobalNetworkSet,
					Name: "globalnetset2",
				},
			},
			&client.QueryPoliciesResp{
				Count: 2,
				Items: []client.Policy{
					qcPolicy(sgnp2_t1_o4_rack2_only, 0, 0, 0, 0),
					qcPolicy(sgnp3_t2_o5_rack2_only, 0, 0, 0, 0),
				},
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset (network set deleted, no match)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, gnp2_t1_o4_rack2_only,
				np1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1_not_rack1_src, np1_t2_o1_ns1_rack2_only,
			},
			client.QueryPoliciesReq{
				NetworkSet: model.ResourceKey{
					Kind: apiv3.KindGlobalNetworkSet,
					Name: "globalnetset2",
				},
			},
			errorResponse{
				text: "Error: resource does not exist: GlobalNetworkSet(globalnetset2) with error: <nil>",
				code: http.StatusBadRequest,
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset (network set deleted, no match) (with namespaced networkset)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, gnp2_t1_o4_rack2_only,
				np1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1_not_rack1_src, np1_t2_o1_ns1_rack2_only,
			},
			client.QueryPoliciesReq{
				NetworkSet: model.ResourceKey{
					Kind:      apiv3.KindNetworkSet,
					Name:      "namespacednetset2",
					Namespace: "namespace-1",
				},
			},
			errorResponse{
				text: "Error: resource does not exist: NetworkSet(namespace-1/namespacednetset2) with error: <nil>",
				code: http.StatusBadRequest,
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset (network set deleted, no match) (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, sgnp2_t1_o4_rack2_only,
				snp1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1_not_rack1_src, snp1_t2_o1_ns1_rack2_only,
			},
			client.QueryPoliciesReq{
				NetworkSet: model.ResourceKey{
					Kind: apiv3.KindGlobalNetworkSet,
					Name: "globalnetset2",
				},
			},
			errorResponse{
				text: "Error: resource does not exist: GlobalNetworkSet(globalnetset2) with error: <nil>",
				code: http.StatusBadRequest,
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset and endpoints, make sure only policies that match both are returned",
			[]resourcemgr.ResourceObject{
				tier1, tier2, gnp2_t1_o4_rack2_only, gnp3_t2_o5_rack2_only, globalnetset1, hep2_n3,
				np1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1, np1_t2_o1_ns1_rack2_only,
				np1_t1_o1_ns1_not_rack1_2,
			},
			client.QueryPoliciesReq{
				Endpoint: resourceKey(hep2_n3),
				NetworkSet: model.ResourceKey{
					Kind: apiv3.KindGlobalNetworkSet,
					Name: "globalnetset1",
				},
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{
					qcpolicy_gnp2_t1_o4_rack2_only_networkset,
				},
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset and endpoints, make sure only policies that match both are returned (with namespaced networkset)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, gnp2_t1_o4_rack2_only, gnp3_t2_o5_rack2_only, namespacednetset1, hep2_n3,
				np1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1, np1_t2_o1_ns1_rack2_only,
				np1_t1_o1_ns1_not_rack1_2,
			},
			client.QueryPoliciesReq{
				Endpoint: resourceKey(hep2_n3),
				NetworkSet: model.ResourceKey{
					Kind:      apiv3.KindNetworkSet,
					Name:      "namespacednetset1",
					Namespace: "namespace-1",
				},
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{
					qcpolicy_gnp2_t1_o4_rack2_only_networkset,
				},
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset and endpoints, make sure only policies that match both are returned (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, sgnp2_t1_o4_rack2_only, sgnp3_t2_o5_rack2_only, globalnetset1, hep2_n3,
				snp1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1, snp1_t2_o1_ns1_rack2_only,
				np1_t1_o1_ns1_not_rack1_2,
			},
			client.QueryPoliciesReq{
				Endpoint: resourceKey(hep2_n3),
				NetworkSet: model.ResourceKey{
					Kind: apiv3.KindGlobalNetworkSet,
					Name: "globalnetset1",
				},
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{
					qcpolicy_sgnp2_t1_o4_rack2_only_networkset,
				},
			},
		},
		{
			"tier1 and tier2 policies, query on a networkset and endpoints, make sure only policies that match both are returned (with staged policies)",
			[]resourcemgr.ResourceObject{
				tier1, tier2, sgnp2_t1_o4_rack2_only, sgnp3_t2_o5_rack2_only, globalnetset1, hep2_n3,
				sknp1_t2_o1_ns1_rack2_only, np1_t1_o1_ns1, snp1_t2_o1_ns1_rack2_only,
				np1_t1_o1_ns1_not_rack1_2,
			},
			client.QueryPoliciesReq{
				Endpoint: resourceKey(hep2_n3),
				NetworkSet: model.ResourceKey{
					Kind: apiv3.KindGlobalNetworkSet,
					Name: "globalnetset1",
				},
			},
			&client.QueryPoliciesResp{
				Count: 1,
				Items: []client.Policy{
					qcpolicy_sgnp2_t1_o4_rack2_only_networkset,
				},
			},
		},
		{
			"reset by removing all endpoints and policy; perform empty query",
			[]resourcemgr.ResourceObject{},
			client.QueryPoliciesReq{},
			&client.QueryPoliciesResp{
				Count: 0,
				Items: []client.Policy{},
			},
		},
	}
	// All of the above queries are returning the policies in order application index which means the index is the same
	// as the index into the items slice.  Fix them up here so that we don't need to above.
	for _, tqd := range tqds {
		startIdx := 0
		qpreq := tqd.query.(client.QueryPoliciesReq)
		if qpreq.Page != nil {
			if qpreq.Page.PageNum < 0 {
				startIdx = 0
			} else {
				startIdx = qpreq.Page.PageNum * qpreq.Page.NumPerPage
			}
		}
		qpr, ok := tqd.response.(*client.QueryPoliciesResp)
		if !ok {
			continue
		}
		for i := 0; i < len(qpr.Items); i++ {
			qpr.Items[i].Index = startIdx + i
		}
	}

	// The following tests are to test the different sort parameters.
	tqdsSortFields := []testQueryData{
		{
			"multiple gnps and nps, endpoints - reverse sort",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					Reverse: true,
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0), qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0),
					qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0), qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0),
					qcPolicy_gnp2_t1_all_res_with_index, qcPolicyWithIdx(gnp1_t1_o3, 2, 1, 3, 0, 0),
					qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0), qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, endpoints - reverse sort",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					Reverse: true,
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0), qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0),
					qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0), qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0),
					qcPolicy_gnp2_t1_all_res_with_index, qcPolicyWithIdx(sgnp1_t1_o3, 2, 1, 3, 0, 0),
					qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0), qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps, endpoints - sort by index",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"index"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res_with_index,
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, endpoints - sort by index",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"index"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(sgnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_sgnp2_t1_all_res_with_index,
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps, endpoints - sort by kind",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"kind"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(gnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res_with_index,
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, endpoints - sort by kind",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"kind"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(sgnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_sgnp2_t1_all_res_with_index,
				},
			},
		},
		{
			"multiple gnps and nps, endpoints - sort by name",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"name"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res_with_index,
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, endpoints - sort by name",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"name"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(sgnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_sgnp2_t1_all_res_with_index,
				},
			},
		},
		{
			"multiple gnps and nps, endpoints - sort by namespace",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"namespace"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(gnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res_with_index,
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0),
					qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, endpoints - sort by namespace",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"namespace"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(sgnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_sgnp2_t1_all_res_with_index,
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0),
					qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps, endpoints - sort by tier",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"tier"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res_with_index,
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, endpoints - sort by tier",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"tier"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(sgnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_sgnp2_t1_all_res_with_index,
				},
			},
		},
		{
			"multiple gnps and nps, endpoints - sort by numHostEndpoints",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"numHostEndpoints"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0),
					qcPolicy_gnp2_t1_all_res_with_index, qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, endpoints - sort by numHostEndpoints",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"numHostEndpoints"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(sgnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0),
					qcPolicy_sgnp2_t1_all_res_with_index, qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps, endpoints - sort by numWorkloadEndpoints",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"numWorkloadEndpoints"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0),
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0), qcPolicyWithIdx(gnp1_t1_o3, 2, 1, 3, 0, 0),
					qcPolicy_gnp2_t1_all_res_with_index, qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, endpoints - sort by numWorkloadEndpoints",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"numWorkloadEndpoints"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0),
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0), qcPolicyWithIdx(sgnp1_t1_o3, 2, 1, 3, 0, 0),
					qcPolicy_sgnp2_t1_all_res_with_index, qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps, endpoints - sort by endpoints (host + workload)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"numEndpoints"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0),
					qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp1_t1_o3, 2, 1, 3, 0, 0),
					qcPolicy_gnp2_t1_all_res_with_index, qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, endpoints - sort by endpoints (host + workload)",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"numEndpoints"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0),
					qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(sgnp1_t1_o3, 2, 1, 3, 0, 0),
					qcPolicy_sgnp2_t1_all_res_with_index, qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
				},
			},
		},
		{
			"multiple gnps and nps, endpoints - sort by tier and some bogus columns",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"bazbarfoo", "tier", "foobarbaz"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_gnp2_t1_all_res_with_index,
				},
			},
		},
		{
			"multiple sgnps, gnps and nps, endpoints - sort by tier and some bogus columns",
			[]resourcemgr.ResourceObject{
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
				tier2, np1_t2_o1_ns1, np2_t2_o2_ns2, gnp1_t2_o3, gnp2_t2_o4,
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, wep2_n1_ns1_filtered_out,
			},
			client.QueryPoliciesReq{
				Sort: &client.Sort{
					SortBy: []string{"bazbarfoo", "tier", "foobarbaz"},
				},
			},
			&client.QueryPoliciesResp{
				Count: 8,
				Items: []client.Policy{
					qcPolicyWithIdx(np1_t2_o1_ns1, 4, 0, 1, 0, 0), qcPolicyWithIdx(np2_t2_o2_ns2, 5, 0, 2, 0, 0),
					qcPolicyWithIdx(gnp1_t2_o3, 6, 1, 1, 0, 0), qcPolicyWithIdx(gnp2_t2_o4, 7, 4, 4, 0, 0),
					qcPolicyWithIdx(np1_t1_o1_ns1, 0, 0, 1, 0, 0), qcPolicyWithIdx(np2_t1_o2_ns2, 1, 0, 2, 0, 0),
					qcPolicyWithIdx(sgnp1_t1_o3, 2, 1, 3, 0, 0), qcPolicy_sgnp2_t1_all_res_with_index,
				},
			},
		},
	}

	tqds = append(tqds, tqdsSortFields...)
	return tqds
}
