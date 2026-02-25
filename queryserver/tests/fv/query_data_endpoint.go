// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.
package fv

import (
	"fmt"
	"net/http"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/client"
)

func endpointTestQueryData() []testQueryData {
	return []testQueryData{
		{
			"multiple weps and heps, no policy - query exact wep, doesn't exist",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryEndpointsReq{
				Endpoint: model.ResourceKey{
					Kind:      internalapi.KindWorkloadEndpoint,
					Name:      "foobarbaz",
					Namespace: "not-a-namespace",
				},
			},
			errorResponse{
				text: "Error: resource does not exist: WorkloadEndpoint(not-a-namespace/foobarbaz) with error: <nil>",
				code: http.StatusNotFound,
			},
		},
		{
			"multiple weps and heps, no policy - query exact hep, doesn't exist",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryEndpointsReq{
				Endpoint: model.ResourceKey{
					Kind: apiv3.KindHostEndpoint,
					Name: "foobarbaz",
				},
			},
			errorResponse{
				text: "Error: resource does not exist: HostEndpoint(foobarbaz) with error: <nil>",
				code: http.StatusNotFound,
			},
		},
		{
			"multiple weps and heps, no policy - query exact wep",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryEndpointsReq{
				Endpoint: resourceKey(wep3_n1_ns2),
			},
			&client.QueryEndpointsResp{
				Count: 1,
				Items: []client.Endpoint{qcEndpoint(wep3_n1_ns2, 0, 0)},
			},
		},
		{
			"multiple weps and heps, no policy - query exact hep",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
				wep2_n1_ns1_filtered_out,
			},
			client.QueryEndpointsReq{
				Endpoint: resourceKey(hep2_n3),
			},
			&client.QueryEndpointsResp{
				Count: 1,
				Items: []client.Endpoint{qcEndpoint(hep2_n3, 0, 0)},
			},
		},
		{
			"multiple weps and heps, no policy - query all of them",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryEndpointsReq{},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 0, 0), qcEndpoint(hep3_n4, 0, 0), qcEndpoint(wep1_n1_ns1, 0, 0),
					qcEndpoint(wep3_n1_ns2, 0, 0), qcEndpoint(wep4_n2_ns1, 0, 0), qcEndpoint(hep1_n2, 0, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 0, 0), qcEndpoint(hep2_n3, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, no policy - query endpoints from a given list of endpoints",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryEndpointsReq{
				EndpointsList: []string{
					fmt.Sprintf(".*%s/%s", wep1_n1_ns1.Namespace, wep1_n1_ns1.Name),
					fmt.Sprintf(".*%s/%s", wep3_n1_ns2.Namespace, wep3_n1_ns2.Name),
					fmt.Sprintf(".*%s/%s", wep4_n2_ns1.Namespace, wep4_n2_ns1.Name),
				},
			},
			&client.QueryEndpointsResp{
				Count: 3,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 0, 0),
					qcEndpoint(wep3_n1_ns2, 0, 0),
					qcEndpoint(wep4_n2_ns1, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, no policy - query unprotected endpoints",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryEndpointsReq{
				Unprotected: true,
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 0, 0), qcEndpoint(hep3_n4, 0, 0), qcEndpoint(wep1_n1_ns1, 0, 0),
					qcEndpoint(wep3_n1_ns2, 0, 0), qcEndpoint(wep4_n2_ns1, 0, 0), qcEndpoint(hep1_n2, 0, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 0, 0), qcEndpoint(hep2_n3, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, no policy - query all of them - page 0 of 2",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
				wep2_n1_ns1_filtered_out,
			},
			client.QueryEndpointsReq{
				Page: &client.Page{
					PageNum:    0,
					NumPerPage: 5,
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 0, 0), qcEndpoint(hep3_n4, 0, 0), qcEndpoint(wep1_n1_ns1, 0, 0),
					qcEndpoint(wep3_n1_ns2, 0, 0), qcEndpoint(wep4_n2_ns1, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, no policy - query all of them - page 1 of 2",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
				wep2_n1_ns1_filtered_out,
			},
			client.QueryEndpointsReq{
				Page: &client.Page{
					PageNum:    1,
					NumPerPage: 5,
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep1_n2, 0, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 0, 0), qcEndpoint(hep2_n3, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, no policy - query all of them - page 2 of 2",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
				wep2_n1_ns1_filtered_out,
			},
			client.QueryEndpointsReq{
				Page: &client.Page{
					PageNum:    2,
					NumPerPage: 5,
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{},
			},
		},
		{
			"multiple weps and heps, no policy - query all of them, filter on node2",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryEndpointsReq{
				Node: node2.Name,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(wep4_n2_ns1, 0, 0), qcEndpoint(hep1_n2, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, no policy - query unprotected nodes, filter on node2",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryEndpointsReq{
				Unprotected: true,
				Node:        node2.Name,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(wep4_n2_ns1, 0, 0), qcEndpoint(hep1_n2, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, selector: all()",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, wep1_n1_ns1, wep5_n3_ns2_unlabelled,
			},
			client.QueryEndpointsReq{
				Selector: "all()",
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 0, 0), qcEndpoint(hep3_n4, 0, 0), qcEndpoint(wep1_n1_ns1, 0, 0),
					qcEndpoint(wep3_n1_ns2, 0, 0), qcEndpoint(wep4_n2_ns1, 0, 0), qcEndpoint(hep1_n2, 0, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 0, 0), qcEndpoint(hep2_n3, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, selector: (rack == '001' || rack == '002') && server == '1'",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled,
			},
			client.QueryEndpointsReq{
				Selector: "(rack == '001' || rack == '002') && server == '1'",
			},
			&client.QueryEndpointsResp{
				Count: 3,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 0, 0), qcEndpoint(wep3_n1_ns2, 0, 0), qcEndpoint(hep2_n3, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query unprotected endpoints",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Unprotected: true,
			},
			&client.QueryEndpointsResp{
				Count: 0,
				Items: []client.Endpoint{},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query unprotected endpoints (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Unprotected: true,
			},
			&client.QueryEndpointsResp{
				Count: 0,
				Items: []client.Endpoint{},
			},
		},
		{
			"multiple weps and heps, some tier1 policies (no all() policies) - query unprotected endpoints (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, gnp1_t1_o3,
			},
			client.QueryEndpointsReq{
				Unprotected: true,
			},
			&client.QueryEndpointsResp{
				Count: 4,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 0, 0), qcEndpoint(hep3_n4, 0, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 0, 0), qcEndpoint(hep2_n3, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, some tier1 policies (no all() policies) - query unprotected endpoints (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, sknp1_t1_o1_ns1, gnp1_t1_o3,
			},
			client.QueryEndpointsReq{
				Unprotected: true,
			},
			&client.QueryEndpointsResp{
				Count: 4,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 0, 0), qcEndpoint(hep3_n4, 0, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 0, 0), qcEndpoint(hep2_n3, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, some tier1 policies (no all() policies) - query unprotected endpoints (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, sgnp1_t1_o3,
			},
			client.QueryEndpointsReq{
				Unprotected: true,
			},
			&client.QueryEndpointsResp{
				Count: 4,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 0, 0), qcEndpoint(hep3_n4, 0, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 0, 0), qcEndpoint(hep2_n3, 0, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query unlabelled endpoints",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Unlabelled: true,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query unlabelled endpoints (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, sknp1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Unlabelled: true,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - selector: rack == '001' && server == '2'",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Selector: "rack == '001' && server == '2'",
			},
			// We've removed gnp1 so counts are lower for GNP than previous run.
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(wep4_n2_ns1, 1, 0), qcEndpoint(hep1_n2, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query unprotected and matching policy (invalid query)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Unprotected: true,
				Policy:      resourceKey(gnp1_t1_o3),
			},
			errorResponse{
				text: "Error: invalid query: specify only one of selector or policy, or specify one of policy or " +
					"unprotected",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple weps and heps, tier1 policy - query invalid policy name",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			// The namespace has a slash which will get rendered into the URL (and will error).
			client.QueryEndpointsReq{
				Policy: model.ResourceKey{
					Kind:      apiv3.KindNetworkPolicy,
					Namespace: "this/has",
					Name:      "a.slash",
				},
			},
			errorResponse{
				text: "Error: invalid policy name format, expected kind/name or kind/namespace/name",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple weps and heps, tier1 policy - query with valid policy name but it can't be found in the cluster",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy: model.ResourceKey{
					Kind:      apiv3.KindNetworkPolicy,
					Namespace: "some-ns-can-not-be-found",
					Name:      "some-name-can-not-be-found",
				},
			},
			&client.QueryEndpointsResp{
				Count: 0,
				Items: []client.Endpoint{},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching policy selector gnp1_t1_o3",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				wep2_n1_ns1_filtered_out,
			},
			client.QueryEndpointsReq{
				Policy: resourceKey(gnp1_t1_o3),
			},
			&client.QueryEndpointsResp{
				Count: 4,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0),
					qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching policy selector gnp1_t1_o3, filter in wep2",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				wep2_n1_ns1_filtered_in,
			},
			client.QueryEndpointsReq{
				Policy: resourceKey(gnp1_t1_o3),
			},
			&client.QueryEndpointsResp{
				Count: 5,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep2_n1_ns1_filtered_in, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching policy selector gnp1_t1_o3, filter in wep2  (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, sknp1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
				wep2_n1_ns1_filtered_in,
			},
			client.QueryEndpointsReq{
				Policy: resourceKey(gnp1_t1_o3),
			},
			&client.QueryEndpointsResp{
				Count: 5,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep2_n1_ns1_filtered_in, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching policy selector gnp1_t1_o3",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy: resourceKey(gnp1_t1_o3),
			},
			&client.QueryEndpointsResp{
				Count: 4,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0),
					qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching gnp2-t1-o4;egress;idx=0;source;notSelector",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o4),
				RuleDirection:       "egress",
				RuleIndex:           0,
				RuleEntity:          "source",
				RuleNegatedSelector: true,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching gnp2-t1-o4;egress;idx=0;source;notSelector - testing negative rule index",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o4),
				RuleDirection:       "egress",
				RuleIndex:           -1,
				RuleEntity:          "source",
				RuleNegatedSelector: true,
			},
			errorResponse{
				text: "Error: rule index out of range, expected: 0-1; requested index: -1",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching gnp2-t1-o4;egress;idx=0;source;notSelector - high rule index",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o4),
				RuleDirection:       "egress",
				RuleIndex:           1000000,
				RuleEntity:          "source",
				RuleNegatedSelector: true,
			},
			errorResponse{
				text: "Error: rule index out of range, expected: 0-1; requested index: 1000000",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching sgnp2-t1-o4;egress;idx=0;source;notSelector - high rule index (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(sgnp2_t1_o4),
				RuleDirection:       "egress",
				RuleIndex:           1000000,
				RuleEntity:          "source",
				RuleNegatedSelector: true,
			},
			errorResponse{
				text: "Error: rule index out of range, expected: 0-1; requested index: 1000000",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching gnp2-t1-o4;egress;idx=0;source;notSelector - testing bad rule direction",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o4),
				RuleDirection:       "foobarbaz",
				RuleIndex:           0,
				RuleEntity:          "source",
				RuleNegatedSelector: true,
			},
			errorResponse{
				text: "Error: rule direction not valid: foobarbaz",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching sgnp2-t1-o4;egress;idx=0;source;notSelector - testing bad rule direction (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(sgnp2_t1_o4),
				RuleDirection:       "foobarbaz",
				RuleIndex:           0,
				RuleEntity:          "source",
				RuleNegatedSelector: true,
			},
			errorResponse{
				text: "Error: rule direction not valid: foobarbaz",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching gnp2-t1-o4;egress;idx=0;source;notSelector - testing bad rule entity",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o4),
				RuleDirection:       "egress",
				RuleIndex:           0,
				RuleEntity:          "foobarbaz",
				RuleNegatedSelector: true,
			},
			errorResponse{
				text: "Error: rule entity not valid: foobarbaz",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching sgnp2-t1-o4;egress;idx=0;source;notSelector - testing bad rule entity (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(sgnp2_t1_o4),
				RuleDirection:       "egress",
				RuleIndex:           0,
				RuleEntity:          "foobarbaz",
				RuleNegatedSelector: true,
			},
			errorResponse{
				text: "Error: rule entity not valid: foobarbaz",
				code: http.StatusBadRequest,
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching gnp2-t1-o4;egress;idx=1;source;selector",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o4),
				RuleDirection:       "egress",
				RuleIndex:           1,
				RuleEntity:          "source",
				RuleNegatedSelector: false,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching sgnp2-t1-o4;egress;idx=1;source;selector (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(sgnp2_t1_o4),
				RuleDirection:       "egress",
				RuleIndex:           1,
				RuleEntity:          "source",
				RuleNegatedSelector: false,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching gnp2-t1-o4;ingress;idx=0;destination;selector",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o4),
				RuleDirection:       "ingress",
				RuleIndex:           0,
				RuleEntity:          "destination",
				RuleNegatedSelector: false,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching sgnp2-t1-o4;ingress;idx=0;destination;selector (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(sgnp2_t1_o4),
				RuleDirection:       "ingress",
				RuleIndex:           0,
				RuleEntity:          "destination",
				RuleNegatedSelector: false,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching gnp2-t1-o4;ingress;idx=1;destination;notSelector",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o4),
				RuleDirection:       "ingress",
				RuleIndex:           1,
				RuleEntity:          "destination",
				RuleNegatedSelector: true,
			},
			&client.QueryEndpointsResp{
				Count: 5,
				Items: []client.Endpoint{
					qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - endpoints matching sgnp2-t1-o4;ingress;idx=1;destination;notSelector (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(sgnp2_t1_o4),
				RuleDirection:       "ingress",
				RuleIndex:           1,
				RuleEntity:          "destination",
				RuleNegatedSelector: true,
			},
			&client.QueryEndpointsResp{
				Count: 5,
				Items: []client.Endpoint{
					qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"updated GNPs orders and rules - check no change to main policy selectors and counts",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules,
				gnp2_t1_o3_fewer_rules,
			},
			client.QueryEndpointsReq{
				Policy: resourceKey(gnp1_t1_o3),
			},
			&client.QueryEndpointsResp{
				Count: 4,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0),
					qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"updated GNPs orders and rules - endpoints matching gnp2-t1-o4;egress;idx=0;source;selector (should match previous idx=1)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules,
				gnp2_t1_o3_fewer_rules,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o3_fewer_rules),
				RuleDirection:       "egress",
				RuleIndex:           0,
				RuleEntity:          "source",
				RuleNegatedSelector: false,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"updated GNPs orders and rules - endpoints matching gnp2-t1-o4;ingress;idx=0;destination;notSelector (should match previous idx=1)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules,
				gnp2_t1_o3_fewer_rules,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o3_fewer_rules),
				RuleDirection:       "ingress",
				RuleIndex:           0,
				RuleEntity:          "destination",
				RuleNegatedSelector: true,
			},
			&client.QueryEndpointsResp{
				Count: 5,
				Items: []client.Endpoint{
					qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"updated GNPs orders and rules - endpoints matching gnp2-t1-o4;ingress;idx=1;destination;notSelector (should not exist anymore)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules,
				gnp2_t1_o3_fewer_rules,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp2_t1_o3_fewer_rules),
				RuleDirection:       "ingress",
				RuleIndex:           1,
				RuleEntity:          "destination",
				RuleNegatedSelector: true,
			},
			errorResponse{
				text: "Error: rule index out of range, expected: 0-0; requested index: 1",
				code: http.StatusBadRequest,
			},
		},
		{
			"updated GNPs orders and rules - endpoints matching gnp1_t1_o4;ingress;idx=0;destination;selector (should match rules from previous gnp2)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules,
				gnp2_t1_o3_fewer_rules,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp1_t1_o4_more_rules),
				RuleDirection:       "ingress",
				RuleIndex:           0,
				RuleEntity:          "destination",
				RuleNegatedSelector: false,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"updated GNPs orders and rules - endpoints matching gnp1_t1_o4;egress;idx=0;source;notSelector (should match rules from previous gnp2)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules,
				gnp2_t1_o3_fewer_rules,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp1_t1_o4_more_rules),
				RuleDirection:       "egress",
				RuleIndex:           0,
				RuleEntity:          "source",
				RuleNegatedSelector: true,
			},
			&client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1),
				},
			},
		},
		{
			"updated GNPs orders and rules - endpoints matching gnp1_t1_o4;ingress;idx=1;destination;selector (should match all)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules,
				gnp2_t1_o3_fewer_rules,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp1_t1_o4_more_rules),
				RuleDirection:       "ingress",
				RuleIndex:           1,
				RuleEntity:          "destination",
				RuleNegatedSelector: false,
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"updated GNPs orders and rules - endpoints matching gnp1_t1_o4;egress;idx=1;source;notSelector (should match all)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o4_more_rules,
				gnp2_t1_o3_fewer_rules,
			},
			client.QueryEndpointsReq{
				Policy:              resourceKey(gnp1_t1_o4_more_rules),
				RuleDirection:       "egress",
				RuleIndex:           1,
				RuleEntity:          "source",
				RuleNegatedSelector: true,
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; reverse sort",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					Reverse: true,
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep2_n3, 1, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep4_n4_unlabelled, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; reverse sort (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					Reverse: true,
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep2_n3, 1, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep4_n4_unlabelled, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by name and namespace",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"name", "namespace"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by name and namespace (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"name", "namespace"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by kind",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"kind"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(hep2_n3, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1),
					qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by kind (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"kind"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(hep2_n3, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1),
					qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by namespace",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"namespace"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(hep2_n3, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by namespace (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"namespace"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(hep2_n3, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by node",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"node"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by node (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"node"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by orchestrator (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"orchestrator"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep1_n2, 2, 0),
					qcEndpoint(hep2_n3, 1, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by pod (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp2_t1_o4, sgnp1_t1_o3,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"pod"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep4_n2_ns1, 2, 0),
					qcEndpoint(hep1_n2, 2, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep2_n3, 1, 0),
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by workload",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, gnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"workload"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(hep1_n2, 2, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
					qcEndpoint(hep2_n3, 1, 0), qcEndpoint(wep4_n2_ns1, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by workload (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, sgnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"workload"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(hep1_n2, 2, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
					qcEndpoint(hep2_n3, 1, 0), qcEndpoint(wep4_n2_ns1, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by interfaceName (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"interfaceName"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(wep4_n2_ns1, 2, 0),
					qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep4_n4_unlabelled, 1, 0),
					qcEndpoint(hep1_n2, 2, 0), qcEndpoint(hep2_n3, 1, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by ipNetworks",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp2_t1_o4, sgnp1_t1_o3,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"ipNetworks"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep2_n3, 1, 0),
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by numGlobalNetworkPolicies (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"numGlobalNetworkPolicies"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1), qcEndpoint(hep2_n3, 1, 0),
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep4_n2_ns1, 2, 0),
					qcEndpoint(hep1_n2, 2, 0),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by numNetworkPolicies (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp2_t1_o4, sgnp1_t1_o3,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"numNetworkPolicies"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(wep4_n2_ns1, 2, 0),
					qcEndpoint(hep1_n2, 2, 0), qcEndpoint(hep2_n3, 1, 0), qcEndpoint(wep1_n1_ns1, 2, 1),
					qcEndpoint(wep3_n1_ns2, 2, 1), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by numPolicies (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp1_t1_o3, sgnp2_t1_o4,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"numPolicies"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep2_n3, 1, 0),
					qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1),
				},
			},
		},
		{
			"multiple weps and heps, tier1 policy - query all of them; sort by numPolicies and some bogus columns (with staged policies)",
			[]resourcemgr.ResourceObject{
				hep2_n3, hep3_n4, hep1_n2, hep4_n4_unlabelled, wep4_n2_ns1, wep3_n1_ns2, profile_rack_001, wep1_n1_ns1,
				wep5_n3_ns2_unlabelled, tier1, np1_t1_o1_ns1, np2_t1_o2_ns2, gnp2_t1_o4, sgnp1_t1_o3,
			},
			client.QueryEndpointsReq{
				Sort: &client.Sort{
					SortBy: []string{"bazbarfoo", "numPolicies", "foobarbaz"},
				},
			},
			&client.QueryEndpointsResp{
				Count: 8,
				Items: []client.Endpoint{
					qcEndpoint(hep4_n4_unlabelled, 1, 0), qcEndpoint(hep3_n4, 1, 0), qcEndpoint(hep2_n3, 1, 0),
					qcEndpoint(wep4_n2_ns1, 2, 0), qcEndpoint(hep1_n2, 2, 0), qcEndpoint(wep5_n3_ns2_unlabelled, 1, 1),
					qcEndpoint(wep1_n1_ns1, 2, 1), qcEndpoint(wep3_n1_ns2, 2, 1),
				},
			},
		},
		{
			"reset by removing all endpoints and policy; perform empty query",
			[]resourcemgr.ResourceObject{},
			client.QueryEndpointsReq{},
			&client.QueryEndpointsResp{
				Count: 0,
				Items: []client.Endpoint{},
			},
		},
		{
			description: "multiple weps, no policy - query by namespace",
			resources: []resourcemgr.ResourceObject{
				wep1_n1_ns1, wep3_n1_ns2, wep5_n3_ns2_unlabelled,
			},
			query: client.QueryEndpointsReq{
				Namespace: getStringPointer("namespace-2"),
				Sort: &client.Sort{
					SortBy: []string{"name"},
				},
			},
			response: &client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(wep3_n1_ns2, 0, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 0, 0),
				},
			},
		},
		{
			description: "multiple heps, weps, no policy - query by namespace, return heps only if namespace is set to empty string",
			resources: []resourcemgr.ResourceObject{
				wep1_n1_ns1, wep3_n1_ns2, wep5_n3_ns2_unlabelled, hep1_n2,
			},
			query: client.QueryEndpointsReq{
				Namespace: getStringPointer(""),
				Sort: &client.Sort{
					SortBy: []string{"name"},
				},
			},
			response: &client.QueryEndpointsResp{
				Count: 1,
				Items: []client.Endpoint{
					qcEndpoint(hep1_n2, 0, 0),
				},
			},
		},
		{
			description: "multiple heps, weps, no policy - query by namespace, return all if namespace is not set or nil",
			resources: []resourcemgr.ResourceObject{
				wep1_n1_ns1, wep3_n1_ns2, wep5_n3_ns2_unlabelled, hep1_n2,
			},
			query: client.QueryEndpointsReq{
				Namespace: nil,
				Sort: &client.Sort{
					SortBy: []string{"name"},
				},
			},
			response: &client.QueryEndpointsResp{
				Count: 4,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 0, 0),
					qcEndpoint(wep3_n1_ns2, 0, 0),
					qcEndpoint(hep1_n2, 0, 0),
					qcEndpoint(wep5_n3_ns2_unlabelled, 0, 0),
				},
			},
		},
		{
			description: "multiple heps, weps, no policy - query by pod name prefix, return all endpoints starting with podNamePrefix",
			resources: []resourcemgr.ResourceObject{
				wep1_n1_ns1, wep3_n1_ns2, wep2_n1_ns1_filtered_in, hep1_n2,
			},
			query: client.QueryEndpointsReq{
				PodNamePrefix: getStringPointer("pod1"),
				Sort: &client.Sort{
					SortBy: []string{"name"},
				},
			},
			response: &client.QueryEndpointsResp{
				Count: 2,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 0, 0),
					qcEndpoint(wep2_n1_ns1_filtered_in, 0, 0),
				},
			},
		},
		{
			description: "multiple heps, weps, no policy - query by pod name prefix, return all if podPrefix is empty",
			resources: []resourcemgr.ResourceObject{
				wep1_n1_ns1, wep3_n1_ns2, hep1_n2,
			},
			query: client.QueryEndpointsReq{
				PodNamePrefix: getStringPointer(""),
				Sort: &client.Sort{
					SortBy: []string{"name"},
				},
			},
			response: &client.QueryEndpointsResp{
				Count: 3,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 0, 0),
					qcEndpoint(wep3_n1_ns2, 0, 0),
					qcEndpoint(hep1_n2, 0, 0),
				},
			},
		},
		{
			description: "multiple heps, weps, no policy - query by pod name prefix, return all if podPrefix is nil",
			resources: []resourcemgr.ResourceObject{
				wep1_n1_ns1, wep3_n1_ns2, hep1_n2,
			},
			query: client.QueryEndpointsReq{
				PodNamePrefix: nil,
				Sort: &client.Sort{
					SortBy: []string{"name"},
				},
			},
			response: &client.QueryEndpointsResp{
				Count: 3,
				Items: []client.Endpoint{
					qcEndpoint(wep1_n1_ns1, 0, 0),
					qcEndpoint(wep3_n1_ns2, 0, 0),
					qcEndpoint(hep1_n2, 0, 0),
				},
			},
		},
	}
}

func getStringPointer(s string) *string {
	return &s
}
