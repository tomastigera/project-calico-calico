// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.
package fv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/client"
	"github.com/projectcalico/calico/queryserver/queryserver/auth"
	"github.com/projectcalico/calico/queryserver/queryserver/config"
	authhandler "github.com/projectcalico/calico/queryserver/queryserver/handlers/auth"
	queryhdr "github.com/projectcalico/calico/queryserver/queryserver/handlers/query"
	"github.com/projectcalico/calico/queryserver/queryserver/server"
)

var _ = testutils.E2eDatastoreDescribe("Query tests", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {
	// Disable the max length output truncation for these tests.
	format.MaxLength = 0

	DescribeTable("Query tests (e2e with server)",
		func(tqds []testQueryData, crossCheck func(tqd testQueryData, addr string, netClient *http.Client)) {
			By("Creating a v3 client interface")
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			By("Cleaning the datastore")
			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			err = be.Clean()
			Expect(err).NotTo(HaveOccurred())

			// Choose an arbitrary port for the server to listen on.
			By("Choosing an arbitrary available local port for the queryserver")
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())
			addr := listener.Addr().String()
			_ = listener.Close()

			// Get server configuration variables meant for FVs.
			servercfg := getDummyConfigFromEnvFv(addr, "", "")

			fakeK8sClient := fake.NewSimpleClientset()
			mh := &mockHandler{}

			authz := &mockAuthorizer{}

			By("Starting the queryserver")
			srv := server.NewServer(fakeK8sClient, &config, servercfg, mh, authz)
			err = srv.Start()
			Expect(err).NotTo(HaveOccurred())
			defer srv.Stop()

			var configured map[model.ResourceKey]resourcemgr.ResourceObject
			netClient := &http.Client{Timeout: time.Second * 10}
			for _, tqd := range tqds {
				By(fmt.Sprintf("Creating the resources for test: %s", tqd.description))
				configured = createResources(c, tqd.resources, configured)

				By(fmt.Sprintf("Running query for test: %s", tqd.description))

				// remove CreationTime, Order, and UID from QueryPoliciesResp as the tests are not build to
				// verify these values.
				switch tqd.response.(type) {
				case *client.QueryPoliciesResp:
					if tqd.response.(*client.QueryPoliciesResp).Items != nil {
						for i := range tqd.response.(*client.QueryPoliciesResp).Items {
							tqd.response.(*client.QueryPoliciesResp).Items[i].CreationTime = nil
							tqd.response.(*client.QueryPoliciesResp).Items[i].Order = nil
							tqd.response.(*client.QueryPoliciesResp).Items[i].UID = ""
						}
					}
				}
				queryFn := getQueryFunction(tqd, addr, netClient)
				Eventually(queryFn).Should(Equal(tqd.response), tqd.description)
				Consistently(queryFn).Should(Equal(tqd.response), tqd.description)

				if crossCheck != nil {
					By("Running a cross-check query")
					crossCheck(tqd, addr, netClient)
				}
			}
		},

		Entry("Summary queries", summaryTestQueryData(), nil),
		Entry("Node queries", nodeTestQueryData(), nil),
		Entry("Endpoint queries", endpointTestQueryData(), crossCheckEndpointQuery),
		Entry("Policy queries", policyTestQueryData(), crossCheckPolicyQuery),
	)
})

func getQueryFunction(tqd testQueryData, addr string, netClient *http.Client) func() interface{} {
	By(fmt.Sprintf("Creating the query function for test: %s", tqd.description))
	return func() interface{} {
		By(fmt.Sprintf("Calculating the URL for the test: %s", tqd.description))
		qurl, httpMethod := calculateQueryUrl(addr, tqd.query)
		qbody := calculateQueryBody(tqd.query)

		// Return the result if we have it, otherwise the error, this allows us to use Eventually to
		// check both values and errors.
		log.WithField("url", qurl).Debug("Running query")

		var r *http.Response
		var err error
		switch httpMethod {
		case authhandler.MethodPOST:
			r, err = netClient.Post(qurl, "Application/Json", qbody)
		default:
			r, err = netClient.Get(qurl)
		}
		if err != nil {
			return err
		}
		defer func() { _ = r.Body.Close() }()
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		bodyString := string(bodyBytes)
		if r.StatusCode != http.StatusOK {
			return errorResponse{
				text: strings.TrimSpace(bodyString),
				code: r.StatusCode,
			}
		}

		if _, ok := tqd.response.(errorResponse); ok {
			// We are expecting an error but didn't get one, we'll have to return an error containing
			// the raw json.
			return fmt.Errorf("expecting error but command was successful: %s", bodyString)
		}

		// The response body should be json and the same type as the expected response object.
		ro := reflect.New(reflect.TypeOf(tqd.response).Elem()).Interface()
		err = json.Unmarshal(bodyBytes, ro)
		if err != nil {
			return fmt.Errorf("unmarshal error: %v: %v: %v", reflect.TypeOf(ro), err, bodyString)
		}

		// remove CreationTime, Order, and UID from QueryPoliciesResp as the tests are not build to
		// verify these values.
		switch ro := ro.(type) {
		case *client.QueryPoliciesResp:
			for i := range ro.Items {
				ro.Items[i].UID = ""
				ro.Items[i].CreationTime = nil
				ro.Items[i].Order = nil
			}
		}

		return ro
	}
}

func calculateQueryUrl(addr string, query interface{}) (string, authhandler.HTTPMethod) {
	var parms []string
	u := "http://" + addr + "/"
	httpMethod := authhandler.MethodGET

	switch qt := query.(type) {
	case client.QueryEndpointsReq:
		u += "endpoints"
		if qt.Endpoint != nil {
			u = u + "/" + namespacedNameFromKey(qt.Endpoint)
			break
		}

		httpMethod = authhandler.MethodPOST
	case client.QueryPoliciesReq:
		// Base URL
		if qt.Policy != nil {
			// Single policy
			u = u + policyIDStringFromkey(qt.Policy)
			break
		} else {
			// List all policies
			u += "policies"
		}

		// Add query parameters.
		parms = appendResourceParm(parms, queryhdr.QueryEndpoint, qt.Endpoint)
		parms = appendResourceParm(parms, queryhdr.QueryNetworkSet, qt.NetworkSet)
		if len(qt.Tier) > 0 {
			parms = appendStringParm(parms, queryhdr.QueryTier, strings.Join(qt.Tier, ","))
		}
		parms = appendStringParm(parms, queryhdr.QueryUnmatched, fmt.Sprint(qt.Unmatched))
		for k, v := range qt.Labels {
			parms = append(parms, queryhdr.QueryLabelPrefix+k+"="+v)
		}
		parms = appendPageParms(parms, qt.Page)
		parms = appendSortParms(parms, qt.Sort)
	case client.QueryNodesReq:
		u += "nodes"
		if qt.Node != nil {
			u = u + "/" + namespacedNameFromKey(qt.Node)
			break
		}
		parms = appendPageParms(parms, qt.Page)
		parms = appendSortParms(parms, qt.Sort)
	case client.QueryClusterReq:
		u += "summary?from=now-15m&to=now-0m"
	}

	if len(parms) == 0 {
		return u, httpMethod
	}
	return u + "?" + strings.Join(parms, "&"), httpMethod
}

func calculateQueryBody(query interface{}) io.Reader {
	switch qt := query.(type) {
	case client.QueryEndpointsReq:
		var policy []string
		if qt.Policy != nil {
			policy = []string{policyIDStringFromkey(qt.Policy)}
		}
		body := client.QueryEndpointsReqBody{
			Policy:              policy,
			RuleDirection:       qt.RuleDirection,
			RuleIndex:           qt.RuleIndex,
			RuleEntity:          qt.RuleEntity,
			RuleNegatedSelector: qt.RuleNegatedSelector,
			Selector:            qt.Selector,
			Unprotected:         qt.Unprotected,
			EndpointsList:       qt.EndpointsList,
			Node:                qt.Node,
			Namespace:           qt.Namespace,
			PodNamePrefix:       qt.PodNamePrefix,
			Unlabelled:          qt.Unlabelled,
			Page:                qt.Page,
			Sort:                qt.Sort,
		}

		bodyData, err := json.Marshal(body)
		Expect(err).ShouldNot(HaveOccurred())

		return bytes.NewReader(bodyData)
	}

	return nil
}

func appendPageParms(parms []string, page *client.Page) []string {
	if page == nil {
		return append(parms, queryhdr.QueryNumPerPage+"="+queryhdr.AllResults)
	}
	return append(parms,
		fmt.Sprintf("%s=%d", queryhdr.QueryPageNum, page.PageNum),
		fmt.Sprintf("%s=%d", queryhdr.QueryNumPerPage, page.NumPerPage),
	)
}

func appendSortParms(parms []string, sort *client.Sort) []string {
	if sort == nil {
		return parms
	}
	for _, f := range sort.SortBy {
		parms = append(parms, fmt.Sprintf("%s=%s", queryhdr.QuerySortBy, f))
	}
	return append(parms, fmt.Sprintf("%s=%v", queryhdr.QueryReverseSort, sort.Reverse))
}

func appendStringParm(parms []string, key, value string) []string {
	if value == "" {
		return parms
	}
	return append(parms, key+"="+url.QueryEscape(value))
}

func appendResourceParm(parms []string, key string, value model.Key) []string {
	if value == nil {
		return parms
	}
	return append(parms, key+"="+namespacedNameFromKey(value))
}

func namespacedNameFromKey(k model.Key) string {
	rk := k.(model.ResourceKey)
	if rk.Namespace != "" {
		return rk.Namespace + "/" + rk.Name
	}
	return rk.Name
}

// policyIDStringFromkey returns the policy ID string in the format expected by the query API.
func policyIDStringFromkey(k model.Key) string {
	rk := k.(model.ResourceKey)
	if rk.Namespace != "" {
		return strings.ToLower(rk.Kind) + "/" + rk.Namespace + "/" + rk.Name
	}
	return strings.ToLower(rk.Kind) + "/" + rk.Name
}

func crossCheckPolicyQuery(tqd testQueryData, addr string, netClient *http.Client) {
	qpr, ok := tqd.response.(*client.QueryPoliciesResp)
	if !ok {
		// Don't attempt to cross check errored queries since we have nothing to cross-check.
		return
	}
	for _, p := range qpr.Items {
		policy := p.Kind + "/" + p.Name
		if p.Namespace != "" {
			policy = p.Kind + "/" + p.Namespace + "/" + p.Name
		}

		By(fmt.Sprintf("Running endpoint query for policy: %s", policy))
		qurl := "http://" + addr + "/endpoints"
		body := client.QueryEndpointsReqBody{
			Policy: []string{policy},
			Page:   nil,
		}
		bodyData, err := json.Marshal(body)
		Expect(err).ShouldNot(HaveOccurred())

		r, err := netClient.Post(qurl, "Application/Json", bytes.NewReader(bodyData))
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = r.Body.Close() }()
		bodyBytes, err := io.ReadAll(r.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(r.StatusCode).To(Equal(http.StatusOK))
		output := client.QueryEndpointsResp{}
		err = json.Unmarshal(bodyBytes, &output)
		Expect(err).NotTo(HaveOccurred())
		var numWeps, numHeps int
		for _, i := range output.Items {
			if i.Kind == libapi.KindWorkloadEndpoint {
				numWeps++
			} else {
				numHeps++
			}
		}
		Expect(numHeps).To(Equal(p.NumHostEndpoints))
		Expect(numWeps).To(Equal(p.NumWorkloadEndpoints))
	}
}

func crossCheckEndpointQuery(tqd testQueryData, addr string, netClient *http.Client) {
	qpr, ok := tqd.response.(*client.QueryEndpointsResp)
	if !ok {
		// Don't attempt to cross check errored queries since we have nothing to cross-check.
		return
	}
	for _, p := range qpr.Items {
		endpoint := p.Name
		if p.Namespace != "" {
			endpoint = p.Namespace + "/" + endpoint
		}

		By(fmt.Sprintf("Running policy query for endpoint: %s", endpoint))
		qurl := "http://" + addr + "/policies?endpoint=" + endpoint + "&page=all"

		r, err := netClient.Get(qurl)
		Expect(err).NotTo(HaveOccurred())

		defer func() { _ = r.Body.Close() }()
		bodyBytes, err := io.ReadAll(r.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(r.StatusCode).To(Equal(http.StatusOK))

		output := client.QueryPoliciesResp{}
		err = json.Unmarshal(bodyBytes, &output)
		Expect(err).NotTo(HaveOccurred())

		var numNps, numGnps int
		for _, i := range output.Items {
			switch i.Kind {
			case apiv3.KindNetworkPolicy,
				apiv3.KindStagedNetworkPolicy,
				apiv3.KindStagedKubernetesNetworkPolicy,
				model.KindKubernetesNetworkPolicy:
				// TODO: These are all counted as NetworkPolicies for now.
				numNps++
			case apiv3.KindGlobalNetworkPolicy,
				apiv3.KindStagedGlobalNetworkPolicy,
				model.KindKubernetesAdminNetworkPolicy,
				model.KindKubernetesBaselineAdminNetworkPolicy:
				// TODO: These are all counted as GlobalNetworkPolicies for now.
				numGnps++
			default:
				Expect(true).To(BeFalse(), fmt.Sprintf("unexpected policy kind: %s", i.Kind))
			}
		}
		Expect(numNps).To(Equal(p.NumNetworkPolicies), tqd.description)
		Expect(numGnps).To(Equal(p.NumGlobalNetworkPolicies), tqd.description)
	}
}

// getDummyConfigFromEnvFv returns the server configuration variables meant for FV tests.
func getDummyConfigFromEnvFv(addr, webKey, webCert string) *config.Config {
	config := &config.Config{
		ListenAddr: addr,
		TLSCert:    webCert,
		TLSKey:     webKey,
	}

	return config
}

type mockHandler struct{}

func (mh *mockHandler) AuthenticationHandler(handlerFunc http.HandlerFunc, httpMethodAllowed authhandler.HTTPMethod) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != string(httpMethodAllowed) {
			// Operation not allowed
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, err := w.Write([]byte("Method Not Allowed"))
			if err != nil {
				log.WithError(err).Error("failed to write body to response.")
			}
			return
		}

		handlerFunc.ServeHTTP(w, req)
	}
}

type mockAuthorizer struct{}

type mockPermissions struct{}

func (p *mockPermissions) IsAuthorized(res api.Resource, tier *string, verbs []rbac.Verb) bool {
	return true
}

func (authz *mockAuthorizer) PerformUserAuthorizationReview(ctx context.Context,
	authReviewattributes []apiv3.AuthorizationReviewResourceAttributes,
) (auth.Permission, error) {
	return &mockPermissions{}, nil
}

// TODO(rlb):
// - reorder policies
// - re-node a HostEndpoint
