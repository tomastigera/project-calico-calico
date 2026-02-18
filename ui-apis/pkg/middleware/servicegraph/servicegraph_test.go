// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package servicegraph_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	. "github.com/projectcalico/calico/ui-apis/pkg/middleware/servicegraph"
)

const (
	timeStrFrom = "2021-05-30T21:23:10Z"
	timeStrTo   = "2021-05-30T21:38:10Z"
)

func toJson(obj interface{}) string {
	b, err := json.MarshalIndent(obj, "      ", "  ")
	ExpectWithOffset(2, err).NotTo(HaveOccurred())
	return "      " + string(b)
}

func compareEdges(actual, expected v1.GraphEdge) []string {
	var errStrs []string
	if !reflect.DeepEqual(actual.Stats, expected.Stats) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  Stats are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.Stats),
			toJson(expected.Stats)),
		)
	}
	if !reflect.DeepEqual(actual.Selectors, expected.Selectors) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  Selectors are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.Selectors),
			toJson(expected.Selectors)),
		)
	}
	if !reflect.DeepEqual(actual.ServicePorts, expected.ServicePorts) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  ServicePorts are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.ServicePorts),
			toJson(expected.ServicePorts)),
		)
	}
	if !reflect.DeepEqual(actual.EndpointProtoPorts, expected.EndpointProtoPorts) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  EndpointProtoPorts are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.EndpointProtoPorts),
			toJson(expected.EndpointProtoPorts)),
		)
	}
	if len(errStrs) > 0 {
		// Prepend a heading for this edge.
		errStrs = append([]string{"==== Edge data is incorrect for " + actual.ID.String() + " ===="}, errStrs...)
	}

	// Handle new fields not being added.
	if len(errStrs) == 0 {
		ExpectWithOffset(1, actual).To(Equal(expected), "Edge comparison function needs updating")
	}

	return errStrs
}

func compareNodes(actual, expected v1.GraphNode) []string {
	//	Events GraphEvents `json:"events,omitempty"`
	var errStrs []string
	if !reflect.DeepEqual(actual.ParentID, expected.ParentID) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  ParentID are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.ParentID),
			toJson(expected.ParentID)),
		)
	}
	if !reflect.DeepEqual(actual.ServicePorts, expected.ServicePorts) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  ServicePorts are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.ServicePorts),
			toJson(expected.ServicePorts)),
		)
	}
	if !reflect.DeepEqual(actual.AggregatedProtoPorts, expected.AggregatedProtoPorts) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  AggregatedProtoPorts are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.AggregatedProtoPorts),
			toJson(expected.AggregatedProtoPorts)),
		)
	}
	if !reflect.DeepEqual(actual.StatsWithin, expected.StatsWithin) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  StatsWithin are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.StatsWithin),
			toJson(expected.StatsWithin)),
		)
	}
	if !reflect.DeepEqual(actual.StatsIngress, expected.StatsIngress) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  StatsIngress are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.StatsIngress),
			toJson(expected.StatsIngress)),
		)
	}
	if !reflect.DeepEqual(actual.StatsEgress, expected.StatsEgress) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  StatsEgress are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.StatsEgress),
			toJson(expected.StatsEgress)),
		)
	}
	if !reflect.DeepEqual(actual.Expandable, expected.Expandable) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  Expandable are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.Expandable),
			toJson(expected.Expandable)),
		)
	}
	if !reflect.DeepEqual(actual.Expanded, expected.Expanded) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  Expanded are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.Expanded),
			toJson(expected.Expanded)),
		)
	}
	if !reflect.DeepEqual(actual.FollowEgress, expected.FollowEgress) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  FollowEgress are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.FollowEgress),
			toJson(expected.FollowEgress)),
		)
	}
	if !reflect.DeepEqual(actual.FollowIngress, expected.FollowIngress) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  FollowIngress are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.FollowIngress),
			toJson(expected.FollowIngress)),
		)
	}
	if !reflect.DeepEqual(actual.Selectors, expected.Selectors) {
		errStrs = append(errStrs, fmt.Sprintf(
			"  Selectors are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.Selectors),
			toJson(expected.Selectors)),
		)
	}
	if actual.EventsCount != expected.EventsCount {
		errStrs = append(errStrs, fmt.Sprintf(
			"  EventsCount are not the same:\n    Actual:\n%v\n    Expected:\n%v",
			toJson(actual.EventsCount),
			toJson(expected.EventsCount)),
		)
	}
	if len(errStrs) > 0 {
		// Prepend a heading for this edge.
		errStrs = append([]string{"==== Node data is incorrect for " + string(actual.ID) + " ===="}, errStrs...)
	}

	// Handle new fields not being added.
	if len(errStrs) == 0 && !reflect.DeepEqual(actual, expected) {
		ExpectWithOffset(1, actual).To(Equal(expected), "Node comparison function needs updating")
	}

	return errStrs
}

var _ = Describe("Service graph data tests", func() {
	var fakeClient ctrlclient.WithWatch

	// Track last handled response filename and expected data.
	var expectDataFilename string
	var actualDataFilename string
	var actualData *v1.ServiceGraphResponse

	BeforeEach(func() {
		scheme := kscheme.Scheme
		err := v3.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		fakeClient = fakeclient.NewClientBuilder().WithScheme(scheme).Build()
	})

	AfterEach(func() {
		// If the test failed then write out the actual contents of the file. We can verify the data by hand and if
		// correct rename (by removing the .actual from the name).
		if CurrentSpecReport().Failed() && actualData != nil && actualDataFilename != "" {
			sort.Slice(actualData.Nodes, func(i, j int) bool {
				return actualData.Nodes[i].ID < actualData.Nodes[j].ID
			})
			sort.Slice(actualData.Edges, func(i, j int) bool {
				return actualData.Edges[i].ID.String() < actualData.Edges[j].ID.String()
			})
			formatted, err := json.MarshalIndent(actualData, "", "  ")
			Expect(err).NotTo(HaveOccurred())
			err = os.WriteFile(actualDataFilename, formatted, 0o644)
			Expect(err).NotTo(HaveOccurred())

			_, err = fmt.Fprintf(GinkgoWriter, `
**********************************************************************************
  Comparison failed comparing service graph response to expected response data.

  Expected response is in test file: %s
  Actual response has been written out to file: %s

  This may be a valid failure if the response format has been modified. If so,
  check the difference in the files and once verified as correct the file may be
  renamed so that the test no long errors.
**********************************************************************************
`, expectDataFilename, actualDataFilename)
			Expect(err).NotTo(HaveOccurred())
		}

		actualData = nil
		actualDataFilename = ""
		expectDataFilename = ""
	})

	DescribeTable("valid request parameters",
		func(sgr v1.ServiceGraphRequest, code int, resp string, rbac RBACFilter, names NameHelper) {
			// Create a mock backend.
			mb := CreateMockBackendWithData(rbac, names)

			// Create a service graph.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sg := NewServiceGraphHandlerWithBackend(fakeClient, mb, &Config{
				ServiceGraphCacheMaxEntries:        1,
				ServiceGraphCachePolledEntryAgeOut: 5 * time.Minute,
				ServiceGraphCachePollLoopInterval:  5 * time.Minute,
				ServiceGraphCachePollQueryInterval: 5 * time.Minute,
				ServiceGraphCacheDataSettleTime:    5 * time.Minute,
				ServiceGraphCacheFetchL7:           true,
				ServiceGraphCacheFetchDNS:          true,
				ServiceGraphCacheFetchEvents:       true,
			})

			// Fix the time range in the request.
			timeFrom, err := time.Parse(time.RFC3339, timeStrFrom)
			Expect(err).NotTo(HaveOccurred())
			timeTo, err := time.Parse(time.RFC3339, timeStrTo)
			Expect(err).NotTo(HaveOccurred())
			sgr.TimeRange = &lmav1.TimeRange{
				From: timeFrom,
				To:   timeTo,
			}

			// Marshal the request and create an HTTP request
			sgrb, err := json.Marshal(sgr)
			Expect(err).NotTo(HaveOccurred())
			body := io.NopCloser(bytes.NewReader(sgrb))
			req, err := http.NewRequest("POST", "/serviceGraph", body)
			Expect(err).NotTo(HaveOccurred())
			req = req.WithContext(ctx)

			// Pass it through the handler
			writer := httptest.NewRecorder()
			sg.ServeHTTP(writer, req)
			Expect(writer.Code).To(Equal(code))

			// The remaining checks are only applicable if the response was 200 OK.
			if code != http.StatusOK {
				Expect(strings.TrimSpace(writer.Body.String())).To(Equal(resp))
				return
			}

			// Parse the response and the expected response.
			var actual, expected v1.ServiceGraphResponse
			err = json.Unmarshal(writer.Body.Bytes(), &actual)
			Expect(err).NotTo(HaveOccurred())
			actualData = &actual

			// Track the last handled response data and the response filename. We use this to write out the expected
			// file in the event of an error.  It makes dev cycles easier.
			expectDataFilename = "testdata/responses/test-" + resp + ".json"
			actualDataFilename = "testdata/responses/test-" + resp + ".actual.json"

			// Parse the expected response.
			content, err := os.ReadFile(expectDataFilename)
			Expect(err).NotTo(HaveOccurred())
			err = json.Unmarshal(content, &expected)
			Expect(err).NotTo(HaveOccurred())

			// Compile a complete list of differences.
			actualEdgesMap := make(map[v1.GraphEdgeID]v1.GraphEdge)
			expectedEdgesMap := make(map[v1.GraphEdgeID]v1.GraphEdge)
			actualNodesMap := make(map[v1.GraphNodeID]v1.GraphNode)
			expectedNodesMap := make(map[v1.GraphNodeID]v1.GraphNode)

			for i := range actual.Edges {
				actualEdgesMap[actual.Edges[i].ID] = actual.Edges[i]
			}
			for i := range expected.Edges {
				expectedEdgesMap[expected.Edges[i].ID] = expected.Edges[i]
			}
			for i := range actual.Nodes {
				actualNodesMap[actual.Nodes[i].ID] = actual.Nodes[i]
			}
			for i := range expected.Nodes {
				expectedNodesMap[expected.Nodes[i].ID] = expected.Nodes[i]
			}

			var errStrs []string

			for id, actual := range actualEdgesMap {
				expected, ok := expectedEdgesMap[id]
				if ok {
					errStrs = append(errStrs, compareEdges(actual, expected)...)
					delete(expectedEdgesMap, id)
				} else {
					errStrs = append(errStrs, "==== Edge found but not expected: "+id.String()+" ====")
				}
			}
			for id := range expectedEdgesMap {
				errStrs = append(errStrs, "==== Edge expected but not found: "+id.String()+" ====")
			}

			for id, actual := range actualNodesMap {
				expected, ok := expectedNodesMap[id]
				if ok {
					errStrs = append(errStrs, compareNodes(actual, expected)...)
					delete(expectedNodesMap, id)
				} else {
					errStrs = append(errStrs, "==== Node found but not expected: "+string(id)+" ====")
				}
			}
			for id := range expectedNodesMap {
				errStrs = append(errStrs, "==== Node expected but not found: "+string(id)+" ====")
			}

			if !reflect.DeepEqual(actual.TimeIntervals, expected.TimeIntervals) {
				errStrs = append(errStrs, fmt.Sprintf(
					"==== Time intervals are not the same ====\n  Actual=%v\n  Expected=%v",
					toJson(actual.TimeIntervals),
					toJson(expected.TimeIntervals)),
				)
			}

			if !reflect.DeepEqual(actual.Selectors, expected.Selectors) {
				errStrs = append(errStrs, fmt.Sprintf(
					"  View selectors are not the same:\n    Actual:\n%v\n    Expected:\n%v",
					toJson(actual.Selectors),
					toJson(expected.Selectors)),
				)
			}

			if len(errStrs) > 0 {
				err := errors.New(strings.Join(errStrs, "\n\n"))
				Expect(err).NotTo(HaveOccurred())
			}
		},
		Entry("No request parameters",
			v1.ServiceGraphRequest{}, http.StatusOK, "001-no-req-parms", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Non-nil empty request parameters",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:                    []v1.GraphNodeID{},
					Expanded:                 []v1.GraphNodeID{},
					HostAggregationSelectors: []v1.NamedSelector{},
					FollowedEgress:           []v1.GraphNodeID{},
					FollowedIngress:          []v1.GraphNodeID{},
					Layers:                   []v1.Layer{},
				},
			}, http.StatusOK, "001-no-req-parms", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Focus on storefront",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus: []v1.GraphNodeID{"namespace/storefront"},
				},
			}, http.StatusOK, "002-focus-storefront", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Focus and expand storefront",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:    []v1.GraphNodeID{"namespace/storefront"},
					Expanded: []v1.GraphNodeID{"namespace/storefront"},
				},
			}, http.StatusOK, "003-focus-expand-storefront", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Focus and expand storefront, follow ingress",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:           []v1.GraphNodeID{"namespace/storefront"},
					Expanded:        []v1.GraphNodeID{"namespace/storefront"},
					FollowedIngress: []v1.GraphNodeID{"hosts/*"},
				},
			}, http.StatusOK, "004-focus-expand-storefront-follow-ingress", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Focus and expand storefront, follow egress",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:          []v1.GraphNodeID{"namespace/storefront"},
					Expanded:       []v1.GraphNodeID{"namespace/storefront"},
					FollowedEgress: []v1.GraphNodeID{"hosts/*"},
				},
			}, http.StatusOK, "005-focus-expand-storefront-follow-egress", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Split ingress and egress",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					SplitIngressEgress: true,
				},
			}, http.StatusOK, "006-split-ingress-egress", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Follow connection direction",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:                     []v1.GraphNodeID{"namespace/tigera-elasticsearch"},
					FollowConnectionDirection: true,
				},
			}, http.StatusOK, "007-elastic-follow", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Follow connection direction with split ingress/egress",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:                     []v1.GraphNodeID{"namespace/tigera-elasticsearch"},
					FollowConnectionDirection: true,
					SplitIngressEgress:        true,
				},
			}, http.StatusOK, "008-elastic-follow-split", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Infrastructure layer, no focus",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Layers: []v1.Layer{{
						Name: "infrastructure-tigera",
						Nodes: []v1.GraphNodeID{
							"namespace/tigera-kibana",
							"namespace/tigera-fluentd",
							"namespace/tigera-manager",
							"namespace/tigera-compliance",
							"namespace/tigera-eck-operator",
							"namespace/tigera-elasticsearch",
							"namespace/tigera-intrusion-detection",
							"namespace/tigera-prometheus",
							"namespace/calico-system",
						},
					}, {
						Name: "infrastructure-kubernetes",
						Nodes: []v1.GraphNodeID{
							"namespace/kube-system",
							"namespace/crc-local-storage-system",
							"svcgp;svc/default/kubernetes",
						},
					}},
				},
			}, http.StatusOK, "009-infra-layers-no-focus", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("No request parameters, no permissions",
			v1.ServiceGraphRequest{}, http.StatusOK, "010-no-req-parms-no-permissions", RBACFilterIncludeNone{}, NewMockNameHelper(nil, nil),
		),
		Entry("No request parameters, aggregating nodes",
			v1.ServiceGraphRequest{}, http.StatusOK, "011-no-req-parms-host-aggr", RBACFilterIncludeAll{},
			NewMockNameHelper(map[string]string{
				"rob-bz-q5fq-kadm-infra-0": "infra",
				"rob-bz-q5fq-kadm-node-1":  "worker",
				"rob-bz-q5fq-kadm-node-0":  "worker",
			}, nil),
		),
		Entry("No request parameters, aggregating nodes, expanded node",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Expanded: []v1.GraphNodeID{"hosts/worker"},
				},
			}, http.StatusOK, "012-no-req-parms-host-aggr-expand", RBACFilterIncludeAll{},
			NewMockNameHelper(map[string]string{
				"rob-bz-q5fq-kadm-infra-0": "infra",
				"rob-bz-q5fq-kadm-node-1":  "worker",
				"rob-bz-q5fq-kadm-node-0":  "worker",
			}, nil),
		),
		Entry("Focus and expand storefront, expand emailservice",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:    []v1.GraphNodeID{"namespace/storefront"},
					Expanded: []v1.GraphNodeID{"namespace/storefront", "svcgp;svc/storefront/emailservice"},
				},
			}, http.StatusOK, "013-focus-expand-storefront-expand-emailsvc", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Focus default",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus: []v1.GraphNodeID{"namespace/default"},
				},
			}, http.StatusOK, "014-focus-default", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Focus and expand default",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:    []v1.GraphNodeID{"namespace/default"},
					Expanded: []v1.GraphNodeID{"namespace/default"},
				},
			}, http.StatusOK, "015-focus-expand-default", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Focus and expand default, expand kubernetes service",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:    []v1.GraphNodeID{"namespace/default"},
					Expanded: []v1.GraphNodeID{"namespace/default", "svcgp;svc/default/kubernetes"},
				},
			}, http.StatusOK, "016-focus-expand-default-expand-kubernetes", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Storefront layer, focus on storefront namespace",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus: []v1.GraphNodeID{"namespace/storefront"},
					Layers: []v1.Layer{{
						Name: "storefront-layer",
						Nodes: []v1.GraphNodeID{
							"namespace/storefront",
						},
					}},
				},
			}, http.StatusOK, "017-storefront-layer-focus-storefront", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Expand and focus shippingservice",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:    []v1.GraphNodeID{"svcgp;svc/storefront/shippingservice"},
					Expanded: []v1.GraphNodeID{"svcgp;svc/storefront/shippingservice"},
				},
			}, http.StatusOK, "018-expand-focus-shippingservice", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Expand and focus shippingservice in layer",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:    []v1.GraphNodeID{"svcgp;svc/storefront/shippingservice"},
					Expanded: []v1.GraphNodeID{"svcgp;svc/storefront/shippingservice"},
					Layers: []v1.Layer{{
						Name: "shippingservice-layer",
						Nodes: []v1.GraphNodeID{
							"svcgp;svc/storefront/shippingservice",
						},
					}},
				},
			}, http.StatusOK, "019-expand-focus-shippingservice-layer", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("With expanded ports: Focus and expand storefront, expand emailservice",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:       []v1.GraphNodeID{"namespace/storefront"},
					Expanded:    []v1.GraphNodeID{"namespace/storefront", "svcgp;svc/storefront/emailservice"},
					ExpandPorts: true,
				},
			}, http.StatusOK, "020-focus-expand-storefront-expand-emailsvc-expand-ports", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("With expanded ports: Focus and expand default, expand kubernetes service",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:       []v1.GraphNodeID{"namespace/default"},
					Expanded:    []v1.GraphNodeID{"namespace/default", "svcgp;svc/default/kubernetes"},
					ExpandPorts: true,
				},
			}, http.StatusOK, "021-focus-expand-default-expand-kubernetes-expand-ports", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("With expanded ports: Expand and focus shippingservice",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:       []v1.GraphNodeID{"svcgp;svc/storefront/shippingservice"},
					Expanded:    []v1.GraphNodeID{"svcgp;svc/storefront/shippingservice"},
					ExpandPorts: true,
				},
			}, http.StatusOK, "022-expand-focus-shippingservice-expand-ports", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("With expanded ports: Expand and focus shippingservice in layer",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:    []v1.GraphNodeID{"svcgp;svc/storefront/shippingservice"},
					Expanded: []v1.GraphNodeID{"svcgp;svc/storefront/shippingservice"},
					Layers: []v1.Layer{{
						Name: "shippingservice-layer",
						Nodes: []v1.GraphNodeID{
							"svcgp;svc/storefront/shippingservice",
						},
					}},
					ExpandPorts: true,
				},
			}, http.StatusOK, "023-expand-focus-shippingservice-layer-expand-ports", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Foobar layer with non-existent nodes",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Layers: []v1.Layer{{
						Name: "infrastructure-tigera",
						Nodes: []v1.GraphNodeID{
							"namespace/foobarbaz",
							"svc/foo/bar",
						},
					}},
				},
				// Should be same results as if no request params.
			}, http.StatusOK, "001-no-req-parms", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
		Entry("Expanded hosts",
			v1.ServiceGraphRequest{
				SelectedView: v1.GraphView{
					Focus:    []v1.GraphNodeID{"hosts/*"},
					Expanded: []v1.GraphNodeID{"hosts/*"},
				},
				// Should be same results as if no request params.
			}, http.StatusOK, "024-expanded-hosts", RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil),
		),
	)

	DescribeTable("badly formatted requests",
		func(sgr string, code int, resp string) {
			// Create a mock backend.
			mb := CreateMockBackendWithData(RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil))

			// Create a service graph.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sg := NewServiceGraphHandlerWithBackend(fakeClient, mb, &Config{
				ServiceGraphCacheMaxEntries:        1,
				ServiceGraphCachePolledEntryAgeOut: 5 * time.Minute,
				ServiceGraphCachePollLoopInterval:  5 * time.Minute,
				ServiceGraphCachePollQueryInterval: 5 * time.Minute,
				ServiceGraphCacheDataSettleTime:    5 * time.Minute,
				ServiceGraphCacheFetchL7:           true,
				ServiceGraphCacheFetchDNS:          true,
				ServiceGraphCacheFetchEvents:       true,
			})

			// Marshal the request and create an HTTP request
			body := io.NopCloser(strings.NewReader(sgr))
			req, err := http.NewRequest("POST", "/serviceGraph", body)
			Expect(err).NotTo(HaveOccurred())
			req = req.WithContext(ctx)

			// Pass it through the handler
			writer := httptest.NewRecorder()
			sg.ServeHTTP(writer, req)
			Expect(writer.Code).To(Equal(code))
			Expect(strings.TrimSpace(writer.Body.String())).To(Equal(resp), writer.Body.String())
		},
		Entry("bad focus node ID",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
				"selected_view": {
					"focus": ["foobar/baz"]
				}
			}`, http.StatusBadRequest, "Request body contains an invalid focus node: unexpected format of node ID foobar/baz",
		),
		Entry("bad expanded node ID",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
				"selected_view": {
					"expanded": ["namespace/abc/def"]
				}
			}`, http.StatusBadRequest, "Request body contains an invalid expanded node: unexpected format of node ID namespace/abc/def",
		),
		Entry("bad followed_ingress node ID",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
				"selected_view": {
					"followed_ingress": ["hosts/%Rlsdf!"]
				}
			}`, http.StatusBadRequest, "Request body contains an invalid followed_ingress node: unexpected format of node ID hosts/%Rlsdf!: badly formatted segment",
		),
		Entry("bad followed_egress node ID",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
				"selected_view": {
					"followed_egress": ["port/tcp/thing;hosts/*"]
				}
			}`, http.StatusBadRequest, "Request body contains an invalid followed_egress node: unexpected format of node ID port/tcp/thing;hosts/*: port is not a number",
		),
		Entry("bad layer node ID",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
				"selected_view": {
					"layers": [{
						"name": "test",
						"nodes": ["svc"]
					}]
				}
			}`, http.StatusBadRequest, "Request body contains an invalid layer node: unexpected format of node ID svc",
		),
		Entry("bad layer name",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
				"selected_view": {
					"layers": [{
						"name": "test@",
						"nodes": ["namespace/n"]
					}]
				}
			}`, http.StatusBadRequest, "Request body contains an invalid layer name: test@",
		),
		Entry("duplicate layer name",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
				"selected_view": {
					"layers": [{
						"name": "test",
						"nodes": ["namespace/n"]
					}, {
						"name": "test",
						"nodes": ["namespace/n2"]
					}]
				}
			}`, http.StatusBadRequest, "Request body contains a duplicate layer name: test",
		),
		Entry("bad aggregated hosts name",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
				"selected_view": {
					"host_aggregation_selectors": [{
						"name": "test@",
						"selector": "all()"
					}]
				}
			}`, http.StatusBadRequest, "Request body contains an invalid aggregated host name: test@",
		),
		Entry("duplicate aggregated host names",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
				"selected_view": {
					"host_aggregation_selectors": [{
						"name": "test",
						"selectors": "all()"
					}, {
						"name": "test",
						"selector": "all()"
					}]
				}
			}`, http.StatusBadRequest, "Request body contains a duplicate aggregated host name: test",
		),
		Entry("invalid host aggregation selector",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
				"selected_view": {
					"host_aggregation_selectors": [{
						"name": "test",
						"selector": "foobar()"
					}]
				}
			}`, http.StatusBadRequest, "Request body contains an invalid selector: foobar()",
		),
		Entry("invalid json syntax",
			`{
				"time_range": {
					"from": "now-15m",
					"to": "now"
				},
			}`, http.StatusBadRequest, "Request body contains badly-formed JSON (at position 74)",
		),
		Entry("reversed relative time range",
			`{
				"time_range": {
					"from": "now",
					"to": "now-15m"
				}
			}`, http.StatusBadRequest, "Request body contains an invalid time range: from (now) is after to (now-15m)",
		),
		Entry("missing time range",
			`{
			}`, http.StatusBadRequest, "Request body contains invalid data: error with field TimeRange = '<nil>' (Reason: failed to validate Field: TimeRange because of Tag: required )",
		),
		Entry("reversed absolute time range",
			`{
				"time_range": {
					"from": "2021-05-30T21:38:10Z",
					"to": "2021-05-30T21:23:10Z"
				}
			}`, http.StatusBadRequest, "Request body contains an invalid time range: from (2021-05-30T21:38:10Z) is after to (2021-05-30T21:23:10Z)",
		),
		Entry("mix relative time range",
			`{
				"time_range": {
					"from": "now",
					"to": "2021-05-30T21:38:10Z"
				}
			}`, http.StatusBadRequest, "Request body contains an invalid time range: values must either both be explicit times or both be relative to now",
		),
		Entry("bad time range from value",
			`{
				"time_range": {
					"from": "nox",
					"to": "2021-05-30T21:38:10Z"
				}
			}`, http.StatusBadRequest, "Request body contains an invalid value for the time range 'from' field: nox",
		),
	)
})
