// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//

package query

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/olivere/elastic/v7"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

const (
	alertName = "sample-test"
)

var _ = Describe("Service Test", func() {
	var (
		httpServer *httptest.Server
		lsc        client.MockClient
		ctx        context.Context
		cancel     context.CancelFunc
	)

	BeforeEach(func() {
		// for vulnerability dataset
		f := mustOpen("test_files/10_vulnerability_events_from_image_assurance_api.json")
		defer func() { _ = f.Close() }()
		events, err := io.ReadAll(f)
		Expect(err).NotTo(HaveOccurred())
		httpServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, string(events))
		}))
		Expect(httpServer).NotTo(BeNil())

		_ = os.Setenv("IMAGE_ASSURANCE_ENDPOINT", httpServer.URL)
		_ = os.Setenv("IMAGE_ASSURANCE_ORGANIZATION_ID", "image-assurance-org-id")
		_ = os.Setenv("IMAGE_ASSURANCE_API_TOKEN", "token")

		ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	})

	AfterEach(func() {
		_ = os.Unsetenv("IMAGE_ASSURANCE_ENDPOINT")
		_ = os.Unsetenv("IMAGE_ASSURANCE_ORGANIZATION_ID")
		cancel()
	})

	Context("alert with count as metric and without any aggregations", func() {
		It("1 - with count and no aggregation", func() {
			// Uses file with prefix 1_with_count_and_no_aggregation_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "flows",
					Metric:      "count",
					Threshold:   100,
					Condition:   "gt",
					Query:       "action=allow",
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to count how many flow logs are
				// selected using the query "action=allow"
				// We return a total count of 645 logs
				{
					Body: &lsv1.List[lsv1.FlowLog]{
						// This needs to be gt than 100
						TotalHits: 645,
					},
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract count metric
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.FlowLogParams{
				{
					QueryParams: lsv1.QueryParams{
						TimeRange: &lmav1.TimeRange{
							From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
							To:   time.Unix(0, 0).UTC(),
						},
						MaxPageSize: 0,
					},
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "action=allow",
					},
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/1_with_count_and_no_aggregation_events_doc.json"))
		})
	})

	Context("with min/max/avg/sum as metric and without aggregateBy", func() {
		It("2 - with max and no aggregate by", func() {
			// Uses file with prefix 2_with_max_and_no_aggregateby_* for testing this scenario
			a := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "dns",
					Metric:      "max",
					Threshold:   100,
					Condition:   "gt",
					Query:       "qtype=AAAA",
					Field:       "count",
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to count the maximum of dns logs are
				// selected using the query "qtype=AAAA"
				// We return a total value of 66057.0
				{
					Body: expectedAggregations("test_files/2_with_max_and_no_aggregateby_response.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", a)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, a)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract max of count field
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.DNSAggregationParams{
				{
					DNSLogParams: lsv1.DNSLogParams{
						QueryParams: lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
								To:   time.Unix(0, 0).UTC(),
							},
							MaxPageSize: 0,
						},
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: "qtype=AAAA",
						},
					},
					Aggregations: expectedAggregationParams("test_files/2_with_max_and_no_aggregateby_query.json"),
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/2_with_max_and_no_aggregateby_events_doc.json"))
		})
	})

	Context("with count as metric and with aggregateBy", func() {
		It("3 - with count and aggregate by", func() {
			// Uses file with prefix 3_with_count_and_aggregateby_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: "test alert summary ${source_namespace} ${count}",
					Severity:    100,
					DataSet:     "flows",
					Metric:      "count",
					AggregateBy: []string{"source_namespace"},
					Threshold:   100,
					Condition:   "gte",
					Query:       "action=allow",
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to count flow logs aggregated by source_namespace
				// selected using the query "action=allow"
				{
					Body: expectedAggregations("test_files/3_with_count_and_aggregateby_response.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
				{
					Body: expectedAggregations("test_files/3_with_count_and_aggregateby_response_after_key.json"),
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(3))
			// Verify requests made to extract max of count field
			verifyQueries([]rest.MockRequest{*requests[0], *requests[2]}, lookBack, []*lsv1.FlowLogAggregationParams{
				{
					FlowLogParams: lsv1.FlowLogParams{
						QueryParams: lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
								To:   time.Unix(0, 0).UTC(),
							},
							MaxPageSize: 0,
						},
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: "action=allow",
						},
					},
					Aggregations: expectedAggregationParams("test_files/3_with_count_and_aggregateby_query.json"),
				},
				{
					FlowLogParams: lsv1.FlowLogParams{
						QueryParams: lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
								To:   time.Unix(0, 0).UTC(),
							},
							MaxPageSize: 0,
						},
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: "action=allow",
						},
					},
					Aggregations: expectedAggregationParams("test_files/3_with_count_and_aggregateby_query_after_key.json"),
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/3_with_count_and_aggregateby_events_doc.json"))
		})

		It("3_1 - with count and aggregate by ", func() {
			// Uses file with prefix 3_1_with_count_and_aggregateby_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "flows",
					Metric:      "count",
					AggregateBy: []string{"source_namespace", "source_name_aggr"},
					Threshold:   100,
					Condition:   "not_eq",
					Query:       "action=allow",
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to count the flow logs are
				// selected using the query "action=allow"
				// aggregating by source_namespace and source_name_aggr
				{
					Body: expectedAggregations("test_files/3_1_with_count_and_aggregateby_response.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract the count field from aggregations
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.FlowLogAggregationParams{
				{
					FlowLogParams: lsv1.FlowLogParams{
						QueryParams: lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
								To:   time.Unix(0, 0).UTC(),
							},
							MaxPageSize: 0,
						},
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: "action=allow",
						},
					},
					Aggregations: expectedAggregationParams("test_files/3_1_with_count_and_aggregateby_query.json"),
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/3_1_with_count_and_aggregateby_events_doc.json"))
		})
	})

	Context("with min/max/avg/sum as metric and with aggregateBy", func() {
		It("4 - with max and aggregate by", func() {
			// Uses file with prefix 4_with_max_and_aggregateby_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: "test alert description ${source_namespace}/${source_name_aggr} ${max}",
					Severity:    100,
					DataSet:     "flows",
					Metric:      "max",
					Field:       "num_flows",
					AggregateBy: []string{"source_namespace", "source_name_aggr"},
					Threshold:   100,
					Condition:   "gt",
					Query:       "action=allow",
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to max value for flow logs are
				// selected using the query "action=allow"
				// aggregating by source_namespace and source_name_aggr
				{
					Body: expectedAggregations("test_files/4_with_max_and_aggregateby_response.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract the count field from aggregations
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.FlowLogAggregationParams{
				{
					FlowLogParams: lsv1.FlowLogParams{
						QueryParams: lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
								To:   time.Unix(0, 0).UTC(),
							},
							MaxPageSize: 0,
						},
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: "action=allow",
						},
					},
					Aggregations: expectedAggregationParams("test_files/4_with_max_and_aggregateby_query.json"),
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/4_with_max_and_aggregateby_events_doc.json"))
		})
	})

	Context("without metric and without aggregateBy", func() {
		It("5 - with no metric and no aggregation", func() {
			// Uses file with prefix 5_with_no_metric_and_no_aggregation* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "flows",
					Threshold:   100,
					Query:       "action=allow",
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to count flow logs are
				// selected using the query "action=allow" - first page
				{
					Body: expectedFlowLogs("test_files/5_with_no_metric_and_no_aggregation_response.json"),
				},
				// This is the response to count flow logs are
				// selected using the query "action=allow" - last page
				{
					Body: expectedFlowLogs("test_files/5_with_no_metric_and_no_aggregation_response_part2.json"),
				},

				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},

				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(4))
			// Verify requests made to extract count metric
			verifyQueries([]rest.MockRequest{*requests[0], *requests[1]}, lookBack, []*lsv1.FlowLogParams{
				{
					QueryParams: lsv1.QueryParams{
						TimeRange: &lmav1.TimeRange{
							From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
							To:   time.Unix(0, 0).UTC(),
						},
						MaxPageSize: 10000,
						// TODO: ALINA - Need to check why this shows up in the mock client
						AfterKey: map[string]any{"startFrom": "10001"},
					},
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "action=allow",
					},
				},
				{
					QueryParams: lsv1.QueryParams{
						TimeRange: &lmav1.TimeRange{
							From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
							To:   time.Unix(0, 0).UTC(),
						},
						MaxPageSize: 10000,
						AfterKey:    map[string]any{"startFrom": "10001"},
					},
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "action=allow",
					},
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[2], *requests[3]}, expectedEvents("test_files/5_with_no_metric_and_no_aggregation_events_doc.json"))
		})
	})

	Context("without metric and with aggregateBy", func() {
		It("6 without metric and with aggregateby", func() {
			// Uses file with prefix 6_without_metric_and_with_aggregateby_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "flows",
					Query:       "action=allow",
					AggregateBy: []string{"source_name_aggr"},
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to for flow logs are
				// selected using the query "action=allow"
				// aggregating by source_name_aggr
				{
					Body: expectedAggregations("test_files/6_without_metric_and_with_aggregateby_response.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract the count field from aggregations
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.FlowLogAggregationParams{
				{
					FlowLogParams: lsv1.FlowLogParams{
						QueryParams: lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
								To:   time.Unix(0, 0).UTC(),
							},
							MaxPageSize: 0,
						},
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: "action=allow",
						},
					},
					Aggregations: expectedAggregationParams("test_files/6_without_metric_and_with_aggregateby_query.json"),
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/6_without_metric_and_with_aggregateby_events_doc.json"))
		})
	})

	Context("query with set", func() {
		It("7 - with in and count and no aggregation", func() {
			// Uses file with prefix 7_with_in_and_count_and_no_aggregation_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "flows",
					Metric:      "count",
					Threshold:   3,
					Condition:   "gt",
					Query:       `process_name IN {"*voltron", "?service-proxy"}`,
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to count how many flow logs are
				// selected using the query "process_name IN {"*voltron", "?service-proxy"}"
				// We return a total count of 3 logs
				{
					Body: &lsv1.List[lsv1.FlowLog]{
						// This needs to be gt than 3
						TotalHits: 9,
					},
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract count metric
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.FlowLogParams{
				{
					QueryParams: lsv1.QueryParams{
						TimeRange: &lmav1.TimeRange{
							From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
							To:   time.Unix(0, 0).UTC(),
						},
						MaxPageSize: 0,
					},
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "process_name IN {\"*voltron\", \"?service-proxy\"}",
					},
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/7_with_in_and_count_and_no_aggregation_events_doc.json"))
		})
		It("7 - with notin and count and no aggregation", func() {
			// Uses file with prefix 7_with_notin_and_count_and_no_aggregation_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "flows",
					Metric:      "count",
					Threshold:   3,
					Condition:   "gt",
					Query:       `process_name NOTIN {"*voltron", "?service-proxy"}`,
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to count how many flow logs are
				// selected using the query "process_name NOTIN {"*voltron", "?service-proxy"}"
				// We return a total count of 3 logs
				{
					Body: &lsv1.List[lsv1.FlowLog]{
						// This needs to be gt than 3
						TotalHits: 5,
					},
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract count metric
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.FlowLogParams{
				{
					QueryParams: lsv1.QueryParams{
						TimeRange: &lmav1.TimeRange{
							From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
							To:   time.Unix(0, 0).UTC(),
						},
						MaxPageSize: 0,
					},
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "process_name NOTIN {\"*voltron\", \"?service-proxy\"}",
					},
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/7_with_notin_and_count_and_no_aggregation_events_doc.json"))
		})
		It("8 - with in and count and aggregate by", func() {
			// Uses file with prefix 8_with_in_and_count_and_aggregateby_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "flows",
					Metric:      "count",
					Condition:   "gt",
					Threshold:   3,
					Query:       `process_name IN {"*voltron", "?service-proxy"}`,
					AggregateBy: []string{"source_namespace", "source_name_aggr"},
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to count the flow logs are
				// selected using the query "process_name IN {"*voltron", "?service-proxy"}"
				// aggregating by source_namespace and source_name_aggr
				// aggregations contain after_key
				{
					Body: expectedAggregations("test_files/8_with_in_and_count_and_aggregateby_response.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     2,
						Succeeded: 2,
					},
				},
				// This is the response to count the flow logs are
				// selected using the query "process_name IN {"*voltron", "?service-proxy"}"
				// aggregating by source_namespace and source_name_aggr
				// without an after_key
				{
					Body: expectedAggregations("test_files/8_with_in_and_count_and_aggregateby_response_after_key.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(4))
			// Verify requests made to extract the count field from aggregations
			verifyQueries([]rest.MockRequest{*requests[0], *requests[2]}, lookBack, []*lsv1.FlowLogAggregationParams{
				{
					FlowLogParams: lsv1.FlowLogParams{
						QueryParams: lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
								To:   time.Unix(0, 0).UTC(),
							},
							MaxPageSize: 0,
						},
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: "process_name IN {\"*voltron\", \"?service-proxy\"}",
						},
					},
					Aggregations: expectedAggregationParams("test_files/8_with_in_and_count_and_aggregateby_query.json"),
				},
				{
					FlowLogParams: lsv1.FlowLogParams{
						QueryParams: lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
								To:   time.Unix(0, 0).UTC(),
							},
							MaxPageSize: 0,
						},
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: "process_name IN {\"*voltron\", \"?service-proxy\"}",
						},
					},
					Aggregations: expectedAggregationParams("test_files/8_with_in_and_count_and_aggregateby_query_after_key.json"),
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1], *requests[3]}, expectedEvents("test_files/8_with_in_and_count_and_aggregateby_events_doc.json"))
		})

		It("8 - with notin and count and aggregateby", func() {
			// Uses file with prefix 8_with_notin_and_count_and_aggregateby_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "flows",
					Metric:      "count",
					Condition:   "gt",
					Threshold:   3,
					Query:       `process_name NOTIN {"*voltron", "?service-proxy"}`,
					AggregateBy: []string{"source_namespace", "source_name_aggr"},
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to count the flow logs are
				// selected using the query "process_name NOTIN {"*voltron", "?service-proxy"}"
				// aggregating by source_namespace and source_name_aggr
				// aggregations contain after_key
				{
					Body: expectedAggregations("test_files/8_with_notin_and_count_and_aggregateby_response.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract the count field from aggregations
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.FlowLogAggregationParams{
				{
					FlowLogParams: lsv1.FlowLogParams{
						QueryParams: lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
								To:   time.Unix(0, 0).UTC(),
							},
							MaxPageSize: 0,
						},
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: "process_name NOTIN {\"*voltron\", \"?service-proxy\"}",
						},
					},
					Aggregations: expectedAggregationParams("test_files/8_with_notin_and_count_and_aggregateby_query.json"),
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/8_with_notin_and_count_and_aggregateby_events_doc.json"))
		})

		It("9 - with in without metric and no aggregation", func() {
			// Uses file with prefix 9_with_in_without_metric_and_no_aggregation_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "flows",
					Query:       `process_name IN {"*voltron", "?service-proxy"}`,
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to return the flow logs are
				// selected using the query "process_name NOTIN {"*voltron", "?service-proxy"}"
				{
					Body: expectedFlowLogs("test_files/9_with_in_without_metric_and_no_aggregation_response.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     2,
						Succeeded: 2,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract count metric
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.FlowLogParams{
				{
					QueryParams: lsv1.QueryParams{
						TimeRange: &lmav1.TimeRange{
							From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
							To:   time.Unix(0, 0).UTC(),
						},
						MaxPageSize: 10000,
					},
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "process_name IN {\"*voltron\", \"?service-proxy\"}",
					},
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/9_with_in_without_metric_and_no_aggregation_events_doc.json"))
		})
		It("9 - with notin without metric and no aggregation", func() {
			// Uses file with prefix 9_with_notin_without_metric_and_no_aggregation_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "flows",
					Query:       `process_name NOTIN {"*voltron", "?service-proxy"}`,
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to return the flow logs are
				// selected using the query "process_name NOTIN {"*voltron", "?service-proxy"}"
				{
					Body: expectedFlowLogs("test_files/9_with_notin_without_metric_and_no_aggregation_response.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     2,
						Succeeded: 2,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract count metric
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.FlowLogParams{
				{
					QueryParams: lsv1.QueryParams{
						TimeRange: &lmav1.TimeRange{
							From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
							To:   time.Unix(0, 0).UTC(),
						},
						MaxPageSize: 10000,
					},
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "process_name NOTIN {\"*voltron\", \"?service-proxy\"}",
					},
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/9_with_notin_without_metric_and_no_aggregation_events_doc.json"))
		})
		It("12 - with substitution and aggregation", func() {
			// Uses file with prefix 12_with_substitution_and_aggregation_* for testing this scenario
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "dns",
					Query:       "qname NOTIN ${domains} AND client_namespace IN ${namespaces}",
					AggregateBy: []string{"client_namespace", "client_name_aggr", "qname"},
					Substitutions: []v3.GlobalAlertSubstitution{
						{
							Name:   "domains",
							Values: []string{"*cluster.local", "ec2.internal", ".in-addr.arpa", "localhost"},
						},
						{
							Name:   "namespaces",
							Values: []string{"java-app"},
						},
					},
				},
			}

			lsc = client.NewMockClient("", []rest.MockResult{
				// This is the response to the query for dns logs
				{
					Body: expectedAggregations("test_files/12_with_substitution_and_aggregation_response.json"),
				},
				// This is the response when writing events
				{
					Body: lsv1.BulkResponse{
						Total:     1,
						Succeeded: 1,
					},
				},
			}...)

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify requests that have been made
			lookBack := time.Duration(10)
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(2))
			// Verify requests made to extract the count field from aggregations
			verifyQueries([]rest.MockRequest{*requests[0]}, lookBack, []*lsv1.DNSAggregationParams{
				{
					DNSLogParams: lsv1.DNSLogParams{
						QueryParams: lsv1.QueryParams{
							TimeRange: &lmav1.TimeRange{
								From: time.Unix(0, 0).UTC().Add(-1 * lookBack),
								To:   time.Unix(0, 0).UTC(),
							},
							MaxPageSize: 0,
						},
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: `qname NOTIN {"*cluster.local","ec2.internal",".in-addr.arpa","localhost"} AND client_namespace IN {"java-app"}`,
						},
					},
					Aggregations: expectedAggregationParams("test_files/12_with_substitution_and_aggregation_query.json"),
				},
			})
			// Verify requests to write events
			verifyEventWrites([]rest.MockRequest{*requests[1]}, expectedEvents("test_files/12_with_substitution_and_aggregation_events_doc.json"))
		})
	})

	Context("vulnerability dataset", func() {
		It("should query image assurance api", func() {
			// uses file 10_vulnerability_events_doc.json
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "vulnerability",
					Query:       `registry="quay.io" AND repository=node`,
				},
			}

			// Mock linseed response for writing events
			lsc = client.NewMockClient("", rest.MockResult{
				Body: lsv1.BulkResponse{
					Total:     2,
					Succeeded: 2,
				},
			})

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Validate the test setup
			Expect(e.httpClient).NotTo(BeNil())

			Expect(len(e.vulnerabilityQuery)).To(Equal(2))
			val, ok := e.vulnerabilityQuery["registry"]
			Expect(ok).To(BeTrue())
			Expect(val).To(Equal("quay.io"))
			val, ok = e.vulnerabilityQuery["repository"]
			Expect(ok).To(BeTrue())
			Expect(val).To(Equal("node"))

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify the events written via Linseed
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(1))
			verifyEventWrites([]rest.MockRequest{*requests[0]}, expectedEvents("test_files/10_vulnerability_events_doc.json"))
		})

		It("should query image assurance api with metric count", func() {
			// uses file 10_vulnerability_events_metric_count_events_doc.json
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "vulnerability",
					Query:       `registry="quay.io" AND repository=node`,
					Metric:      "count",
					Condition:   "gt",
					Threshold:   1.0,
				},
			}

			// Mock linseed response for writing events
			lsc = client.NewMockClient("", rest.MockResult{
				Body: lsv1.BulkResponse{
					Total:     1,
					Succeeded: 1,
				},
			})

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify the events written via Linseed
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(1))
			verifyEventWrites([]rest.MockRequest{*requests[0]}, expectedEvents("test_files/10_vulnerability_events_metric_count_events_doc.json"))
		})

		It("should query image assurance api with metric max", func() {
			// uses file 10_vulnerability_events_metric_max_events_doc.json
			ga := &v3.GlobalAlert{
				ObjectMeta: v1.ObjectMeta{
					Name: alertName,
				},
				Spec: v3.GlobalAlertSpec{
					Description: fmt.Sprintf("test alert: %s", alertName),
					Severity:    100,
					DataSet:     "vulnerability",
					Query:       `registry="quay.io" AND repository=node`,
					Metric:      "max",
					Condition:   "gt",
					Field:       "max_cvss_score",
					Threshold:   6.6,
				},
			}

			// Mock linseed response for writing events
			lsc = client.NewMockClient("", rest.MockResult{
				Body: lsv1.BulkResponse{
					Total:     1,
					Succeeded: 1,
				},
			})

			e, err := getTestService(lsc, httpServer, "test-cluster", ga)
			Expect(err).ShouldNot(HaveOccurred())

			// Execute the alert
			status := e.ExecuteAlert(ctx, ga)

			// Verify alert status
			Expect(status.Healthy).To(BeTrue())
			Expect(len(status.ErrorConditions)).To(BeZero())

			// Verify the events written via Linseed
			requests := lsc.Requests()
			Expect(len(requests)).To(Equal(1))
			verifyEventWrites([]rest.MockRequest{*requests[0]}, expectedEvents("test_files/10_vulnerability_events_metric_max_events_doc.json"))
		})
	})

	Context("on error", func() {
		It("should store only recent errors", func() {
			var errs []v3.ErrorCondition
			for i := range 12 {
				errs = appendError(errs, v3.ErrorCondition{Message: fmt.Sprintf("Error %v", i)})
			}
			Expect(len(errs)).Should(Equal(10))
			Expect(errs[MaxErrorsSize-1].Message).Should(Equal("Error 11"))
			Expect(errs[0].Message).Should(Equal("Error 2"))
		})
	})
})

func verifyEventWrites(requests []rest.MockRequest, expectedEvents []lsv1.Event) {
	var actualEvents []lsv1.Event
	var actualRecords []any
	for _, request := range requests {
		Expect(request.Result.Called).To(BeTrue())
		rawBody := request.GetBody().([]byte)
		d := json.NewDecoder(bytes.NewReader(rawBody))
		for {
			var event lsv1.Event
			err := d.Decode(&event)
			if err == io.EOF {
				break
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(event.Time).NotTo(BeZero())
			// Extract record in order to compare it separately
			actualRecords = append(actualRecords, event.Record)
			event.Record = nil
			// Alter time in order to allow a match using the assertion framework
			event.Time = lsv1.NewEventTimestamp(time.Unix(0, 0).UTC().Unix())
			actualEvents = append(actualEvents, event)
		}
	}

	// Extract records from expected events
	var expectedRecords []any
	for idx, event := range expectedEvents {
		expectedRecords = append(expectedRecords, event.Record)
		event.Record = nil
		expectedEvents[idx] = event
	}

	// Compare events without records
	Expect(actualEvents).To(BeEquivalentTo(expectedEvents))
	Expect(len(actualEvents)).To(Equal(len(expectedEvents)))

	// Compare records
	Expect(actualRecords).To(BeEquivalentTo(expectedRecords))
}

func verifyQueries[T any](requests []rest.MockRequest, lookBack time.Duration, expected []T) {
	var actual []T
	for _, request := range requests {
		Expect(request.Result.Called).To(BeTrue())
		actual = append(actual, modifyTime(request.GetParams(), lookBack).(T))
	}
	Expect(actual).To(ConsistOf(expected))
	Expect(len(actual)).To(Equal(len(expected)))
}

func modifyTime(params any, lookBack time.Duration) any {
	switch p := params.(type) {
	case *lsv1.FlowLogParams:
		p.TimeRange.From = time.Unix(0, 0).UTC().Add(-1 * lookBack)
		p.TimeRange.To = time.Unix(0, 0).UTC()
		return p
	case *lsv1.WAFLogParams:
		p.TimeRange.From = time.Unix(0, 0).UTC().Add(-1 * lookBack)
		p.TimeRange.To = time.Unix(0, 0).UTC()
		return p
	case *lsv1.DNSAggregationParams:
		p.TimeRange.From = time.Unix(0, 0).UTC().Add(-1 * lookBack)
		p.TimeRange.To = time.Unix(0, 0).UTC()
		return p
	case *lsv1.FlowLogAggregationParams:
		p.TimeRange.From = time.Unix(0, 0).UTC().Add(-1 * lookBack)
		p.TimeRange.To = time.Unix(0, 0).UTC()
		return p
	}

	return params
}

func getTestService(linseedClient client.Client, httpServer *httptest.Server, clusterName string, alert *v3.GlobalAlert) (*service, error) {
	e := &service{
		clusterName:   clusterName,
		linseedClient: linseedClient,
	}

	var err error
	if alert.Spec.DataSet == v3.GlobalAlertDataSetVulnerability {
		e.httpClient = httpServer.Client()
		err = e.buildVulnerabilityQuery(alert)
	} else {
		e.queryBuilder, err = e.buildQueryConfiguration(alert)
		if err != nil {
			return nil, err
		}
		e.queryExecutor, err = newGenericExecutor(linseedClient, clusterName, alert)
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	}

	return e, err
}

func mustOpen(name string) io.ReadCloser {
	f, err := os.Open(name)
	if err != nil {
		panic(err)
	}
	return f
}

func expectedEvents(name string) []lsv1.Event {
	f, err := os.Open(name)
	Expect(err).ShouldNot(HaveOccurred())
	b, err := io.ReadAll(f)
	Expect(err).ShouldNot(HaveOccurred())
	err = f.Close()
	Expect(err).ShouldNot(HaveOccurred())

	var events []lsv1.Event
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	for {
		var event lsv1.Event
		err := decoder.Decode(&event)
		if err == io.EOF {
			// all done
			break
		}
		Expect(err).ShouldNot(HaveOccurred())
		event.Time = lsv1.NewEventTimestamp(time.Unix(0, 0).Unix())
		events = append(events, event)
	}
	return events
}

func expectedAggregations(name string) elastic.Aggregations {
	f, err := os.Open(name)
	Expect(err).ShouldNot(HaveOccurred())
	b, err := io.ReadAll(f)
	Expect(err).ShouldNot(HaveOccurred())
	err = f.Close()
	Expect(err).ShouldNot(HaveOccurred())

	dst := &bytes.Buffer{}
	if err := json.Compact(dst, b); err != nil {
		Expect(err).ShouldNot(HaveOccurred())
	}

	var aggregations elastic.Aggregations
	err = json.Unmarshal(dst.Bytes(), &aggregations)
	Expect(err).NotTo(HaveOccurred())

	return aggregations
}

func expectedAggregationParams(name string) map[string]json.RawMessage {
	f, err := os.Open(name)
	Expect(err).ShouldNot(HaveOccurred())
	b, err := io.ReadAll(f)
	Expect(err).ShouldNot(HaveOccurred())
	err = f.Close()
	Expect(err).ShouldNot(HaveOccurred())

	dst := &bytes.Buffer{}
	if err := json.Compact(dst, b); err != nil {
		Expect(err).ShouldNot(HaveOccurred())
	}

	var params map[string]json.RawMessage
	err = json.Unmarshal(dst.Bytes(), &params)
	Expect(err).ShouldNot(HaveOccurred())

	return params
}

func expectedFlowLogs(name string) *lsv1.List[lsv1.FlowLog] {
	f, err := os.Open(name)
	Expect(err).ShouldNot(HaveOccurred())
	b, err := io.ReadAll(f)
	Expect(err).ShouldNot(HaveOccurred())
	err = f.Close()
	Expect(err).ShouldNot(HaveOccurred())

	dst := &bytes.Buffer{}
	if err := json.Compact(dst, b); err != nil {
		Expect(err).ShouldNot(HaveOccurred())
	}

	var params lsv1.List[lsv1.FlowLog]
	err = json.Unmarshal(dst.Bytes(), &params)
	Expect(err).ShouldNot(HaveOccurred())

	return &params
}
