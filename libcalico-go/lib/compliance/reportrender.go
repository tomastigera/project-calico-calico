// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

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

package compliance

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/apis/audit"
	"sigs.k8s.io/yaml"
)

var (
	// Exposed to be used by UT code.
	EndpointIdSample1 = api.ResourceID{
		TypeMeta: metav1.TypeMeta{
			Kind:       "HostEndpoint",
			APIVersion: "projectcalico.org/v3",
		},
		Name: "hep1",
	}
	EndpointIdSample2 = api.ResourceID{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		Name:      "pod-abcdef",
		Namespace: "ns1",
	}
	PolicyIdSample1 = api.ResourceID{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "projectcalico.org/v3",
		},
		Name:      "np1",
		Namespace: "ns1",
	}
	PolicyIdSample2 = api.ResourceID{
		TypeMeta: metav1.TypeMeta{
			Kind:       "GlobalNetworkPolicy",
			APIVersion: "projectcalico.org/v3",
		},
		Name: "gnp1",
	}
	ServiceIdSample1 = api.ResourceID{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		Name:      "svc1",
		Namespace: "n21",
	}
	ServiceIdSample2 = api.ResourceID{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		Name:      "svc2",
		Namespace: "n22",
	}
	EndpointSample1 = api.EndpointsReportEndpoint{
		Endpoint:         EndpointIdSample1,
		IngressProtected: false,
		EgressProtected:  true,
		EnvoyEnabled:     false,
		AppliedPolicies:  []api.ResourceID{PolicyIdSample2},
	}
	EndpointSample2 = api.EndpointsReportEndpoint{
		Endpoint:               EndpointIdSample2,
		FlowLogAggregationName: "pod-*",
		IngressProtected:       false,
		EgressProtected:        true,
		EnvoyEnabled:           false,
		AppliedPolicies:        []api.ResourceID{PolicyIdSample1, PolicyIdSample2},
		Services:               []api.ResourceID{ServiceIdSample1, ServiceIdSample2},
	}
	FlowSample1 = api.EndpointsReportFlow{
		Source: api.FlowEndpoint{
			Kind:                    "Pod",
			Name:                    "pod-*",
			Namespace:               "ns1",
			NameIsAggregationPrefix: true,
		},
		Destination: api.FlowEndpoint{
			Kind:                    "Pod",
			Name:                    "pod-*",
			Namespace:               "ns2",
			NameIsAggregationPrefix: true,
		},
	}
	FlowSample2 = api.EndpointsReportFlow{
		Source: api.FlowEndpoint{
			Kind:                    "Pod",
			Name:                    "pod-abc-*",
			Namespace:               "ns2",
			NameIsAggregationPrefix: true,
		},
		Destination: api.FlowEndpoint{
			Kind:                    "HostEndpoint",
			Name:                    "hep1",
			NameIsAggregationPrefix: false,
		},
	}
	FlowSample3 = api.EndpointsReportFlow{
		Source: api.FlowEndpoint{
			Kind:                    "Pod",
			Name:                    "pod-*",
			Namespace:               "ns1",
			NameIsAggregationPrefix: true,
		},
		Destination: api.FlowEndpoint{
			Kind:                    "Pod",
			Name:                    "pod-*",
			Namespace:               "ns3",
			NameIsAggregationPrefix: true,
		},
	}
	AuditEventSample = audit.Event{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Event",
			APIVersion: "audit.k8s.io/v1beta1",
		},
		Level:      "Metadata",
		AuditID:    "1-2-3-4-5",
		Stage:      "RequestReceived",
		RequestURI: "/api/v1/foo/bar",
		Verb:       "list",
		User: authnv1.UserInfo{
			Username: "userFoo",
			Groups:   []string{"groupFoo"},
		},
		ImpersonatedUser: &authnv1.UserInfo{
			Username: "imporUserFoo",
			Groups:   []string{"imperGroupFoo"},
		},
		SourceIPs: []string{"192.168.1.2"},
		ObjectRef: &audit.ObjectReference{
			Name:       "oRef",
			Namespace:  "default",
			Resource:   "fooBarResource",
			APIVersion: "v1",
		},
		ResponseStatus: &metav1.Status{
			Status: "k8s-audit-report-resp-status",
		},
		RequestObject: &runtime.Unknown{
			/*
				TypeMeta: runtime.TypeMeta{
					Kind:       "Request",
					APIVersion: "request/v1",
				},
			*/
			Raw:         []byte(`{"reqFoo": "reqBar"}`),
			ContentType: "application/json",
		},
		ResponseObject: &runtime.Unknown{
			/*
				TypeMeta: runtime.TypeMeta{
					Kind:       "Response",
					APIVersion: "response/v1",
				},
			*/
			Raw:         []byte(`{"respFoo": "respBar"}`),
			ContentType: "application/json",
		},
		RequestReceivedTimestamp: metav1.UnixMicro(1554076800, 0),
		StageTimestamp:           metav1.UnixMicro(1554112800, 0),
		Annotations:              map[string]string{"foo": "bar"},
	}

	// ReportDataSample is used by ReportTemplate validator.
	five             = 5
	ReportDataSample = api.ReportData{
		StartTime: metav1.Unix(1554076800, 0),
		EndTime:   metav1.Unix(1554112800, 0),
		ReportSpec: api.ReportSpec{
			Endpoints: &api.EndpointsSelection{
				Selector: "lbl == 'lbl-val'",
				Namespaces: &api.NamesAndLabelsMatch{
					Selector: "endpoint-namespace-selector",
				},
				ServiceAccounts: &api.NamesAndLabelsMatch{
					Selector: "serviceaccount-selector",
				},
			},
			CIS: &api.CISBenchmarkParams{NumFailedTests: &five},
		},
		EndpointsSummary: api.EndpointsSummary{
			NumTotal:                     1,
			NumIngressProtected:          10,
			NumEgressProtected:           100,
			NumIngressFromInternet:       1000,
			NumEgressToInternet:          9000,
			NumIngressFromOtherNamespace: 900,
			NumEgressToOtherNamespace:    90,
			NumEnvoyEnabled:              9,
		},
		Endpoints: []api.EndpointsReportEndpoint{
			EndpointSample1,
			EndpointSample2,
		},
		AuditEvents: []audit.Event{
			AuditEventSample,
		},
		Flows: []api.EndpointsReportFlow{FlowSample1, FlowSample2, FlowSample3},
		CISBenchmark: []api.CISBenchmarkNode{
			{
				Results: []api.CISBenchmarkSectionResult{
					{
						Results: []api.CISBenchmarkResult{
							{TestNumber: "1.1.1", TestDesc: "Test1", TestInfo: "fix1", Status: "PASS", Scored: true},
							{TestNumber: "1.1.2", TestDesc: "Test1", TestInfo: "fix1", Status: "PASS", Scored: true},
							{TestNumber: "1.1.3", TestDesc: "Test1", TestInfo: "fix1", Status: "PASS", Scored: true},
							{TestNumber: "1.1.4", TestDesc: "Test1", TestInfo: "fix1", Status: "PASS", Scored: true},
							{TestNumber: "1.1.5", TestDesc: "Test1", TestInfo: "fix1", Status: "PASS", Scored: true},
						},
					},
				},
			},
			{
				Results: []api.CISBenchmarkSectionResult{
					{
						Results: []api.CISBenchmarkResult{
							{TestNumber: "1.1.1", TestDesc: "Test1", TestInfo: "fix1", Status: "PASS", Scored: true},
							{TestNumber: "1.1.2", TestDesc: "Test2", TestInfo: "fix2", Status: "FAIL", Scored: true},
							{TestNumber: "1.1.3", TestDesc: "Test3", TestInfo: "fix3", Status: "FAIL", Scored: true},
							{TestNumber: "1.1.4", TestDesc: "Test4", TestInfo: "fix4", Status: "PASS", Scored: true},
							{TestNumber: "1.1.5", TestDesc: "Test5", TestInfo: "fix5", Status: "PASS", Scored: true},
						},
					},
				},
			},
			{
				Results: []api.CISBenchmarkSectionResult{
					{
						Results: []api.CISBenchmarkResult{
							{TestNumber: "1.1.1", TestDesc: "Test1", TestInfo: "fix1", Status: "PASS", Scored: true},
							{TestNumber: "1.1.2", TestDesc: "Test2", TestInfo: "fix2", Status: "FAIL", Scored: true},
							{TestNumber: "1.1.3", TestDesc: "Test3", TestInfo: "fix3", Status: "PASS", Scored: true},
							{TestNumber: "1.1.4", TestDesc: "Test4", TestInfo: "fix4", Status: "PASS", Scored: true},
							{TestNumber: "1.1.5", TestDesc: "Test5", TestInfo: "fix5", Status: "PASS", Scored: true},
						},
					},
				},
			},
			{
				Results: []api.CISBenchmarkSectionResult{
					{
						Results: []api.CISBenchmarkResult{
							{TestNumber: "1.1.1", TestDesc: "Test1", TestInfo: "fix1", Status: "PASS", Scored: true},
							{TestNumber: "1.1.2", TestDesc: "Test2", TestInfo: "fix2", Status: "FAIL", Scored: true},
							{TestNumber: "1.1.3", TestDesc: "Test3", TestInfo: "fix3", Status: "FAIL", Scored: true},
							{TestNumber: "1.1.4", TestDesc: "Test4", TestInfo: "fix4", Status: "FAIL", Scored: true},
							{TestNumber: "1.1.5", TestDesc: "Test5", TestInfo: "fix5", Status: "FAIL", Scored: true},
						},
					},
				},
			},
			{
				Results: []api.CISBenchmarkSectionResult{
					{
						Results: []api.CISBenchmarkResult{
							{TestNumber: "1.1.1", TestDesc: "Test1", TestInfo: "fix1", Status: "PASS", Scored: true},
							{TestNumber: "1.1.2", TestDesc: "Test2", TestInfo: "fix2", Status: "FAIL", Scored: true},
							{TestNumber: "1.1.3", TestDesc: "Test3", TestInfo: "fix3", Status: "FAIL", Scored: true},
							{TestNumber: "1.1.4", TestDesc: "Test4", TestInfo: "fix4", Status: "PASS", Scored: true},
							{TestNumber: "1.1.5", TestDesc: "Test5", TestInfo: "fix5", Status: "FAIL", Scored: true},
						},
					},
				},
			},
		},
	}

	// These are used by the validation code to check that any nil entries will not break the template. Note that
	// the ReportName is being sneakily used to specify which field in the template is nil.
	ReportDataNilEntries = []api.ReportData{{
		ReportName: "ReportSpec.Endpoints",
		ReportSpec: api.ReportSpec{
			Endpoints: nil,
		},
		ReportTypeSpec: api.ReportTypeSpec{
			AuditEventsSelection: &api.AuditEventsSelection{},
		},
	}, {
		ReportName: "ReportSpec.Endpoints.Namespaces",
		ReportSpec: api.ReportSpec{
			Endpoints: &api.EndpointsSelection{
				Selector:        "lbl == 'lbl-val'",
				ServiceAccounts: &api.NamesAndLabelsMatch{},
			},
		},
		ReportTypeSpec: api.ReportTypeSpec{
			AuditEventsSelection: &api.AuditEventsSelection{},
		},
	}, {
		ReportName: "ReportSpec.Endpoints.ServiceAccounts",
		ReportSpec: api.ReportSpec{
			Endpoints: &api.EndpointsSelection{
				Selector:   "lbl == 'lbl-val'",
				Namespaces: &api.NamesAndLabelsMatch{},
			},
		},
		ReportTypeSpec: api.ReportTypeSpec{
			AuditEventsSelection: &api.AuditEventsSelection{},
		},
	}, {
		ReportName: "ReportTypeSpec.AuditEventsSelection",
		ReportSpec: api.ReportSpec{
			Endpoints: &api.EndpointsSelection{
				Selector:        "lbl == 'lbl-val'",
				Namespaces:      &api.NamesAndLabelsMatch{},
				ServiceAccounts: &api.NamesAndLabelsMatch{},
			},
		},
		ReportTypeSpec: api.ReportTypeSpec{},
	}}
)

// Returns rendered text for given text-template and data struct input.
func RenderTemplate(reportTemplateText string, reportData *api.ReportData) (rendered string, ret error) {
	defer func() {
		if perr := recover(); perr != nil {
			ret = fmt.Errorf("%v", perr)
		}
	}()

	templ, err := template.New("report-template").Funcs(templateFuncs(reportData)).Parse(reportTemplateText)
	if err != nil {
		return rendered, err
	}

	var b bytes.Buffer
	err = templ.Execute(&b, reportData)
	if err != nil {
		return rendered, err
	}
	rendered = b.String()

	return rendered, nil
}

// yamlify prints YAML for a given struct.
func yamlify(resource any) (string, error) {
	yamled, err := yaml.Marshal(resource)
	if err != nil {
		return "", err
	}

	return string(yamled), nil
}

// formatDate returns the date in the specified format
func getFormatDateFn(format string) func(date any) string {
	return func(date any) string {
		switch d := date.(type) {
		case time.Time:
			return d.Format(format)
		case *time.Time:
			if d == nil {
				return "nil"
			}
			return d.Format(format)
		case metav1.Time:
			return d.Format(format)
		case *metav1.Time:
			if d == nil {
				return "nil"
			}
			return d.Format(format)
		}
		return fmt.Sprint(date)
	}
}

func templateFuncs(reportData *api.ReportData) template.FuncMap {
	// Use the functions defined by sprig and add a couple more.
	funcs := sprig.GenericFuncMap()

	// Add YAML conversion, naming as per toJson.
	funcs["toYaml"] = yamlify

	// Add a joinN function which joins an array of strings up to a max number of elements. We utilize the
	// sprig toStrings() method to convert the final arg to a string slice.
	toStrings := funcs["toStrings"].(func(any) []string)
	funcs["joinN"] = func(sep string, max int, v any) string {
		s := toStrings(v)
		if len(s) > max {
			s = s[:max]
		}
		return strings.Join(s, sep)
	}

	// Add a useful time formats, we can add more later if required.
	funcs["dateRfc3339"] = getFormatDateFn(time.RFC3339)

	// Add flow functions to enable flow lookup from endpoint
	flowsPrefix, flowsIngress, flowsEgress := getFlowsLookupFuncs(reportData)
	funcs["flowsPrefix"] = flowsPrefix
	funcs["flowsIngress"] = flowsIngress
	funcs["flowsEgress"] = flowsEgress

	// The csv functions allow a template to be defined that constructs a CSV column by column and then
	// renders after. This makes the template look significantly better and is much easier to read.
	funcs["csv"] = func() *csv { return &csv{funcs: funcs} }

	//
	funcs["cisTopFailedTests"] = computeTopFailedCISBenchmarkTests

	return template.FuncMap(funcs)
}

// SortableCISBenchmarkTests wraps an array of cis benchmark result counts to be sortable.
type SortableCISBenchmarkTests []*api.CISBenchmarkResultCount

// Len is part of sort.Interface.
func (s SortableCISBenchmarkTests) Len() int {
	return len(s)
}

// Swap is part of sort.Interface.
func (s SortableCISBenchmarkTests) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less is part of sort.Interface.
// Since we want top failed tests first, we reverse the inequality.
func (s SortableCISBenchmarkTests) Less(i, j int) bool {
	return s[i].Count > s[j].Count
}

func computeTopFailedCISBenchmarkTests(d *api.ReportData) SortableCISBenchmarkTests {
	// Maintain a mapping of cis benchmark test result failures to their frequency of occurence.
	counter := map[api.CISBenchmarkResult]int{}
	for _, node := range d.CISBenchmark {
		for _, section := range node.Results {
			for _, test := range section.Results {
				if test.Status == "FAIL" {
					counter[test]++
				}
			}
		}
	}

	// Coerce map values into an array and sort.
	sortedTests := SortableCISBenchmarkTests{}
	for test, count := range counter {
		sortedTests = append(sortedTests, &api.CISBenchmarkResultCount{CISBenchmarkResult: test, Count: count})
	}
	sort.Sort(sortedTests)

	// https://<github-tigera-libcalico-go-repo>/blob/7c59755b40823ef3ce13ab10f7f37b46287710a1/lib/clientv3/globalreport.go#L56
	numTests := five
	if d.ReportSpec.CIS != nil && d.ReportSpec.CIS.NumFailedTests != nil {
		numTests = *d.ReportSpec.CIS.NumFailedTests
	}
	// Avoid out of bounds error by capping numTests to be the length of sortedTests if needed.
	if numTests > len(sortedTests) {
		numTests = len(sortedTests)
	}
	return sortedTests[:numTests]
}

// getFlowsLookupFuncs creates ReportData specific flow lookup functions to determine the
// prefix, ingress and egress flows associated with a specific report endpoint.
func getFlowsLookupFuncs(d *api.ReportData) (prefix func(ep api.EndpointsReportEndpoint) string, ingress, egress func(ep api.EndpointsReportEndpoint) []api.FlowEndpoint) {
	// Create a map of the flows keyed of the FlowEndpoint.
	flows := make(map[api.FlowEndpoint]endpointFlowLogs)
	for _, flow := range d.Flows {
		if isCalicoEndpoint(flow.Destination) {
			d := flows[flow.Destination]
			d.ingress = append(d.ingress, flow.Source)
			flows[flow.Destination] = d
		}
		if isCalicoEndpoint(flow.Source) {
			d := flows[flow.Source]
			d.egress = append(d.egress, flow.Destination)
			flows[flow.Source] = d
		}
	}

	prefix = func(ep api.EndpointsReportEndpoint) string {
		unaggregated, aggregated := reportEndpointToFlowEndpoint(ep)
		if _, ok := flows[unaggregated]; ok {
			return unaggregated.Name
		}
		if aggregated != nil {
			if _, ok := flows[*aggregated]; ok {
				return aggregated.Name
			}
		}
		return ""
	}
	ingress = func(ep api.EndpointsReportEndpoint) []api.FlowEndpoint {
		unaggregated, aggregated := reportEndpointToFlowEndpoint(ep)
		if f, ok := flows[unaggregated]; ok {
			return f.ingress
		}
		if aggregated != nil {
			return flows[*aggregated].ingress
		}
		return nil
	}
	egress = func(ep api.EndpointsReportEndpoint) []api.FlowEndpoint {
		unaggregated, aggregated := reportEndpointToFlowEndpoint(ep)
		if f, ok := flows[unaggregated]; ok {
			return f.egress
		}
		if aggregated != nil {
			return flows[*aggregated].egress
		}
		return nil
	}
	return
}

// isCalicoEndpoint returns true if the flow endpoint is a Calico endpoint (i.e. not the internet etc.)
func isCalicoEndpoint(fe api.FlowEndpoint) bool {
	switch fe.Kind {
	case api.KindK8sPod, api.KindHostEndpoint:
		return true
	default:
		return false
	}
}

// reportEndpointToFlowEndpoint converts the report endpoint to an unaggregated and aggregated FlowEndpoint which
// we can use to lookup the flows. We preferentially use the unaggregated name to lookup and fallback to the
// aggregated name if known.
func reportEndpointToFlowEndpoint(ep api.EndpointsReportEndpoint) (unaggregated api.FlowEndpoint, aggregated *api.FlowEndpoint) {
	unaggregated = api.FlowEndpoint{
		Kind:                    ep.Endpoint.Kind,
		Name:                    ep.Endpoint.Name,
		NameIsAggregationPrefix: false,
		Namespace:               ep.Endpoint.Namespace,
	}
	if ep.FlowLogAggregationName != "" && ep.FlowLogAggregationName != ep.Endpoint.Name {
		aggregated = &api.FlowEndpoint{
			Kind:                    ep.Endpoint.Kind,
			Name:                    ep.FlowLogAggregationName,
			NameIsAggregationPrefix: true,
			Namespace:               ep.Endpoint.Namespace,
		}
	}
	return
}

// endpointFlowLogs encapsulates flow data for a specific endpoint in terms of ingress and egress flows.
type endpointFlowLogs struct {
	ingress []api.FlowEndpoint
	egress  []api.FlowEndpoint
}

// cvs encapsulates the headings and value template strings.
type csv struct {
	funcs    template.FuncMap
	headings []string
	values   []string
}

func (c *csv) AddColumn(heading, value string) *csv {
	c.headings = append(c.headings, heading)
	c.values = append(c.values, value)
	return c
}

// Render renders a csv from the heading/value/function information stored in the csv struct.
func (c *csv) Render(data any) (string, error) {
	var templateString string

	val := reflect.ValueOf(data)
	switch val.Kind() {
	case reflect.Array, reflect.Slice:
		templateString = strings.Join(c.headings, ",") + "\n{{ range . }}" + strings.Join(c.values, ",") + "\n{{ end }}"
	default:
		templateString = strings.Join(c.headings, ",") + "\n" + strings.Join(c.values, ",")
	}

	templ, err := template.New("csv-template").Funcs(c.funcs).Parse(templateString)
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	err = templ.Execute(&b, data)
	if err != nil {
		return "", err
	}
	return b.String(), nil
}
