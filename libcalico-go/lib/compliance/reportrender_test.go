// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package compliance_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/compliance"
)

var _ = Describe("ReportTemplate Renderer", func() {
	It("inventory-summary report rendering", func() {
		tmpl := `startTime,endTime,selector,namespaceSelector,serviceAccountSelectors,endpointsNumInScope,endpointsNumIngressProtected,endpointsNumEgressProtected,endpointsNumIngressFromInternet,endpointsNumEgressToInternet,endpointsNumIngressFromOtherNamespace,endpointsNumEgressToOtherNamespace,endpointsNumEnvoyEnabled
{{ dateRfc3339 .StartTime }},{{ dateRfc3339 .EndTime }},{{ .ReportSpec.Endpoints.Selector }},{{ .ReportSpec.Endpoints.Namespaces.Selector }},{{ .ReportSpec.Endpoints.ServiceAccounts.Selector }},{{ .EndpointsSummary.NumTotal }},{{ .EndpointsSummary.NumIngressProtected }},{{ .EndpointsSummary.NumEgressProtected }},{{ .EndpointsSummary.NumIngressFromInternet }},{{ .EndpointsSummary.NumEgressToInternet }},{{ .EndpointsSummary.NumIngressFromOtherNamespace }},{{ .EndpointsSummary.NumEgressToOtherNamespace }},{{ .EndpointsSummary.NumEnvoyEnabled }}`
		rendered := `startTime,endTime,selector,namespaceSelector,serviceAccountSelectors,endpointsNumInScope,endpointsNumIngressProtected,endpointsNumEgressProtected,endpointsNumIngressFromInternet,endpointsNumEgressToInternet,endpointsNumIngressFromOtherNamespace,endpointsNumEgressToOtherNamespace,endpointsNumEnvoyEnabled
2019-04-01T00:00:00Z,2019-04-01T10:00:00Z,lbl == 'lbl-val',endpoint-namespace-selector,serviceaccount-selector,1,10,100,1000,9000,900,90,9`

		matches, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(rendered))
	})

	It("inventory-summary report rendering using csv", func() {
		tmpl := `{{ $c := csv }}
{{- $c := $c.AddColumn "startTime"                             "{{ dateRfc3339 .StartTime }}" }}
{{- $c := $c.AddColumn "endTime"                               "{{ dateRfc3339 .EndTime }}" }}
{{- $c := $c.AddColumn "selector"                              "{{ .ReportSpec.Endpoints.Selector }}" }}
{{- $c := $c.AddColumn "namespaceSelector"                     "{{ .ReportSpec.Endpoints.Namespaces.Selector }}" }}
{{- $c := $c.AddColumn "serviceAccountSelectors"               "{{ .ReportSpec.Endpoints.ServiceAccounts.Selector }}" }}
{{- $c := $c.AddColumn "endpointsNumInScope"                   "{{ .EndpointsSummary.NumTotal }}" }}
{{- $c := $c.AddColumn "endpointsNumIngressProtected"          "{{ .EndpointsSummary.NumIngressProtected }}" }}
{{- $c := $c.AddColumn "endpointsNumEgressProtected"           "{{ .EndpointsSummary.NumEgressProtected }}" }}
{{- $c := $c.AddColumn "endpointsNumIngressFromInternet"       "{{ .EndpointsSummary.NumIngressFromInternet }}" }}
{{- $c := $c.AddColumn "endpointsNumEgressToInternet"          "{{ .EndpointsSummary.NumEgressToInternet }}" }}
{{- $c := $c.AddColumn "endpointsNumIngressFromOtherNamespace" "{{ .EndpointsSummary.NumIngressFromOtherNamespace }}" }}
{{- $c := $c.AddColumn "endpointsNumEgressToOtherNamespace"    "{{ .EndpointsSummary.NumEgressToOtherNamespace }}" }}
{{- $c := $c.AddColumn "endpointsNumEnvoyEnabled"              "{{ .EndpointsSummary.NumEnvoyEnabled }}" }}
{{- $c.Render . }}`
		rendered := `startTime,endTime,selector,namespaceSelector,serviceAccountSelectors,endpointsNumInScope,endpointsNumIngressProtected,endpointsNumEgressProtected,endpointsNumIngressFromInternet,endpointsNumEgressToInternet,endpointsNumIngressFromOtherNamespace,endpointsNumEgressToOtherNamespace,endpointsNumEnvoyEnabled
2019-04-01T00:00:00Z,2019-04-01T10:00:00Z,lbl == 'lbl-val',endpoint-namespace-selector,serviceaccount-selector,1,10,100,1000,9000,900,90,9`

		matches, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(rendered), matches)
	})

	It("inventory-endpoints report rendering", func() {
		tmpl := `name,namespace,ingressProtected,egressProtected,envoyEnabled,appliedPolicies,services
{{ range .Endpoints -}}
  {{ .Endpoint.Name }},{{ .Endpoint.Namespace }},{{ .IngressProtected }},{{ .EgressProtected }},{{ .EnvoyEnabled }},{{ join ";" .AppliedPolicies }},{{ join ";" .Services }}
{{ end }}`
		rendered := `name,namespace,ingressProtected,egressProtected,envoyEnabled,appliedPolicies,services
hep1,,false,true,false,GlobalNetworkPolicy(gnp1),
pod-abcdef,ns1,false,true,false,NetworkPolicy(ns1/np1);GlobalNetworkPolicy(gnp1),Service.v1(n21/svc1);Service.v1(n22/svc2)
`

		matches, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(rendered))
	})

	It("inventory-endpoints report rendering using csv", func() {
		tmpl := `{{ $c := csv }}
{{- $c := $c.AddColumn "name"             "{{ .Endpoint.Name }}" }}
{{- $c := $c.AddColumn "namespace"        "{{ .Endpoint.Namespace }}" }}
{{- $c := $c.AddColumn "ingressProtected" "{{ .IngressProtected }}" }}
{{- $c := $c.AddColumn "egressProtected"  "{{ .EgressProtected }}" }}
{{- $c := $c.AddColumn "envoyEnabled"     "{{ .EnvoyEnabled }}" }}
{{- $c := $c.AddColumn "appliedPolicies"  "{{ join \";\" .AppliedPolicies }}" }}
{{- $c := $c.AddColumn "services"         "{{ join \";\" .Services }}" }}
{{- $c.Render .Endpoints }}`
		rendered := `name,namespace,ingressProtected,egressProtected,envoyEnabled,appliedPolicies,services
hep1,,false,true,false,GlobalNetworkPolicy(gnp1),
pod-abcdef,ns1,false,true,false,NetworkPolicy(ns1/np1);GlobalNetworkPolicy(gnp1),Service.v1(n21/svc1);Service.v1(n22/svc2)
`

		matches, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(rendered))
	})

	It("inventory-endpoints report rendering with | separator", func() {
		tmpl := `name,namespace,ingressProtected,egressProtected,envoyEnabled,appliedPolicies,services
{{ range .Endpoints -}}
  {{ .Endpoint.Name }},{{ .Endpoint.Namespace }},{{ .IngressProtected }},{{ .EgressProtected }},{{ .EnvoyEnabled }},{{ join "|" .AppliedPolicies }},{{ join "|" .Services }}
{{ end }}`
		rendered := `name,namespace,ingressProtected,egressProtected,envoyEnabled,appliedPolicies,services
hep1,,false,true,false,GlobalNetworkPolicy(gnp1),
pod-abcdef,ns1,false,true,false,NetworkPolicy(ns1/np1)|GlobalNetworkPolicy(gnp1),Service.v1(n21/svc1)|Service.v1(n22/svc2)
`

		matches, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(rendered))
	})

	It("inventory-endpoints report using ResourceID", func() {
		tmpl := "{{ range .Endpoints -}} {{ .Endpoint }} {{- end }}"
		rendered := "HostEndpoint(hep1)Pod.v1(ns1/pod-abcdef)"

		matches, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(rendered))
	})

	It("network access report rendering flow logs", func() {
		tmpl := `name,prefix,ingress,egress
{{ range .Endpoints -}}
  {{ .Endpoint }},{{ flowsPrefix . }},{{ join ";" (flowsIngress .) }},{{ join ";" (flowsEgress .) }}
{{ end }}`
		// Can't easily predict the order of flow entries, so just check for both possibilities.
		rendered1 := `name,prefix,ingress,egress
HostEndpoint(hep1),hep1,Pod.v1(ns2/pod-abc-*),
Pod.v1(ns1/pod-abcdef),pod-*,,Pod.v1(ns2/pod-*);Pod.v1(ns3/pod-*)
`
		rendered2 := `name,prefix,ingress,egress
HostEndpoint(hep1),hep1,Pod.v1(ns2/pod-abc-*),
Pod.v1(ns1/pod-abcdef),pod-*,,Pod.v1(ns3/pod-*);Pod.v1(ns2/pod-*)
`

		matches, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).ToNot(HaveOccurred())
		if matches != rendered1 {
			Expect(matches).To(Equal(rendered2))
		}
	})

	It("inventory-endpoints report failing with invalid argument", func() {
		// Wrong number of arguments
		tmpl := `{{ range .Endpoints -}} {{ join .AppliedPolicies }} {{ end }}`
		_, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).To(HaveOccurred())

		// Invalid max-entries argument
		invalidCappedTmpl := `{{ range .Endpoints -}} {{ join ";" "1" .AppliedPolicies }} {{ end }}`
		_, err = compliance.RenderTemplate(invalidCappedTmpl, &compliance.ReportDataSample)
		Expect(err).To(HaveOccurred())
	})

	It("audit report rendering - json", func() {
		tmpl := "{{ toJson .AuditEvents }}"

		_, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).ToNot(HaveOccurred())
	})

	It("audit report rendering - yaml", func() {
		tmpl := "{{ toYaml .AuditEvents }}"

		_, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should properly determine the top failed tests from a list of CIS benchmark node results", func() {
		tmpl := "{{ $tests := cisTopFailedTests . }}{{ range $i, $test := $tests }}{{ $test.TestNumber }}:{{ end }}"
		rendered, err := compliance.RenderTemplate(tmpl, &compliance.ReportDataSample)
		Expect(err).ToNot(HaveOccurred())
		Expect(rendered).To(Equal("1.1.2:1.1.3:1.1.5:1.1.4:"))
	})
})
