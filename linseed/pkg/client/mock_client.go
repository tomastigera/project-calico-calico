// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package client

import "github.com/projectcalico/calico/linseed/pkg/client/rest"

type MockClient interface {
	Client
	SetResults(results ...rest.MockResult)
	Requests() []*rest.MockRequest
}

type mockClient struct {
	restClient rest.RESTClient
	tenant     string
}

func (c *mockClient) RESTClient() rest.RESTClient {
	return c.restClient
}

func (c *mockClient) L3Flows(cluster string) L3FlowsInterface {
	return newL3Flows(c, cluster)
}

func (c *mockClient) L7Flows(cluster string) L7FlowsInterface {
	return newL7Flows(c, cluster)
}

func (c *mockClient) DNSFlows(cluster string) DNSFlowsInterface {
	return newDNSFlows(c, cluster)
}

func (c *mockClient) Events(cluster string) EventsInterface {
	return newEvents(c, cluster)
}

func (c *mockClient) FlowLogs(cluster string) FlowLogsInterface {
	return newFlowLogs(c, cluster)
}

func (c *mockClient) DNSLogs(cluster string) DNSLogsInterface {
	return newDNSLogs(c, cluster)
}

func (c *mockClient) L7Logs(cluster string) L7LogsInterface {
	return newL7Logs(c, cluster)
}

func (c *mockClient) AuditLogs(cluster string) AuditLogsInterface {
	return newAuditLogs(c, cluster)
}

func (c *mockClient) BGPLogs(cluster string) BGPLogsInterface {
	return newBGPLogs(c, cluster)
}

func (c *mockClient) WAFLogs(cluster string) WAFLogsInterface {
	return newWAFLogs(c, cluster)
}

func (c *mockClient) Processes(cluster string) ProcessesInterface {
	return newProcesses(c, cluster)
}

func (c *mockClient) Compliance(cluster string) ComplianceInterface {
	return newCompliance(c, cluster)
}

func (c *mockClient) RuntimeReports(cluster string) RuntimeReportsInterface {
	return newRuntimeReports(c, cluster)
}

func (c *mockClient) ThreatFeeds(cluster string) ThreatFeedsInterface {
	return newThreatFeeds(c, cluster)
}

func (c *mockClient) PolicyActivity(cluster string) PolicyActivityInterface {
	return newPolicyActivityLogs(c, cluster)
}

func (c *mockClient) Token() []byte {
	return nil
}

func NewMockClient(tenantID string, results ...rest.MockResult) MockClient {
	return &mockClient{
		restClient: rest.NewMockClient(results...),
		tenant:     tenantID,
	}
}

func (m *mockClient) SetResults(results ...rest.MockResult) {
	m.restClient = rest.NewMockClient(results...)
}

func (m *mockClient) Requests() []*rest.MockRequest {
	return m.restClient.(*rest.MockRESTClient).Requests()
}
