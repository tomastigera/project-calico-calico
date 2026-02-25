// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

package processor

import (
	"context"

	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

// MockClientInterface is mock of clientv3.Interface
// it mocks call to DeepPacketInspections() and returns nil for every other functions of clientv3.Interface
type MockClientInterface struct {
	mock.Mock
}

func (_m *MockClientInterface) AlertExceptions() clientv3.AlertExceptionInterface {
	return nil
}

func (_m *MockClientInterface) SecurityEventWebhook() clientv3.SecurityEventWebhookInterface {
	return nil
}

func (_m *MockClientInterface) BGPConfigurations() clientv3.BGPConfigurationInterface {
	return nil
}

func (_m *MockClientInterface) BGPFilter() clientv3.BGPFilterInterface {
	return nil
}

func (_m *MockClientInterface) BGPPeers() clientv3.BGPPeerInterface {
	return nil
}

func (_m *MockClientInterface) CalicoNodeStatus() clientv3.CalicoNodeStatusInterface {
	panic("implement me")
}

func (_m *MockClientInterface) ClusterInformation() clientv3.ClusterInformationInterface {
	return nil
}

func (_m *MockClientInterface) IPAMConfiguration() clientv3.IPAMConfigurationInterface {
	return nil
}

func (_m *MockClientInterface) BlockAffinities() clientv3.BlockAffinityInterface {
	return nil
}

func (_m *MockClientInterface) DeepPacketInspections() clientv3.DeepPacketInspectionInterface {
	ret := _m.Called()

	var r0 clientv3.DeepPacketInspectionInterface
	if rf, ok := ret.Get(0).(func() clientv3.DeepPacketInspectionInterface); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(clientv3.DeepPacketInspectionInterface)
		}
	}

	return r0
}

func (_m *MockClientInterface) EnsureInitialized(ctx context.Context, calicoVersion string, calicoEnterpriseVersion string, clusterType string) error {
	return nil
}

func (_m *MockClientInterface) Close() error {
	return nil
}

func (_m *MockClientInterface) FelixConfigurations() clientv3.FelixConfigurationInterface {
	return nil
}

func (_m *MockClientInterface) GlobalAlertTemplates() clientv3.GlobalAlertTemplateInterface {
	return nil
}

func (_m *MockClientInterface) GlobalAlerts() clientv3.GlobalAlertInterface {
	return nil
}

func (_m *MockClientInterface) GlobalNetworkPolicies() clientv3.GlobalNetworkPolicyInterface {
	return nil
}

func (_m *MockClientInterface) GlobalNetworkSets() clientv3.GlobalNetworkSetInterface {
	return nil
}

func (_m *MockClientInterface) GlobalReportTypes() clientv3.GlobalReportTypeInterface {
	return nil
}

func (_m *MockClientInterface) GlobalReports() clientv3.GlobalReportInterface {
	return nil
}

func (_m *MockClientInterface) GlobalThreatFeeds() clientv3.GlobalThreatFeedInterface {
	return nil
}

func (_m *MockClientInterface) HostEndpoints() clientv3.HostEndpointInterface {
	return nil
}

func (_m *MockClientInterface) IPAM() ipam.Interface {
	return nil
}

func (_m *MockClientInterface) IPPools() clientv3.IPPoolInterface {
	return nil
}

func (_m *MockClientInterface) IPReservations() clientv3.IPReservationInterface {
	panic("implement me")
}

func (_m *MockClientInterface) KubeControllersConfiguration() clientv3.KubeControllersConfigurationInterface {
	return nil
}

func (_m *MockClientInterface) LicenseKey() clientv3.LicenseKeyInterface {
	return nil
}

func (_m *MockClientInterface) ManagedClusters() clientv3.ManagedClusterInterface {
	return nil
}

func (_m *MockClientInterface) NetworkPolicies() clientv3.NetworkPolicyInterface {
	return nil
}

func (_m *MockClientInterface) NetworkSets() clientv3.NetworkSetInterface {
	return nil
}

func (_m *MockClientInterface) Nodes() clientv3.NodeInterface {
	return nil
}

func (_m *MockClientInterface) PacketCaptures() clientv3.PacketCaptureInterface {
	return nil
}

func (_m *MockClientInterface) PolicyRecommendationScopes() clientv3.PolicyRecommendationScopeInterface {
	return nil
}

func (_m *MockClientInterface) Profiles() clientv3.ProfileInterface {
	return nil
}

func (_m *MockClientInterface) RemoteClusterConfigurations() clientv3.RemoteClusterConfigurationInterface {
	return nil
}

func (_m *MockClientInterface) StagedGlobalNetworkPolicies() clientv3.StagedGlobalNetworkPolicyInterface {
	return nil
}

func (_m *MockClientInterface) StagedKubernetesNetworkPolicies() clientv3.StagedKubernetesNetworkPolicyInterface {
	return nil
}

func (_m *MockClientInterface) StagedNetworkPolicies() clientv3.StagedNetworkPolicyInterface {
	return nil
}

func (_m *MockClientInterface) Tiers() clientv3.TierInterface {
	return nil
}

func (_m *MockClientInterface) UISettingsGroups() clientv3.UISettingsGroupInterface {
	panic("implement me")
}

func (_m *MockClientInterface) UISettings() clientv3.UISettingsInterface {
	panic("implement me")
}

func (_m *MockClientInterface) WorkloadEndpoints() clientv3.WorkloadEndpointInterface {
	return nil
}

func (_m *MockClientInterface) ExternalNetworks() clientv3.ExternalNetworkInterface {
	return nil
}

func (_m *MockClientInterface) EgressGatewayPolicy() clientv3.EgressGatewayPolicyInterface {
	return nil
}

func (_m *MockClientInterface) BFDConfigurations() clientv3.BFDConfigurationInterface {
	return nil
}
