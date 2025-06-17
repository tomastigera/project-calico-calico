// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package features

import (
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
)

const (
	All                    = "all"
	DropActionOverride     = "drop-action-override"
	PrometheusMetrics      = "prometheus-metrics"
	AWSCloudwatchFlowLogs  = "aws-cloudwatch-flow-logs"
	AWSCloudwatchMetrics   = "aws-cloudwatch-metrics"
	AWSSecurityGroups      = "aws-security-groups"
	IPSec                  = "ipsec"
	FederatedServices      = "federated-services"
	FileOutputFlowLogs     = "file-output-flow-logs"
	FileOutputL7Logs       = "file-output-l7-logs"
	ManagementPortal       = "management-portal"
	PolicyRecommendation   = "policy-recommendation"
	PolicyPreview          = "policy-preview"
	PolicyManagement       = "policy-management"
	Tiers                  = "tiers"
	EgressAccessControl    = "egress-access-control"
	ExportLogs             = "export-logs"
	AlertManagement        = "alert-management"
	TopologicalGraph       = "topological-graph"
	KibanaDashboard        = "kibana-dashboard"
	ComplianceReports      = "compliance-reports"
	ThreatDefense          = "threat-defense"
	PacketCapture          = "packet-capture"
	MultiClusterManagement = "multi-cluster-management"
	IngressGateway         = "ingress-gateway"
)

type set map[string]bool

func merge(a set, b set) set {
	var new set = make(set)

	for k, v := range a {
		new[k] = v
	}

	for k, v := range b {
		new[k] = v
	}

	return new
}

// Keys extracts the keys from a set
func Keys(set map[string]bool) []string {
	var keys []string
	for k := range set {
		keys = append(keys, k)
	}
	return keys
}

const (
	// CloudCommunity constants to define a license package for Calico Cloud Community
	CloudCommunity = "cloud|community"
	// CloudStarter constants to define a license package for Calico Cloud Starter
	CloudStarter = "cloud|starter"
	// CloudPro constants to define a license package for Calico Cloud Pro
	CloudPro = "cloud|pro"
	// Enterprise constant to define a license package for Calico Enterprise using a self - hosted environment
	Enterprise = "cnx|all"
)

// PackageNames defines the name of the license packages available
var PackageNames = set{CloudCommunity: true, CloudStarter: true, CloudPro: true, Enterprise: true}

// IsValidPackageName return true if a package name matches the one defined in PackageNames
func IsValidPackageName(value string) bool {
	return PackageNames[value]
}

// OpenSourceAPIs maps calico open source APIs
var OpenSourceAPIs = set{
	api.NewBGPConfiguration().GetObjectKind().GroupVersionKind().String():             true,
	api.NewBGPPeer().GetObjectKind().GroupVersionKind().String():                      true,
	api.NewClusterInformation().GetObjectKind().GroupVersionKind().String():           true,
	api.NewFelixConfiguration().GetObjectKind().GroupVersionKind().String():           true,
	api.NewGlobalNetworkPolicy().GetObjectKind().GroupVersionKind().String():          true,
	api.NewGlobalNetworkSet().GetObjectKind().GroupVersionKind().String():             true,
	api.NewHostEndpoint().GetObjectKind().GroupVersionKind().String():                 true,
	api.NewIPPool().GetObjectKind().GroupVersionKind().String():                       true,
	api.NewKubeControllersConfiguration().GetObjectKind().GroupVersionKind().String(): true,
	api.NewNetworkPolicy().GetObjectKind().GroupVersionKind().String():                true,
	api.NewNetworkSet().GetObjectKind().GroupVersionKind().String():                   true,
	libapi.NewNode().GetObjectKind().GroupVersionKind().String():                      true,
	api.NewProfile().GetObjectKind().GroupVersionKind().String():                      true,
	api.NewStagedGlobalNetworkPolicy().GetObjectKind().GroupVersionKind().String():    true,
	api.NewExternalNetwork().GetObjectKind().GroupVersionKind().String():              true,
	api.NewBGPFilter().GetObjectKind().GroupVersionKind().String():                    true,
	api.NewEgressGatewayPolicy().GetObjectKind().GroupVersionKind().String():          true,
	api.NewBFDConfiguration().GetObjectKind().GroupVersionKind().String():             true,
}

// EnterpriseAPIsToFeatureName maps calico enterprise APIs to feature names
var EnterpriseAPIsToFeatureName = map[string]string{
	api.NewAlertException().GetObjectKind().GroupVersionKind().String():                 AlertManagement,
	api.NewAlertExceptionList().GetObjectKind().GroupVersionKind().String():             AlertManagement,
	api.NewGlobalAlert().GetObjectKind().GroupVersionKind().String():                    AlertManagement,
	api.NewGlobalAlertList().GetObjectKind().GroupVersionKind().String():                AlertManagement,
	api.NewGlobalAlertTemplate().GetObjectKind().GroupVersionKind().String():            AlertManagement,
	api.NewGlobalAlertTemplateList().GetObjectKind().GroupVersionKind().String():        AlertManagement,
	api.NewPacketCapture().GetObjectKind().GroupVersionKind().String():                  PacketCapture,
	api.NewPacketCaptureList().GetObjectKind().GroupVersionKind().String():              PacketCapture,
	api.NewRemoteClusterConfiguration().GetObjectKind().GroupVersionKind().String():     FederatedServices,
	api.NewRemoteClusterConfigurationList().GetObjectKind().GroupVersionKind().String(): FederatedServices,
	api.NewGlobalReport().GetObjectKind().GroupVersionKind().String():                   ComplianceReports,
	api.NewGlobalReportList().GetObjectKind().GroupVersionKind().String():               ComplianceReports,
	api.NewGlobalReportType().GetObjectKind().GroupVersionKind().String():               ComplianceReports,
	api.NewGlobalReportTypeList().GetObjectKind().GroupVersionKind().String():           ComplianceReports,
	api.NewGlobalThreatFeed().GetObjectKind().GroupVersionKind().String():               ThreatDefense,
	api.NewGlobalThreatFeedList().GetObjectKind().GroupVersionKind().String():           ThreatDefense,
	api.NewManagedCluster().GetObjectKind().GroupVersionKind().String():                 MultiClusterManagement,
	api.NewManagedClusterList().GetObjectKind().GroupVersionKind().String():             MultiClusterManagement,
}

// ManagementAPIs maps calico enterprise APIs used for managing/accessing resources
var ManagementAPIs = set{
	api.NewLicenseKey().GetObjectKind().GroupVersionKind().String():     true,
	api.NewLicenseKeyList().GetObjectKind().GroupVersionKind().String(): true,
}

// CloudCommunityFeatures is defined by features such as: Management Portal UI, Policy Management and Policy Troubleshooting
var CloudCommunityFeatures = set{ManagementPortal: true, PolicyRecommendation: true, PolicyPreview: true, PolicyManagement: true, FileOutputFlowLogs: true, PrometheusMetrics: true, MultiClusterManagement: true}

// CloudCommunityAPIs maps cloud community package APIs
var CloudCommunityAPIs = merge(OpenSourceAPIs, set{
	api.NewLicenseKey().GetObjectKind().GroupVersionKind().String():                        true,
	api.NewLicenseKeyList().GetObjectKind().GroupVersionKind().String():                    true,
	api.NewStagedGlobalNetworkPolicy().GetObjectKind().GroupVersionKind().String():         true,
	api.NewStagedGlobalNetworkPolicyList().GetObjectKind().GroupVersionKind().String():     true,
	api.NewStagedKubernetesNetworkPolicy().GetObjectKind().GroupVersionKind().String():     true,
	api.NewStagedKubernetesNetworkPolicyList().GetObjectKind().GroupVersionKind().String(): true,
	api.NewStagedNetworkPolicy().GetObjectKind().GroupVersionKind().String():               true,
	api.NewStagedNetworkPolicyList().GetObjectKind().GroupVersionKind().String():           true,
})

// CloudStarterFeatures has in addition to CloudCommuniy EgressAccessControl and Tiers
var CloudStarterFeatures = merge(CloudCommunityFeatures, set{EgressAccessControl: true, Tiers: true})

// CloudStarterAPIs maps cloud starter package APIs
var CloudStarterAPIs = merge(CloudCommunityAPIs, set{
	api.NewTier().GetObjectKind().GroupVersionKind().String():     true,
	api.NewTierList().GetObjectKind().GroupVersionKind().String(): true,
})

// CloudProFeatures contains all available features except Compliance and Threat Defense features
var CloudProFeatures = merge(CloudStarterFeatures, set{FederatedServices: true, ExportLogs: true, AlertManagement: true, TopologicalGraph: true, KibanaDashboard: true, FileOutputL7Logs: true, PacketCapture: true})

// CloudProAPIs maps cloud pro package APIs
var CloudProAPIs = merge(CloudStarterAPIs, set{
	api.NewAlertException().GetObjectKind().GroupVersionKind().String():                 true,
	api.NewAlertExceptionList().GetObjectKind().GroupVersionKind().String():             true,
	api.NewGlobalAlert().GetObjectKind().GroupVersionKind().String():                    true,
	api.NewGlobalAlertList().GetObjectKind().GroupVersionKind().String():                true,
	api.NewGlobalAlertTemplate().GetObjectKind().GroupVersionKind().String():            true,
	api.NewGlobalAlertTemplateList().GetObjectKind().GroupVersionKind().String():        true,
	api.NewPacketCapture().GetObjectKind().GroupVersionKind().String():                  true,
	api.NewPacketCaptureList().GetObjectKind().GroupVersionKind().String():              true,
	api.NewRemoteClusterConfiguration().GetObjectKind().GroupVersionKind().String():     true,
	api.NewRemoteClusterConfigurationList().GetObjectKind().GroupVersionKind().String(): true,
})

// EnterpriseAPIs maps enterprise package to all APIs
var EnterpriseAPIs = merge(CloudProAPIs, set{
	api.NewGlobalReport().GetObjectKind().GroupVersionKind().String():         true,
	api.NewGlobalReportList().GetObjectKind().GroupVersionKind().String():     true,
	api.NewGlobalReportType().GetObjectKind().GroupVersionKind().String():     true,
	api.NewGlobalReportTypeList().GetObjectKind().GroupVersionKind().String(): true,
	api.NewGlobalThreatFeed().GetObjectKind().GroupVersionKind().String():     true,
	api.NewGlobalThreatFeedList().GetObjectKind().GroupVersionKind().String(): true,
})

// EnterpriseFeatures package contains all available features
var EnterpriseFeatures = merge(CloudProFeatures, set{ComplianceReports: true, ThreatDefense: true})

var AddOnFeatures = set{
	IngressGateway: true,
}
