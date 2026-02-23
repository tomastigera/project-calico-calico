// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package features

import (
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
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
	IngressGateway         = "ingress-gateway-addons"
)

type set map[string]bool

const (
	// Enterprise constant to define a license package for Calico Enterprise using a self - hosted environment
	Enterprise = "cnx|all"
)

// PackageNames defines the name of the license packages available
var PackageNames = set{Enterprise: true}

// IsValidPackageName return true if a package name matches the one defined in PackageNames
func IsValidPackageName(value string) bool {
	return PackageNames[value]
}

// OpenSourceAPIs maps calico open source APIs
var OpenSourceAPIs = set{
	api.NewBFDConfiguration().GetObjectKind().GroupVersionKind().String():              true,
	api.NewBGPConfiguration().GetObjectKind().GroupVersionKind().String():              true,
	api.NewBGPFilter().GetObjectKind().GroupVersionKind().String():                     true,
	api.NewBGPPeer().GetObjectKind().GroupVersionKind().String():                       true,
	api.NewCalicoNodeStatus().GetObjectKind().GroupVersionKind().String():              true,
	api.NewClusterInformation().GetObjectKind().GroupVersionKind().String():            true,
	api.NewEgressGatewayPolicy().GetObjectKind().GroupVersionKind().String():           true,
	api.NewExternalNetwork().GetObjectKind().GroupVersionKind().String():               true,
	api.NewFelixConfiguration().GetObjectKind().GroupVersionKind().String():            true,
	api.NewGlobalNetworkPolicy().GetObjectKind().GroupVersionKind().String():           true,
	api.NewGlobalNetworkSet().GetObjectKind().GroupVersionKind().String():              true,
	api.NewHostEndpoint().GetObjectKind().GroupVersionKind().String():                  true,
	api.NewIPAMConfiguration().GetObjectKind().GroupVersionKind().String():             true,
	api.NewIPPool().GetObjectKind().GroupVersionKind().String():                        true,
	api.NewIPReservation().GetObjectKind().GroupVersionKind().String():                 true,
	api.NewKubeControllersConfiguration().GetObjectKind().GroupVersionKind().String():  true,
	api.NewNetworkPolicy().GetObjectKind().GroupVersionKind().String():                 true,
	api.NewNetworkSet().GetObjectKind().GroupVersionKind().String():                    true,
	api.NewProfile().GetObjectKind().GroupVersionKind().String():                       true,
	api.NewStagedGlobalNetworkPolicy().GetObjectKind().GroupVersionKind().String():     true,
	api.NewStagedKubernetesNetworkPolicy().GetObjectKind().GroupVersionKind().String(): true,
	api.NewStagedNetworkPolicy().GetObjectKind().GroupVersionKind().String():           true,
	api.NewTier().GetObjectKind().GroupVersionKind().String():                          true,
	internalapi.NewNode().GetObjectKind().GroupVersionKind().String():                  true,
}

// EnterpriseAPIsToFeatureName maps calico enterprise APIs to feature names
var EnterpriseAPIsToFeatureName = map[string]string{
	api.NewAlertException().GetObjectKind().GroupVersionKind().String():                 AlertManagement,
	api.NewAlertExceptionList().GetObjectKind().GroupVersionKind().String():             AlertManagement,
	api.NewDeepPacketInspection().GetObjectKind().GroupVersionKind().String():           ThreatDefense,
	api.NewDeepPacketInspectionList().GetObjectKind().GroupVersionKind().String():       ThreatDefense,
	api.NewGlobalAlert().GetObjectKind().GroupVersionKind().String():                    AlertManagement,
	api.NewGlobalAlertList().GetObjectKind().GroupVersionKind().String():                AlertManagement,
	api.NewGlobalAlertTemplate().GetObjectKind().GroupVersionKind().String():            AlertManagement,
	api.NewGlobalAlertTemplateList().GetObjectKind().GroupVersionKind().String():        AlertManagement,
	api.NewGlobalReport().GetObjectKind().GroupVersionKind().String():                   ComplianceReports,
	api.NewGlobalReportList().GetObjectKind().GroupVersionKind().String():               ComplianceReports,
	api.NewGlobalReportType().GetObjectKind().GroupVersionKind().String():               ComplianceReports,
	api.NewGlobalReportTypeList().GetObjectKind().GroupVersionKind().String():           ComplianceReports,
	api.NewGlobalThreatFeed().GetObjectKind().GroupVersionKind().String():               ThreatDefense,
	api.NewGlobalThreatFeedList().GetObjectKind().GroupVersionKind().String():           ThreatDefense,
	api.NewManagedCluster().GetObjectKind().GroupVersionKind().String():                 MultiClusterManagement,
	api.NewManagedClusterList().GetObjectKind().GroupVersionKind().String():             MultiClusterManagement,
	api.NewPacketCapture().GetObjectKind().GroupVersionKind().String():                  PacketCapture,
	api.NewPacketCaptureList().GetObjectKind().GroupVersionKind().String():              PacketCapture,
	api.NewPolicyRecommendationScope().GetObjectKind().GroupVersionKind().String():      PolicyRecommendation,
	api.NewPolicyRecommendationScopeList().GetObjectKind().GroupVersionKind().String():  PolicyRecommendation,
	api.NewRemoteClusterConfiguration().GetObjectKind().GroupVersionKind().String():     FederatedServices,
	api.NewRemoteClusterConfigurationList().GetObjectKind().GroupVersionKind().String(): FederatedServices,
	api.NewSecurityEventWebhook().GetObjectKind().GroupVersionKind().String():           AlertManagement,
	api.NewSecurityEventWebhookList().GetObjectKind().GroupVersionKind().String():       AlertManagement,
}

// ManagementAPIs maps calico enterprise APIs used for managing/accessing resources
var ManagementAPIs = set{
	api.NewLicenseKey().GetObjectKind().GroupVersionKind().String():     true,
	api.NewLicenseKeyList().GetObjectKind().GroupVersionKind().String(): true,
}
