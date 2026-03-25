// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package migration

import (
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/migration/migrators"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

// Enterprise-specific migration ordering constants. These slot in alongside the
// OSS ordering constants in resources.go so that enterprise types migrate at a
// sensible point relative to OSS types.
const (
	// OrderEnterpriseSecurity covers alert-related, threat, and security event
	// resources that are logically similar to policies.
	OrderEnterpriseSecurity = 65

	// OrderEnterpriseReports covers compliance/report resources.
	OrderEnterpriseReports = 70

	// OrderEnterpriseManagement covers multi-cluster management resources.
	OrderEnterpriseManagement = 80

	// OrderEnterpriseUI covers UI settings resources.
	OrderEnterpriseUI = 90
)

// NewEnterpriseMigrators returns migrators for enterprise-only Calico resource
// types. These are appended to the OSS migrators so the migration controller
// handles both OSS and enterprise resources in a single pass.
func NewEnterpriseMigrators(bc api.Client, rt client.Client) []migrators.ResourceMigrator {
	return []migrators.ResourceMigrator{
		// Config singletons — migrate early alongside OSS config resources.
		migrators.New[apiv3.LicenseKey, apiv3.LicenseKeyList](apiv3.KindLicenseKey, OrderConfigSingletons, bc, rt),

		// Network infrastructure — same order as OSS BGPPeer, IPPool, etc.
		migrators.New[apiv3.BFDConfiguration, apiv3.BFDConfigurationList](apiv3.KindBFDConfiguration, OrderNetworkInfra, bc, rt),
		migrators.New[apiv3.ExternalNetwork, apiv3.ExternalNetworkList](apiv3.KindExternalNetwork, OrderNetworkInfra, bc, rt),

		// Policies — EgressGatewayPolicy is logically a policy resource.
		migrators.New[apiv3.EgressGatewayPolicy, apiv3.EgressGatewayPolicyList](apiv3.KindEgressGatewayPolicy, OrderPolicy, bc, rt),

		// Endpoints and operations — DPI and packet capture are per-namespace.
		migrators.New[apiv3.DeepPacketInspection, apiv3.DeepPacketInspectionList](apiv3.KindDeepPacketInspection, OrderEndpointsAndSets, bc, rt),
		migrators.New[apiv3.PacketCapture, apiv3.PacketCaptureList](apiv3.KindPacketCapture, OrderEndpointsAndSets, bc, rt),

		// Security — alerts, threat feeds, security event webhooks.
		migrators.New[apiv3.AlertException, apiv3.AlertExceptionList](apiv3.KindAlertException, OrderEnterpriseSecurity, bc, rt),
		migrators.New[apiv3.GlobalAlert, apiv3.GlobalAlertList](apiv3.KindGlobalAlert, OrderEnterpriseSecurity, bc, rt),
		migrators.New[apiv3.GlobalAlertTemplate, apiv3.GlobalAlertTemplateList](apiv3.KindGlobalAlertTemplate, OrderEnterpriseSecurity, bc, rt),
		migrators.New[apiv3.GlobalThreatFeed, apiv3.GlobalThreatFeedList](apiv3.KindGlobalThreatFeed, OrderEnterpriseSecurity, bc, rt),
		migrators.New[apiv3.SecurityEventWebhook, apiv3.SecurityEventWebhookList](apiv3.KindSecurityEventWebhook, OrderEnterpriseSecurity, bc, rt),

		// Reports — compliance reporting resources.
		migrators.New[apiv3.GlobalReport, apiv3.GlobalReportList](apiv3.KindGlobalReport, OrderEnterpriseReports, bc, rt),
		migrators.New[apiv3.GlobalReportType, apiv3.GlobalReportTypeList](apiv3.KindGlobalReportType, OrderEnterpriseReports, bc, rt),
		migrators.New[apiv3.PolicyRecommendationScope, apiv3.PolicyRecommendationScopeList](apiv3.KindPolicyRecommendationScope, OrderEnterpriseReports, bc, rt),

		// Management — multi-cluster resources.
		migrators.New[apiv3.ManagedCluster, apiv3.ManagedClusterList](apiv3.KindManagedCluster, OrderEnterpriseManagement, bc, rt),
		migrators.New[apiv3.RemoteClusterConfiguration, apiv3.RemoteClusterConfigurationList](apiv3.KindRemoteClusterConfiguration, OrderEnterpriseManagement, bc, rt),

		// UI settings.
		migrators.New[apiv3.UISettings, apiv3.UISettingsList](apiv3.KindUISettings, OrderEnterpriseUI, bc, rt),
		migrators.New[apiv3.UISettingsGroup, apiv3.UISettingsGroupList](apiv3.KindUISettingsGroup, OrderEnterpriseUI, bc, rt),
	}
}
