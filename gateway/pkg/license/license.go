// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package license

import (
	"context"

	"github.com/sirupsen/logrus"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	lclient "github.com/projectcalico/calico/licensing/client"
	"github.com/projectcalico/calico/licensing/client/features"
	"github.com/projectcalico/calico/licensing/monitor"
)

type GatewayLicense interface {
	// This is a bool and not as enum as it captures the impact on the implementation
	// with respect to gateway functionality.
	// If we're in grace period (not captured at that level), then we mention that in the logs
	// but as far as behaviour is concerned, we treat it as licensed.
	IsLicensed() bool
}

type IngressGatewayLicenseMonitor struct {
	licenseMonitor        monitor.LicenseMonitor
	ingressGatewayEnabled bool
}

// NewIngressGatewayLicenseMonitor creates a new instance of IngressGatewayLicenseMonitor
func NewIngressGatewayLicenseMonitor() *IngressGatewayLicenseMonitor {
	return &IngressGatewayLicenseMonitor{}
}

// backendClientAccessor is an interface to access the backend client from the main v3 client.
type backendClientAccessor interface {
	Backend() bapi.Client
}

// InitializeLicenseMonitor sets up the license client and checks ingress-gateway feature status
func (m *IngressGatewayLicenseMonitor) InitializeLicenseMonitor() {
	logrus.Info("Initializing license monitor...")

	clientCalico, err := clientv3.NewFromEnv()
	if err != nil {
		logrus.WithError(err).Warn("Failed to create Calico client, license enforcement disabled")
		return
	}

	// Create license monitor using the backend client
	m.licenseMonitor = monitor.New(clientCalico.(backendClientAccessor).Backend())

	// Check initial license status for ingress-gateway feature
	ctx := context.Background()
	err = m.licenseMonitor.RefreshLicense(ctx)
	if err != nil {
		logrus.WithError(err).Warn("Failed to refresh license, license enforcement disabled")
		return
	}

	reportLicenseStatus := func(licenseStatus lclient.LicenseStatus) {
		// Check if ingress-gateway feature is enabled
		m.ingressGatewayEnabled = m.licenseMonitor.GetFeatureStatus(features.IngressGateway)

		logrus.WithFields(logrus.Fields{
			"ingress-gateway-enabled": m.ingressGatewayEnabled,
			"license-status":          licenseStatus.String(),
		}).Info("License status check complete")

		if !m.ingressGatewayEnabled {
			logrus.Warn("Ingress Gateway feature is not licensed - enterprise features will be disabled")
		} else {
			logrus.Info("Ingress Gateway feature is properly licensed - all features available")
		}
	}

	m.licenseMonitor.SetFeaturesChangedCallback(func() {
		licenseStatus := m.licenseMonitor.GetLicenseStatus()
		logrus.Info("License features changed, re-evaluating ingress-gateway feature status...")
		reportLicenseStatus(licenseStatus)
	})

	m.licenseMonitor.SetStatusChangedCallback(func(newLicenseStatus lclient.LicenseStatus) {
		logrus.Info("License status changed, re-evaluating ingress-gateway feature status...")
		reportLicenseStatus(newLicenseStatus)
	})

	// Start the license monitor, which will trigger the callback above at start of day and then whenever the license
	// status changes.
	go func() {
		err := m.licenseMonitor.MonitorForever(context.Background())
		if err != nil {
			logrus.WithError(err).Warn("Error while continuously monitoring the license.")
		}
	}()
}

func (m *IngressGatewayLicenseMonitor) IsLicensed() bool {
	return m.ingressGatewayEnabled
}

type FakeGatewayLicense struct {
	IsLicenseEnabled bool
}

func (m *FakeGatewayLicense) IsLicensed() bool {
	return m.IsLicenseEnabled
}
