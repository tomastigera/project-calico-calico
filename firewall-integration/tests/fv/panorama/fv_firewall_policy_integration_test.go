// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package fv

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	panw "github.com/PaloAltoNetworks/pango"
	"github.com/PaloAltoNetworks/pango/objs/addr"
	"github.com/PaloAltoNetworks/pango/objs/srvc"
	dvgrp "github.com/PaloAltoNetworks/pango/pnrm/dg"
	"github.com/PaloAltoNetworks/pango/poli/security"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakeclientset "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/testing"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/firewall-integration/pkg/config"
	pan "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama"
	"github.com/projectcalico/calico/firewall-integration/pkg/util"
	panutilmocks "github.com/projectcalico/calico/firewall-integration/tests/mocks"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	defaultSecurityRulesValue1 = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='device_group1']/post-rulebase/default-security-rules"
	defaultSecurityRulesValue2 = "/config/shared/post-rulebase/default-security-rules"
	defaultSecurityRulesValue3 = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='shared']/post-rulebase/default-security-rules"
	defaultSecurityRulesValue4 = "/config/predefined/default-security-rules"
)

var _ = Describe("Tests policy integration controller", func() {
	var (
		apiserver *containers.Container

		ctx    context.Context
		cancel context.CancelFunc

		hl  *health.HealthAggregator
		cfg *config.Config

		k8sClient  *kubernetes.Clientset
		kubeconfig string

		wg sync.WaitGroup

		mockGnpList *v3.GlobalNetworkPolicyList
		tierLabels  map[string]string
	)

	Context("Tests policy integration controller", func() {
		// Define CERTS env.
		workingDir, err := os.Getwd()
		Expect(err).NotTo(HaveOccurred())
		certsDir := fmt.Sprintf("%s/../../certs", workingDir)
		err = os.Setenv("CERTS_PATH", certsDir)
		Expect(err).NotTo(HaveOccurred())

		BeforeEach(func() {
			By("Setting up controller configurations")
			apiserver = &containers.Container{IP: "127.0.0.2"}

			ctx, cancel = context.WithCancel(context.Background())

			var cancel func()
			kubeconfig, cancel = testutils.BuildKubeconfig(apiserver.IP)
			defer cancel()

			k8sClient, err = testutils.GetK8sClient(kubeconfig)
			Expect(err).NotTo(HaveOccurred())
			// Health setup.
			hl = health.NewHealthAggregator()
			hl.ServeHTTP(true, "0.0.0.0", 9099)

			cfg = &config.Config{EnabledControllers: "panorama-policy"}

			mockGnpList = &v3.GlobalNetworkPolicyList{}
			tierLabels = map[string]string{
				"projectcalico.org/system-tier": strconv.FormatBool(true),
			}
		})

		AfterEach(func() {
			By("Cleaning up after the test is complete")
			apiserver.Stop()
			_ = os.Remove(kubeconfig)
		})

		table.DescribeTable("test Panorama device group values",
			func(userInput, deviceGroup, tag, expectedFileName string) {
				By("setting the user defined device group")
				cfg.FwDeviceGroup = userInput

				By("defining the remaining controller configurations")
				cfg.FwPanoramaFilterTags = tag
				cfg.FwPolicyTier = "firewallpolicy"
				cfg.FwPolicyTierOrder = 101
				cfg.FwPollInterval = time.Millisecond * 1000

				By("loading the Panorama data")
				panClData, err := getMockPanoramaClientData()
				Expect(err).To(BeNil())

				By("defining the mock Panorama client")
				mockPanCl := &panutilmocks.MockPanoramaClient{}
				if deviceGroup != "shared" {
					mockPanCl.On("GetAddressEntries", "shared").Return([]addr.Entry{}, nil)
				}
				mockPanCl.On("GetAddressEntries", deviceGroup).Return(panClData.Addresses, nil)
				mockPanCl.On("GetAddressGroupEntries", deviceGroup).Return(panClData.AddressGroups, nil)
				mockPanCl.On("GetClient").Return(&panw.Panorama{})
				mockPanCl.On("GetDeviceGroupEntry", deviceGroup).Return(dvgrp.Entry{Name: deviceGroup}, nil)
				// Add the expected device group along with a couple of dummy device groups returned by GetDeviceGroups.
				deviceGroups := []string{deviceGroup, "device_group2", "device_group3"}
				mockPanCl.On("GetDeviceGroups").Return(deviceGroups, nil)
				mockPanCl.On("GetPostRulePolicies", deviceGroup).Return(panClData.Postrules, nil)
				mockPanCl.On("GetPreRulePolicies", deviceGroup).Return(panClData.Prerules, nil)
				mockPanCl.On("GetPreRulePolicies", "").Return([]security.Entry{}, nil)
				if deviceGroup != "shared" {
					mockPanCl.On("GetServiceEntries", "shared").Return([]srvc.Entry{}, nil)
				}
				mockPanCl.On("GetServiceEntries", deviceGroup).Return(panClData.Services, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue1, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue2, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue3, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue4, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("GetAddressGroups", "shared").Return([]string{"addressgroup1"}, nil)
				mockPanCl.On("GetAddressGroups", deviceGroup).Return([]string{""}, nil)

				By("defining the Calico client, with an empty datastore")
				mockTier := &v3.Tier{
					ObjectMeta: metav1.ObjectMeta{
						Name:   cfg.FwPolicyTier,
						Labels: tierLabels,
					},
					Spec: v3.TierSpec{
						Order: &cfg.FwPolicyTierOrder,
					},
				}
				fccl := fakeclientset.NewSimpleClientset(mockTier, mockGnpList).ProjectcalicoV3()

				By("defining the address groups controller")
				controller, err := pan.NewFirewallPolicyIntegrationController(ctx, k8sClient, fccl, mockPanCl, cfg, hl, &wg)
				Expect(err).To(BeNil())

				By("running the controller")
				wg.Add(1)
				go controller.Run()

				By("letting the controller run until syncing policies has finished")
				time.Sleep(time.Millisecond * 5000)
				cancel()
				wg.Wait()

				By("loading expected data")
				expectedGnpMap, err := getExpectedGnpMap(expectedFileName)
				Expect(err).To(BeNil())

				By("validating the list of global networks sets present in the datastore")

				gnpList, err := fccl.GlobalNetworkPolicies().List(ctx, metav1.ListOptions{})
				Expect(err).To(BeNil())
				Expect(len(gnpList.Items)).To(Equal(len(expectedGnpMap)))
				for _, gns := range gnpList.Items {
					Expect(gns.Annotations["firewall.tigera.io/object-type"]).To(Equal("Zone"))
					Expect(gns.Annotations["firewall.tigera.io/type"]).To(Equal("Panorama"))

					key := gns.Name
					Expect(gns.ObjectMeta.Name).To(Equal(expectedGnpMap[key].Name))
					Expect(gns.ObjectMeta.Labels).To(Equal(expectedGnpMap[key].Labels))
					Expect(gns.Spec.Egress).To(Equal(expectedGnpMap[key].Spec.Egress))
					Expect(gns.Spec.Ingress).To(Equal(expectedGnpMap[key].Spec.Ingress))
					Expect(gns.Spec.Tier).To(Equal(cfg.FwPolicyTier))
				}
			},
			table.Entry("should handle an empty value for a device group input", "", "shared", "tag2", "expectedGlobalNetworkPolicyMapTag2SharedRules1"),
			table.Entry("should handle the \"shared\" value for a device group input", "shared", "shared", "tag2", "expectedGlobalNetworkPolicyMapTag2SharedRules1"),
			table.Entry("should handle a value other than \"shared\" for a device group input", "device_group1", "device_group1", "tag2", "expectedGlobalNetworkPolicyMapTag2DeviceGroup1Rules1"),
		)

		It("should handle a device group that is not present in Panorama", func() {
			deviceGroup := "shared"
			expectedErrorMessage := "device group: \"device.group.not.present\" does not exist"

			By("setting the invalid device group")
			cfg.FwDeviceGroup = "device.group.not.present"

			By("defining the remaining controller configurations")
			cfg.FwPanoramaTags = "tag1"
			cfg.FwPolicyTier = "firewallpolicy"
			cfg.FwPolicyTierOrder = 101
			cfg.FwPollInterval = time.Millisecond * 1000

			By("loading the Panorama data")
			panClData, err := getMockPanoramaClientData()
			Expect(err).To(BeNil())

			By("defining the mock Panorama client")
			mockPanCl := &panutilmocks.MockPanoramaClient{}
			mockPanCl.On("GetAddressEntries", deviceGroup).Return(panClData.Addresses, nil)
			mockPanCl.On("GetAddressGroupEntries", deviceGroup).Return(panClData.AddressGroups, nil)
			mockPanCl.On("GetClient").Return(&panw.Panorama{})
			mockPanCl.On("GetDeviceGroupEntry", deviceGroup).Return(dvgrp.Entry{Name: deviceGroup}, nil)
			// Add the expected device group along with a couple of dummy device groups returned by GetDeviceGroups.
			deviceGroups := []string{"device_group1", "device_group2", "device_group3"}
			mockPanCl.On("GetDeviceGroups").Return(deviceGroups, nil)
			mockPanCl.On("GetPostRulePolicies", deviceGroup).Return(panClData.Postrules, nil)
			mockPanCl.On("GetPreRulePolicies", deviceGroup).Return(panClData.Prerules, nil)
			mockPanCl.On("GetPreRulePolicies", "").Return([]security.Entry{}, nil)
			mockPanCl.On("GetServiceEntries", deviceGroup).Return(panClData.Services, nil)
			mockPanCl.On("Get", defaultSecurityRulesValue1, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
			mockPanCl.On("Get", defaultSecurityRulesValue2, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
			mockPanCl.On("Get", defaultSecurityRulesValue3, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
			mockPanCl.On("Get", defaultSecurityRulesValue4, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
			mockPanCl.On("GetAddressGroups", "shared").Return([]string{"addressgroup1"}, nil)
			mockPanCl.On("GetAddressGroups", deviceGroup).Return([]string{""}, nil)

			By("defining the Calico client, with an empty datastore")
			mockTier := &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name:   cfg.FwPolicyTier,
					Labels: tierLabels,
				},
				Spec: v3.TierSpec{
					Order: &cfg.FwPolicyTierOrder,
				},
			}
			fccl := fakeclientset.NewSimpleClientset(mockTier, mockGnpList).ProjectcalicoV3()

			By("defining the address groups controller")
			_, err = pan.NewFirewallPolicyIntegrationController(ctx, k8sClient, fccl, mockPanCl, cfg, hl, &wg)

			By("verifying the firewall policy controller factory returns an error when it does not find a valid device group")
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(expectedErrorMessage))
		})

		table.DescribeTable("test Panorama filter values",
			func(userInput, deviceGroup, expectedFileName string) {
				By("setting the user defined filter")
				cfg.FwPanoramaFilterTags = userInput

				By("defining the remaining controller configurations")
				cfg.FwDeviceGroup = deviceGroup
				cfg.FwPolicyTier = "firewallpolicy"
				cfg.FwPolicyTierOrder = 101
				cfg.FwPollInterval = time.Millisecond * 1000

				By("loading the Panorama data")
				panClData, err := getMockPanoramaClientData()
				Expect(err).To(BeNil())

				By("defining the mock Panorama client")
				mockPanCl := &panutilmocks.MockPanoramaClient{}
				if deviceGroup != "shared" {
					mockPanCl.On("GetAddressEntries", "shared").Return([]addr.Entry{}, nil)
				}
				mockPanCl.On("GetAddressEntries", deviceGroup).Return(panClData.Addresses, nil)
				mockPanCl.On("GetAddressGroupEntries", deviceGroup).Return(panClData.AddressGroups, nil)
				mockPanCl.On("GetClient").Return(&panw.Panorama{})
				mockPanCl.On("GetDeviceGroupEntry", deviceGroup).Return(dvgrp.Entry{Name: deviceGroup}, nil)
				// Add the expected device group along with a couple of dummy device groups returned by GetDeviceGroups.
				deviceGroups := []string{deviceGroup, "device_group2", "device_group3"}
				mockPanCl.On("GetDeviceGroups").Return(deviceGroups, nil)
				mockPanCl.On("GetPostRulePolicies", deviceGroup).Return(panClData.Postrules, nil)
				mockPanCl.On("GetPreRulePolicies", deviceGroup).Return(panClData.Prerules, nil)
				mockPanCl.On("GetPreRulePolicies", "").Return([]security.Entry{}, nil)
				if deviceGroup != "shared" {
					mockPanCl.On("GetServiceEntries", "shared").Return([]srvc.Entry{}, nil)
				}
				mockPanCl.On("GetServiceEntries", deviceGroup).Return(panClData.Services, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue1, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue2, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue3, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue4, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("GetAddressGroups", "shared").Return([]string{"addressgroup1"}, nil)
				mockPanCl.On("GetAddressGroups", deviceGroup).Return([]string{""}, nil)

				By("defining the Calico client, with an empty datastore")
				mockTier := &v3.Tier{
					ObjectMeta: metav1.ObjectMeta{
						Name:   cfg.FwPolicyTier,
						Labels: tierLabels,
					},
					Spec: v3.TierSpec{
						Order: &cfg.FwPolicyTierOrder,
					},
				}
				fccl := fakeclientset.NewSimpleClientset(mockTier, mockGnpList).ProjectcalicoV3()

				By("defining the address groups controller")
				controller, err := pan.NewFirewallPolicyIntegrationController(ctx, k8sClient, fccl, mockPanCl, cfg, hl, &wg)
				Expect(err).To(BeNil())

				By("running the controller")
				wg.Add(1)
				go controller.Run()

				By("letting the controller run until syncing policies has finished")
				time.Sleep(time.Millisecond * 5000)
				cancel()
				wg.Wait()

				By("loading expected data")
				expectedGnpMap, err := getExpectedGnpMap(expectedFileName)
				Expect(err).To(BeNil())

				By("validating the list of global networks sets present in the datastore")
				gnpList, err := fccl.GlobalNetworkPolicies().List(ctx, metav1.ListOptions{})
				Expect(err).To(BeNil())
				Expect(len(gnpList.Items)).To(Equal(len(expectedGnpMap)))
				for _, gns := range gnpList.Items {
					Expect(gns.Annotations["firewall.tigera.io/object-type"]).To(Equal("Zone"))
					Expect(gns.Annotations["firewall.tigera.io/type"]).To(Equal("Panorama"))

					key := gns.Name
					Expect(gns.ObjectMeta.Name).To(Equal(expectedGnpMap[key].Name))
					Expect(gns.ObjectMeta.Labels).To(Equal(expectedGnpMap[key].Labels))
					Expect(gns.Spec.Egress).To(Equal(expectedGnpMap[key].Spec.Egress))
					Expect(gns.Spec.Ingress).To(Equal(expectedGnpMap[key].Spec.Ingress))
				}
			},
			table.Entry("should handle an empty filter", "", "shared", "expectedGlobalNetworkPolicyMapEmptyFilterSharedRules1"),
			table.Entry("should handle simple filter", "tag2", "shared", "expectedGlobalNetworkPolicyMapTag2SharedRules1"),
			table.Entry("should handle a complex filter", "tag1 AND tag2", "shared", "expectedGlobalNetworkPolicyMapTag1andTag2SharedRules1"),
			table.Entry("should handle a more complex filter value", "tag2 AND (tag5 OR tag3)", "shared", "expectedGlobalNetworkPolicyMapTag2andTag5orTag3SharedRules1"),
		)

		table.DescribeTable("test Panorama tier and tier order values",
			func(userInputTier string, userInputTierOrder float64, expectedFileName string) {
				deviceGroup := "shared"

				By("setting the user defined tier and order")
				cfg.FwPolicyTier = userInputTier
				cfg.FwPolicyTierOrder = userInputTierOrder

				By("defining the remaining controller configurations")
				cfg.FwDeviceGroup = deviceGroup
				cfg.FwPanoramaFilterTags = "tag2"
				cfg.FwPollInterval = time.Millisecond * 1000

				By("loading the Panorama data")
				panClData, err := getMockPanoramaClientData()
				Expect(err).To(BeNil())

				By("defining the mock Panorama client")
				mockPanCl := &panutilmocks.MockPanoramaClient{}
				mockPanCl.On("GetAddressEntries", deviceGroup).Return(panClData.Addresses, nil)
				mockPanCl.On("GetAddressGroupEntries", deviceGroup).Return(panClData.AddressGroups, nil)
				mockPanCl.On("GetClient").Return(&panw.Panorama{})
				mockPanCl.On("GetDeviceGroupEntry", deviceGroup).Return(dvgrp.Entry{Name: deviceGroup}, nil)
				// Add the expected device group along with a couple of dummy device groups returned by GetDeviceGroups.
				deviceGroups := []string{deviceGroup, "device_group2", "device_group3"}
				mockPanCl.On("GetDeviceGroups").Return(deviceGroups, nil)
				mockPanCl.On("GetPostRulePolicies", deviceGroup).Return(panClData.Postrules, nil)
				mockPanCl.On("GetPreRulePolicies", deviceGroup).Return(panClData.Prerules, nil)
				mockPanCl.On("GetPreRulePolicies", "").Return([]security.Entry{}, nil)
				mockPanCl.On("GetServiceEntries", deviceGroup).Return(panClData.Services, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue1, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue2, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue3, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("Get", defaultSecurityRulesValue4, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
				mockPanCl.On("GetAddressGroups", "shared").Return([]string{"addressgroup1"}, nil)
				mockPanCl.On("GetAddressGroups", deviceGroup).Return([]string{""}, nil)

				By("defining the Calico client, with an empty datastore")
				mockTier := &v3.Tier{
					ObjectMeta: metav1.ObjectMeta{
						Name:   cfg.FwPolicyTier,
						Labels: tierLabels,
					},
					Spec: v3.TierSpec{
						Order: &cfg.FwPolicyTierOrder,
					},
				}
				fccl := fakeclientset.NewSimpleClientset(mockTier, mockGnpList).ProjectcalicoV3()

				By("defining the address groups controller")
				controller, err := pan.NewFirewallPolicyIntegrationController(ctx, k8sClient, fccl, mockPanCl, cfg, hl, &wg)
				Expect(err).To(BeNil())

				By("running the controller")
				wg.Add(1)
				go controller.Run()

				By("letting the controller run until syncing policies has finished")
				time.Sleep(time.Millisecond * 5000)
				cancel()
				wg.Wait()

				By("loading expected data")
				expectedGnpMap, err := getExpectedGnpMap(expectedFileName)
				Expect(err).To(BeNil())

				By("validating the list of global networks sets present in the datastore")
				gnpList, err := fccl.GlobalNetworkPolicies().List(ctx, metav1.ListOptions{})
				Expect(err).To(BeNil())
				Expect(len(gnpList.Items)).To(Equal(len(expectedGnpMap)))
				for _, gns := range gnpList.Items {
					Expect(gns.Annotations["firewall.tigera.io/object-type"]).To(Equal("Zone"))
					Expect(gns.Annotations["firewall.tigera.io/type"]).To(Equal("Panorama"))

					key := gns.Name
					Expect(gns.ObjectMeta.Name).To(Equal(expectedGnpMap[key].Name))
					Expect(gns.ObjectMeta.Labels).To(Equal(expectedGnpMap[key].Labels))
					Expect(gns.Spec.Egress).To(Equal(expectedGnpMap[key].Spec.Egress))
					Expect(gns.Spec.Ingress).To(Equal(expectedGnpMap[key].Spec.Ingress))
				}
			},
			table.Entry("should handle defining a custom tier name and order value", "tier13", float64(13), "expectedGlobalNetworkPolicyMapTier13Tag2SharedRules1"),
		)

		It("should not issue updates when GNPs have not changed", func() {
			userInput := "device_group1"
			deviceGroup := "device_group1"
			tag := "tag2"

			By("setting the user defined device group")
			cfg.FwDeviceGroup = userInput

			By("defining the remaining controller configurations")
			cfg.FwPanoramaFilterTags = tag
			cfg.FwPolicyTier = "firewallpolicy"
			cfg.FwPolicyTierOrder = 101
			cfg.FwPollInterval = time.Millisecond * 250 // Decreased interval to ensure multiple cache reconciles.

			By("loading the Panorama data")
			panClData, err := getMockPanoramaClientData()
			Expect(err).To(BeNil())

			By("defining the mock Panorama client")
			mockPanCl := &panutilmocks.MockPanoramaClient{}
			mockPanCl.On("GetAddressEntries", "shared").Return([]addr.Entry{}, nil)
			mockPanCl.On("GetAddressEntries", deviceGroup).Return(panClData.Addresses, nil)
			mockPanCl.On("GetAddressGroupEntries", deviceGroup).Return(panClData.AddressGroups, nil)
			mockPanCl.On("GetClient").Return(&panw.Panorama{})
			mockPanCl.On("GetDeviceGroupEntry", deviceGroup).Return(dvgrp.Entry{Name: deviceGroup}, nil)
			// Add the expected device group along with a couple of dummy device groups returned by GetDeviceGroups.
			deviceGroups := []string{deviceGroup, "device_group2", "device_group3"}
			mockPanCl.On("GetDeviceGroups").Return(deviceGroups, nil)
			mockPanCl.On("GetPostRulePolicies", deviceGroup).Return(panClData.Postrules, nil)
			mockPanCl.On("GetPreRulePolicies", deviceGroup).Return(panClData.Prerules, nil)
			mockPanCl.On("GetPreRulePolicies", "").Return([]security.Entry{}, nil)
			mockPanCl.On("GetServiceEntries", "shared").Return([]srvc.Entry{}, nil)
			mockPanCl.On("GetServiceEntries", deviceGroup).Return(panClData.Services, nil)
			mockPanCl.On("Get", defaultSecurityRulesValue1, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
			mockPanCl.On("Get", defaultSecurityRulesValue2, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
			mockPanCl.On("Get", defaultSecurityRulesValue3, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
			mockPanCl.On("Get", defaultSecurityRulesValue4, &util.PredefinedSecurityRulesResponse{Rules: nil}).Return([]byte{}, nil)
			mockPanCl.On("GetAddressGroups", "shared").Return([]string{"addressgroup1"}, nil)
			mockPanCl.On("GetAddressGroups", deviceGroup).Return([]string{""}, nil)

			By("defining the Calico client, with an empty datastore")
			mockTier := &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name:   cfg.FwPolicyTier,
					Labels: tierLabels,
				},
				Spec: v3.TierSpec{
					Order: &cfg.FwPolicyTierOrder,
				},
			}
			baseClientSet := fakeclientset.NewSimpleClientset(mockTier, mockGnpList)
			fccl := baseClientSet.ProjectcalicoV3()

			By("defining the address groups controller")
			controller, err := pan.NewFirewallPolicyIntegrationController(ctx, k8sClient, fccl, mockPanCl, cfg, hl, &wg)
			Expect(err).To(BeNil())

			By("running the controller")
			wg.Add(1)
			go controller.Run()

			By("letting the controller run until syncing policies has finished")
			time.Sleep(time.Millisecond * 5000)
			cancel()
			wg.Wait()

			By("validating that globalnetworkpolicy update was never called")
			for _, action := range baseClientSet.Actions() {
				updateAction, ok := action.(testing.UpdateActionImpl)
				if ok {
					Expect(updateAction.GetResource().Resource).ToNot(Equal("globalnetworkpolicies"))
				}
			}
		})
	})
})
