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
	"github.com/PaloAltoNetworks/pango/objs/addrgrp"
	dvgrp "github.com/PaloAltoNetworks/pango/pnrm/dg"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakeclientset "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/firewall-integration/pkg/config"
	pan "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama"
	panutils "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/utils"
	panutilmocks "github.com/projectcalico/calico/firewall-integration/tests/mocks"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	pollingInterval = time.Millisecond * 100
)

var _ = Describe("Tests address groups controller", func() {
	var (
		apiserver *containers.Container

		ctx context.Context

		hl  *health.HealthAggregator
		cfg *config.Config

		k8sClient  *kubernetes.Clientset
		kubeconfig string

		wg sync.WaitGroup

		mockGnpList *v3.GlobalNetworkPolicyList
		tierLabels  map[string]string
	)

	Context("Tests address groups controller", func() {
		// Define CERTS env.
		workingDir, err := os.Getwd()
		Expect(err).NotTo(HaveOccurred())

		certsDir := fmt.Sprintf("%s/../../certs", workingDir)
		err = os.Setenv("CERTS_PATH", certsDir)
		Expect(err).NotTo(HaveOccurred())

		BeforeEach(func() {
			By("Setting up controller configurations")
			apiserver = &containers.Container{IP: "127.0.0.2"}

			ctx = context.Background()

			var cancel func()
			kubeconfig, cancel = testutils.BuildKubeconfig(apiserver.IP)
			defer cancel()

			k8sClient, err = testutils.GetK8sClient(kubeconfig)
			Expect(err).NotTo(HaveOccurred())
			// Health setup.
			hl = health.NewHealthAggregator()
			hl.ServeHTTP(true, "0.0.0.0", 9099)

			cfg = &config.Config{EnabledControllers: "panorama-address-groups"}

			mockGnpList = &v3.GlobalNetworkPolicyList{}
			tierLabels = map[string]string{
				"projectcalico.org/system-tier": strconv.FormatBool(true),
			}
		})

		AfterEach(func() {
			By("Cleaning up after the test is complete")
			apiserver.Stop()
			_ = os.Remove(kubeconfig)
			// Release wait group resources for the running go function.
			wg.Done()
		})

		table.DescribeTable("Test Panorama device group values",
			func(userInput, deviceGroup, tag, expectedFileName string) {
				By("setting the user defined device group")
				cfg.FwDeviceGroup = userInput

				By("defining the remaining controller configurations")
				cfg.FwPanoramaTags = tag
				cfg.FwPollInterval = pollingInterval

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
				fccl := fakeclientset.NewSimpleClientset(mockTier, mockGnpList).ProjectcalicoV3().GlobalNetworkSets()

				By("defining the address groups controller")
				controller, err := pan.NewDynamicAddressGroupsController(ctx, k8sClient, fccl, mockPanCl, cfg, hl, &wg)
				Expect(err).To(BeNil())

				By("running the controller")
				wg.Add(1)
				go controller.Run()

				By("letting the controller run for thrice its polling interval")
				time.Sleep(3 * pollingInterval)

				By("loading expected data")
				expectedGnsMap, err := getExpectedGnsMap(expectedFileName)
				Expect(err).To(BeNil())

				By("validating the list of global networks sets present in the datastore, and that the device group is shared")
				gnsList, err := fccl.List(ctx, metav1.ListOptions{})
				Expect(err).To(BeNil())
				Expect(len(gnsList.Items)).To(Equal(len(expectedGnsMap)))

				for _, gns := range gnsList.Items {
					Expect(gns.Annotations["firewall.tigera.io/device-groups"]).To(Equal(deviceGroup))
					key := gns.Name
					Expect(gns.ObjectMeta.Name).To(Equal(expectedGnsMap[key].Name))
					Expect(gns.ObjectMeta.Annotations).To(Equal(expectedGnsMap[key].Annotations))
					Expect(gns.ObjectMeta.Labels).To(Equal(expectedGnsMap[key].Labels))
					Expect(gns.Spec.Nets).To(Equal(expectedGnsMap[key].Spec.Nets))
					Expect(gns.Spec.AllowedEgressDomains).To(Equal(expectedGnsMap[key].Spec.AllowedEgressDomains))
				}
			},
			table.Entry("should handle an empty value for a device group input", "", "shared", "tag2", "expectedGlobalNetworkSetMapSharedAddressGroup1"),
			table.Entry("should handle the \"shared\" value for a device group input", "shared", "shared", "tag2", "expectedGlobalNetworkSetMapSharedAddressGroup1"),
			table.Entry("should handle a value other than \"shared\" for a device group input", "device_group1", "device_group1", "tag2", "expectedGlobalNetworkSetMapDeviceGroup1"),
		)

		It("should handle a device group that is not present in Panorama", func() {
			deviceGroup := "device.group.not.present"

			By("setting the device group configuration")
			cfg.FwDeviceGroup = deviceGroup

			By("defining the additional controller configurations")
			cfg.FwPanoramaTags = "tag2"
			cfg.FwPollInterval = pollingInterval

			By("loading the address data")
			var addrs []addr.Entry
			addrFileName := fmt.Sprintf("%s/%s", InputDataFolder, "addresses1.json")
			err = panutils.LoadData(addrFileName, &addrs)
			Expect(err).To(BeNil())

			By("loading the address group data")
			var addrgrps []addrgrp.Entry
			addrgrpsFileName := fmt.Sprintf("%s/%s", InputDataFolder, "addressGroups1.json")
			err = panutils.LoadData(addrgrpsFileName, &addrgrps)
			Expect(err).To(BeNil())

			By("defining the mock Panorama client")
			mockPanCl := &panutilmocks.MockPanoramaClient{}
			mockPanCl.On("GetAddressEntries", deviceGroup).Return(addrs, nil)
			mockPanCl.On("GetAddressGroupEntries", deviceGroup).Return(addrgrps, nil)
			mockPanCl.On("GetClient").Return(&panw.Panorama{})
			mockPanCl.On("GetDeviceGroupEntry", deviceGroup).Return(dvgrp.Entry{}, fmt.Errorf("device group: \"%s\" does not exist", deviceGroup))
			// Add the expected device group along with a couple of dummy dgs returned by GetDeviceGroups.
			deviceGroups := []string{"device_group1", "device_group2", "device_group3"}
			mockPanCl.On("GetDeviceGroups").Return(deviceGroups, nil)

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
			fccl := fakeclientset.NewSimpleClientset(mockTier, mockGnpList).ProjectcalicoV3().GlobalNetworkSets()

			expectedErrorMessage := "device group: \"device.group.not.present\" does not exist"

			By("defining the address groups controller")
			wg.Add(1)
			_, err := pan.NewDynamicAddressGroupsController(ctx, k8sClient, fccl, mockPanCl, cfg, hl, &wg)

			By("verifying the address groups controller factory returns an error when it does not find a valid device group")
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal(expectedErrorMessage))
		})

		table.DescribeTable("test Panorama address group tags",
			func(userInput, deviceGroup, tag, expectedFileName string) {
				By("setting the user defined tag(s) configuration")
				cfg.FwPanoramaTags = userInput

				By("defining the additional controller configurations")
				cfg.FwDeviceGroup = deviceGroup
				cfg.FwPollInterval = pollingInterval

				By("loading the Panorama data")
				panClData, err := getMockPanoramaClientData()
				Expect(err).To(BeNil())

				By("defining the mock Panorama client")
				mockPanCl := &panutilmocks.MockPanoramaClient{}
				mockPanCl.On("GetAddressEntries", deviceGroup).Return(panClData.Addresses, nil)
				mockPanCl.On("GetAddressGroupEntries", deviceGroup).Return(panClData.AddressGroups, nil)
				mockPanCl.On("GetClient").Return(&panw.Panorama{})
				mockPanCl.On("GetDeviceGroupEntry", deviceGroup).Return(dvgrp.Entry{Name: deviceGroup}, nil)
				// Add the expected device group along with a couple of dummy dgs returned by GetDeviceGroups.
				deviceGroups := []string{deviceGroup, "device_group2", "device_group3"}
				mockPanCl.On("GetDeviceGroups").Return(deviceGroups, nil)

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
				fccl := fakeclientset.NewSimpleClientset(mockTier, mockGnpList).ProjectcalicoV3().GlobalNetworkSets()

				By("defining the address groups controller")
				wg.Add(1)
				controller, err := pan.NewDynamicAddressGroupsController(ctx, k8sClient, fccl, mockPanCl, cfg, hl, &wg)
				Expect(err).To(BeNil())

				By("running the controller")
				go controller.Run()

				By("letting the controller run for twice its polling interval")
				time.Sleep(3 * pollingInterval)

				By("loading expected data")
				expectedGNSMap, err := getExpectedGnsMap(expectedFileName)
				if expectedFileName != "" {
					Expect(err).To(BeNil())
				}

				By("validating the list of global networks sets present in the datastore, and that the device group is shared")
				gnsList, err := fccl.List(ctx, metav1.ListOptions{})
				Expect(err).To(BeNil())
				Expect(len(gnsList.Items)).To(Equal(len(expectedGNSMap)))
				for _, gns := range gnsList.Items {
					Expect(gns.Annotations["firewall.tigera.io/device-groups"]).To(Equal("shared"))
					key := gns.Name
					Expect(gns.ObjectMeta.Name).To(Equal(expectedGNSMap[key].Name))
					Expect(gns.ObjectMeta.Annotations).To(Equal(expectedGNSMap[key].Annotations))
					Expect(gns.ObjectMeta.Labels).To(Equal(expectedGNSMap[key].Labels))
					Expect(gns.Spec.Nets).To(Equal(expectedGNSMap[key].Spec.Nets))
					Expect(gns.Spec.AllowedEgressDomains).To(Equal(expectedGNSMap[key].Spec.AllowedEgressDomains))
				}
			},
			table.Entry("should handle an empty value for the address group tag, and return an empty data set", "", "shared", "tag2", ""),
			table.Entry("should handle a valid address group tag ", "tag2", "shared", "tag2", "expectedGlobalNetworkSetMapSharedAddressGroup1"),
			table.Entry("should handle a complex address group tag ", "'8$`()5043jgfj$%#'", "shared", "tag2", "expectedGlobalNetworkSetMapComplexTag"),
			table.Entry("should handle multiple address group tags", "tag1, tag3", "shared", "tag2", "expectedGlobalNetworkSetMapTag1Tag3"),
		)

		// TODO(dimitrin): [EV-2243] Revise test case approach and add back the test to verify that no
		//                 changes occur unless the panorama data source has been updated. The tests
		//                 would address fix for [EV-1993].
		// It("should update the data-source when values are added (or updated) in Panorama but should maintain the data-source static otherwise", func() {
		// 	deviceGroup := "shared"

		// 	By("defining the controller configurations")
		// 	cfg.FwDeviceGroup = deviceGroup
		// 	cfg.FwPanoramaTags = "tag2"
		// 	cfg.FwPollInterval = pollingInterval

		// 	By("loading the address data")
		// 	var addrs []addr.Entry
		// 	addrFileName := fmt.Sprintf("%s/%s", InputDataFolder, "addresses1.json")
		// 	panutils.LoadData(addrFileName, &addrs)

		// 	By("loading the address group data")
		// 	var addrgrps []addrgrp.Entry
		// 	addrgrpsFileName := fmt.Sprintf("%s/%s", InputDataFolder, "addressGroups1.json")
		// 	panutils.LoadData(addrgrpsFileName, &addrgrps)

		// 	By("defining the mock Panorama client")
		// 	mockPanCl := &panutilmocks.MockPanoramaClient{}
		// 	mockPanCl.On("GetAddressEntries", deviceGroup).Return(addrs, nil)
		// 	mockPanCl.On("GetAddressGroupEntries", deviceGroup).Return(addrgrps, nil)
		// 	mockPanCl.On("GetClient").Return(&panw.Panorama{})
		// 	mockPanCl.On("GetDeviceGroupEntry", deviceGroup).Return(dvgrp.Entry{Name: deviceGroup}, nil)

		// 	By("defining the Calico client, with an empty datastore")
		// 	mockTier := &v3.Tier{
		// 		ObjectMeta: metav1.ObjectMeta{
		// 			Name:   cfg.FwPolicyTier,
		// 			Labels: tierLabels,
		// 		},
		// 		Spec: v3.TierSpec{
		// 			Order: &cfg.FwPolicyTierOrder,
		// 		},
		// 	}
		// 	fccl := fakeclientset.NewSimpleClientset(mockTier, mockGnpList).ProjectcalicoV3()

		// 	By("defining the address groups controller")
		// 	controller, err := pan.NewDynamicAddressGroupsController(ctx, k8sClient, fccl, mockPanCl, cfg, hl, &wg)
		// 	Expect(err).To(BeNil())

		// 	By("running the controller")
		// 	wg.Add(1)
		// 	go controller.Run()

		// 	By("letting the controller run for twice its polling interval")
		// 	time.Sleep(2 * pollingInterval)

		// 	// Get the timestamp of the latest data store update.
		// 	calicoClientUpdateTimestamp := ccl.GnsClient.Timestamp

		// 	By("validating the list of global networks sets present in the datastore")
		// 	gnsList, err := fccl.GlobalNetworkSets().List(ctx, metav1.ListOptions{})
		// 	Expect(err).To(BeNil())

		// 	By("loading expectedGlobalNetworkSetMapSharedAddressGroup1 data")
		// 	var expectedGNSMap map[string]v3.GlobalNetworkSet
		// 	file := fmt.Sprintf("%s/%s/%s.json", expectedGnsDataFolder, gnsFolderName, "expectedGlobalNetworkSetMapSharedAddressGroup1")
		// 	panutils.LoadData(file, &expectedGNSMap)

		// 	By("validating the global networks set list is expected")
		// 	Expect(len(gnsList.Items)).To(Equal(len(expectedGNSMap)))
		// 	for _, gns := range gnsList.Items {
		// 		key := gns.ObjectMeta.Name
		// 		Expect(gns.ObjectMeta.Name).To(Equal(expectedGNSMap[key].Name))
		// 		Expect(gns.ObjectMeta.Annotations).To(Equal(expectedGNSMap[key].Annotations))
		// 		Expect(gns.ObjectMeta.Labels).To(Equal(expectedGNSMap[key].Labels))
		// 		Expect(gns.Spec.Nets).To(Equal(expectedGNSMap[key].Spec.Nets))
		// 		Expect(gns.Spec.AllowedEgressDomains).To(Equal(expectedGNSMap[key].Spec.AllowedEgressDomains))
		// 	}

		// 	By("loading a new set of addresses groups")
		// 	addrgrpsFileName = fmt.Sprintf("%s/%s", InputDataFolder, "addressGroups2.json")
		// 	panutils.LoadData(addrgrpsFileName, &addrgrps)

		// 	By("letting the controller run for twice its polling interval")
		// 	time.Sleep(2 * pollingInterval)

		// 	By("validating the new list of global networks sets present in the datastore")
		// 	gnsList, err = fccl.GlobalNetworkSets().List(ctx, metav1.ListOptions{})
		// 	Expect(err).To(BeNil())

		// 	By("verifying the calico client update function was called after the Panorama address groups were updated")
		// 	Expect(ccl.GnsClient.Timestamp - calicoClientUpdateTimestamp).NotTo(BeZero())

		// 	By("loading expectedGlobalNetworkSetMapSharedAddressGroup2 data")
		// 	var expectedUpdatedAddressGroup2GNSMap map[string]v3.GlobalNetworkSet
		// 	file = fmt.Sprintf("%s/%s/%s.json", expectedGnsDataFolder, gnsFolderName, "expectedGlobalNetworkSetMapSharedAddressGroup2")
		// 	panutils.LoadData(file, &expectedUpdatedAddressGroup2GNSMap)

		// 	By("validating the global networks set list is expected")
		// 	Expect(len(gnsList.Items)).To(Equal(len(expectedUpdatedAddressGroup2GNSMap)))
		// 	for _, gns := range gnsList.Items {
		// 		key := gns.ObjectMeta.Name
		// 		Expect(gns.ObjectMeta.Name).To(Equal(expectedUpdatedAddressGroup2GNSMap[key].Name))
		// 		Expect(gns.ObjectMeta.Annotations).To(Equal(expectedUpdatedAddressGroup2GNSMap[key].Annotations))
		// 		Expect(gns.ObjectMeta.Labels).To(Equal(expectedUpdatedAddressGroup2GNSMap[key].Labels))
		// 		Expect(gns.Spec.Nets).To(Equal(expectedUpdatedAddressGroup2GNSMap[key].Spec.Nets))
		// 		Expect(gns.Spec.AllowedEgressDomains).To(Equal(expectedUpdatedAddressGroup2GNSMap[key].Spec.AllowedEgressDomains))
		// 	}
		// })
	})
})
