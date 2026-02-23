// Copyright (c) 2021, 2023 Tigera, Inc. All rights reserved.

package eventgenerator_test

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/deep-packet-inspection/pkg/alert"
	cache2 "github.com/projectcalico/calico/deep-packet-inspection/pkg/cache"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/config"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/dpiupdater"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/eventgenerator"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

var _ = Describe("File Parser", func() {
	dpiName := "dpi-name"
	dpiNs := "dpi-ns"
	dpiKey := model.ResourceKey{
		Name:      dpiName,
		Namespace: dpiNs,
		Kind:      "DeepPacketInspection",
	}
	podName := "podname"
	podName2 := "podname2"
	wepKey := model.WorkloadEndpointKey{
		Hostname:       "127.0.0.1",
		OrchestratorID: "k8s",
		WorkloadID:     "dpi-ns/podname",
		EndpointID:     "eth0",
	}
	orgFile := "1_alert_fast.txt"
	expectedFile := "alert_fast.txt"
	elasticRetrySendInterval := 1 * time.Second
	ifaceName1 := "wepKey1-iface"

	var cfg *config.Config
	var ctx context.Context
	var mockForwarder *alert.MockForwarder
	var mockLinseedClient client.MockClient
	var mockDPIUpdater *dpiupdater.MockDPIStatusUpdater

	BeforeEach(func() {
		mockDPIUpdater = &dpiupdater.MockDPIStatusUpdater{}
		mockDPIUpdater.AssertExpectations(GinkgoT())
		mockLinseedClient = client.NewMockClient("")
		ctx = context.Background()
		mockForwarder = &alert.MockForwarder{}
		mockForwarder.AssertExpectations(GinkgoT())
		cfg = &config.Config{SnortAlertFileBasePath: "test"}

		// Cleanup
		path := fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName)
		_ = os.RemoveAll(path)
		_ = os.MkdirAll(path, os.ModePerm)

		path = fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName2)
		_ = os.RemoveAll(path)
		_ = os.MkdirAll(path, os.ModePerm)
	})

	AfterEach(func() {
		// Cleanup
		path := fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName)
		_ = os.RemoveAll(path)
		_ = os.MkdirAll(path, os.ModePerm)

		path = fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName2)
		_ = os.RemoveAll(path)
		_ = os.MkdirAll(path, os.ModePerm)
	})

	It("should start tailing alert file, parse and send it to Linseed", func() {
		// Copy and create an alert file
		path := fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName)
		copyAlertFile(path, orgFile, expectedFile)
		srcIP := "74.125.124.100"
		srcPort := int64(9090)
		destIP := "10.28.0.13"
		destPort := ""
		event := lsv1.Event{
			Time:          lsv1.NewEventTimestamp(1630343977),
			Type:          "deep_packet_inspection",
			Description:   "Deep Packet Inspection found a matching snort rule(s) for some packets in your network",
			Severity:      100,
			Origin:        "dpi.dpi-ns/dpi-name",
			AttackVector:  "Network",
			MitreTactic:   "n/a",
			MitreIDs:      &[]string{"n/a"},
			Mitigations:   &[]string{"n/a"},
			SourceIP:      &srcIP,
			SourcePort:    &srcPort,
			DestIP:        &destIP,
			DestName:      podName,
			DestNamespace: dpiNs,
			Host:          cfg.NodeName,
			Record:        lsv1.DPIRecord{SnortSignatureID: "1000005", SnortSignatureRevision: "1", SnortAlert: "21/08/30-17:19:37.337831 [**] [1:1000005:1] \"msg:1_alert_fast\" [**] [Priority: 0] {ICMP} 74.125.124.100:9090 -> 10.28.0.13"},
		}
		event.ID = fmt.Sprintf("%s_%s_1630343977337831000_%s_%d_%s_%s_%s", dpiKey.Namespace, dpiKey.Name, *event.SourceIP, srcPort, *event.DestIP, destPort, event.Host)
		mockForwarder.On("Forward", event).Return(nil).Times(1)

		// GenerateEventsForWEP should parse file and call elastic service.
		wepCache := cache2.NewWEPCache()
		wepCache.Update(bapi.UpdateTypeKVNew, model.KVPair{
			Key: wepKey,
			Value: &model.WorkloadEndpoint{
				IPv4Nets: []net.IPNet{mustParseNet("10.28.0.13/32")},
			},
		})
		r := eventgenerator.NewEventGenerator(cfg, mockForwarder, mockDPIUpdater, dpiKey, wepCache)
		r.GenerateEventsForWEP(wepKey)
		Eventually(func() int { return len(mockForwarder.Calls) }, 5*time.Second).Should(Equal(1))

		// StopGeneratingEventsForWEP should delete the alert file after parsing all alerts
		r.StopGeneratingEventsForWEP(wepKey)
		Eventually(func() error {
			_, err := os.Stat(fmt.Sprintf("%s/%s", path, expectedFile))
			return err
		}, 5*time.Second).Should(HaveOccurred())

		_, err := os.Stat(fmt.Sprintf("%s/%s", path, expectedFile))
		Expect(os.IsNotExist(err)).Should(BeTrue())
	})

	It("should stop tailing alert file on reaching EOF if snort is no longer running", func() {
		numberOfCalls := 14
		var mockResults []rest.MockResult
		for range numberOfCalls {
			mockResults = append(mockResults, rest.MockResult{
				Body: lsv1.BulkResponse{
					Total:     1,
					Succeeded: 1,
				},
			})
		}
		mockLinseedClient.SetResults(mockResults...)

		alertForwarder, err := alert.NewForwarder(mockLinseedClient, elasticRetrySendInterval, "cluster")
		alertForwarder.Run(ctx)
		Expect(err).ShouldNot(HaveOccurred())

		mockDPIUpdater.On("UpdateStatusWithError", mock.Anything, mock.Anything, true, mock.Anything).Return(nil).Times(1)

		// Copy and create an alert file
		path := fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName)
		copyAlertFile(path, "2_alert_fast.txt", expectedFile)

		wepCache := cache2.NewWEPCache()
		r := eventgenerator.NewEventGenerator(cfg, alertForwarder, mockDPIUpdater, dpiKey, wepCache)
		r.GenerateEventsForWEP(wepKey)

		// StopGeneratingEventsForWEP should delete the alert file after parsing all alerts
		r.StopGeneratingEventsForWEP(wepKey)
		Eventually(func() error {
			_, err := os.Stat(fmt.Sprintf("%s/%s", path, expectedFile))
			return err
		}, 1*time.Second).Should(HaveOccurred())

		_, err = os.Stat(fmt.Sprintf("%s/%s", path, expectedFile))
		Expect(os.IsNotExist(err)).Should(BeTrue())
	})

	It("should send pod name and namespace in Alert when available", func() {
		// Copy and create an alert file
		path := fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName)
		copyAlertFile(path, orgFile, expectedFile)
		cfg.NodeName = "node0"

		srcIP := "74.125.124.100"
		srcPort := int64(9090)
		destIP := "10.28.0.13"
		destPort := ""
		event := lsv1.Event{
			Time:          lsv1.NewEventTimestamp(1630343977),
			Type:          "deep_packet_inspection",
			Description:   "Deep Packet Inspection found a matching snort rule(s) for some packets in your network",
			Severity:      100,
			Origin:        "dpi.dpi-ns/dpi-name",
			AttackVector:  "Network",
			MitreTactic:   "n/a",
			MitreIDs:      &[]string{"n/a"},
			Mitigations:   &[]string{"n/a"},
			SourceIP:      &srcIP,
			SourcePort:    &srcPort,
			DestIP:        &destIP,
			DestName:      podName,
			DestNamespace: dpiNs,
			Host:          cfg.NodeName,
			Record:        lsv1.DPIRecord{SnortSignatureID: "1000005", SnortSignatureRevision: "1", SnortAlert: "21/08/30-17:19:37.337831 [**] [1:1000005:1] \"msg:1_alert_fast\" [**] [Priority: 0] {ICMP} 74.125.124.100:9090 -> 10.28.0.13"},
		}
		event.ID = fmt.Sprintf("%s_%s_1630343977337831000_%s_%d_%s_%s_%s", dpiKey.Namespace, dpiKey.Name, *event.SourceIP, srcPort, *event.DestIP, destPort, event.Host)
		mockForwarder.On("Forward", event).Return(nil).Times(1)

		wepCache := cache2.NewWEPCache()
		r := eventgenerator.NewEventGenerator(cfg, mockForwarder, mockDPIUpdater, dpiKey, wepCache)

		wepCache.Update(bapi.UpdateTypeKVNew,
			model.KVPair{
				Key: wepKey,
				Value: &model.WorkloadEndpoint{
					Name:     ifaceName1,
					IPv4Nets: []net.IPNet{mustParseNet("10.28.0.13/32")},
				},
			})
		r.GenerateEventsForWEP(wepKey)
		Eventually(func() int { return len(mockForwarder.Calls) }, 5*time.Second).Should(Equal(1))

		// StopGeneratingEventsForWEP should delete the alert file after parsing all alerts
		r.StopGeneratingEventsForWEP(wepKey)
		Eventually(func() error {
			_, err := os.Stat(fmt.Sprintf("%s/%s", path, expectedFile))
			return err
		}, 5*time.Second).Should(HaveOccurred())

		_, err := os.Stat(fmt.Sprintf("%s/%s", path, expectedFile))
		Expect(os.IsNotExist(err)).Should(BeTrue())
	})

	It("should send current pod name and namespace in Alert", func() {
		// Copy and create an alert file
		path := fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName)
		copyAlertFile(path, orgFile, expectedFile)
		cfg.NodeName = "node0"

		srcIP := "74.125.124.100"
		srcPort := int64(9090)
		destIP := "10.28.0.13"
		destPort := ""
		event1 := lsv1.Event{
			Time:          lsv1.NewEventTimestamp(1630343977),
			Type:          "deep_packet_inspection",
			Description:   "Deep Packet Inspection found a matching snort rule(s) for some packets in your network",
			Severity:      100,
			Origin:        "dpi.dpi-ns/dpi-name",
			AttackVector:  "Network",
			MitreTactic:   "n/a",
			MitreIDs:      &[]string{"n/a"},
			Mitigations:   &[]string{"n/a"},
			SourceIP:      &srcIP,
			SourcePort:    &srcPort,
			DestIP:        &destIP,
			DestName:      podName,
			DestNamespace: dpiNs,
			Host:          cfg.NodeName,
			Record:        lsv1.DPIRecord{SnortSignatureID: "1000005", SnortSignatureRevision: "1", SnortAlert: "21/08/30-17:19:37.337831 [**] [1:1000005:1] \"msg:1_alert_fast\" [**] [Priority: 0] {ICMP} 74.125.124.100:9090 -> 10.28.0.13"},
		}
		event1.ID = fmt.Sprintf("%s_%s_1630343977337831000_%s_%d_%s_%s_%s", dpiKey.Namespace, dpiKey.Name, *event1.SourceIP, srcPort, *event1.DestIP, destPort, event1.Host)

		event2 := lsv1.Event{
			Time:          lsv1.NewEventTimestamp(1630343977),
			Type:          "deep_packet_inspection",
			Description:   "Deep Packet Inspection found a matching snort rule(s) for some packets in your network",
			Severity:      100,
			Origin:        "dpi.dpi-ns/dpi-name",
			AttackVector:  "Network",
			MitreTactic:   "n/a",
			MitreIDs:      &[]string{"n/a"},
			Mitigations:   &[]string{"n/a"},
			SourceIP:      &srcIP,
			DestIP:        &destIP,
			DestNamespace: dpiNs,
			Host:          cfg.NodeName,
			Record:        lsv1.DPIRecord{SnortSignatureID: "1000005", SnortSignatureRevision: "1", SnortAlert: "21/08/30-17:19:37.337831 [**] [1:1000005:1] \"msg:1_alert_fast\" [**] [Priority: 0] {ICMP} 74.125.124.100:9090 -> 10.28.0.13"},
		}
		event2.ID = fmt.Sprintf("%s_%s_1630343977337831000_%s_%d_%s_%s_%s", dpiKey.Namespace, dpiKey.Name, *event2.SourceIP, srcPort, *event2.DestIP, destPort, event2.Host)

		numberOfCallsToSend := 0
		mockForwarder.On("Forward", mock.Anything).Run(
			func(args mock.Arguments) {
				defer GinkgoRecover()

				numberOfCallsToSend++
				logrus.Infof("Calling %d", numberOfCallsToSend)
				switch numberOfCallsToSend {
				case 1:
					Expect(args.Get(0).(lsv1.Event)).Should(BeEquivalentTo(event1))
				case 2:
					Expect(args.Get(0).(lsv1.Event)).Should(BeEquivalentTo(event2))
				}
			}).Return(nil, false, nil).Times(2)

		wepCache := cache2.NewWEPCache()
		r := eventgenerator.NewEventGenerator(cfg, mockForwarder, mockDPIUpdater, dpiKey, wepCache)

		wepCache.Update(bapi.UpdateTypeKVNew,
			model.KVPair{
				Key: wepKey,
				Value: &model.WorkloadEndpoint{
					Name:     ifaceName1,
					IPv4Nets: []net.IPNet{mustParseNet("10.28.0.13/32")},
				},
			})
		r.GenerateEventsForWEP(wepKey)

		// StopGeneratingEventsForWEP should delete the alert file after parsing all alerts
		r.StopGeneratingEventsForWEP(wepKey)
		Eventually(func() error {
			_, err := os.Stat(fmt.Sprintf("%s/%s", path, expectedFile))
			return err
		}, 5*time.Second).Should(HaveOccurred())

		_, err := os.Stat(fmt.Sprintf("%s/%s", path, expectedFile))
		Expect(os.IsNotExist(err)).Should(BeTrue())

		By("Deleting the WEP key sends podName and namespace as empty string")
		wepCache.Update(bapi.UpdateTypeKVDeleted,
			model.KVPair{
				Key: wepKey,
			})

		copyAlertFile(path, orgFile, expectedFile)

		r.GenerateEventsForWEP(wepKey)

		// StopGeneratingEventsForWEP should delete the alert file after parsing all alerts
		r.StopGeneratingEventsForWEP(wepKey)
		Eventually(func() error {
			_, err := os.Stat(fmt.Sprintf("%s/%s", path, expectedFile))
			return err
		}, 5*time.Second).Should(HaveOccurred())

		_, err = os.Stat(fmt.Sprintf("%s/%s", path, expectedFile))
		Expect(os.IsNotExist(err)).Should(BeTrue())
	})

	It("should handle multiple snorts producing alerts", func() {
		// Copy and create an alert file
		path1 := fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName)
		copyAlertFile(path1, orgFile, expectedFile)

		path2 := fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName2)
		copyAlertFile(path2, orgFile, expectedFile)

		wepKey2 := model.WorkloadEndpointKey{
			Hostname:       "127.0.0.1",
			OrchestratorID: "k8s",
			WorkloadID:     "dpi-ns/podname2",
			EndpointID:     "eth0",
		}

		mockForwarder.On("Forward", mock.Anything, mock.Anything, mock.Anything).Return(nil, false, nil).Times(2)
		wepCache := cache2.NewWEPCache()
		r := eventgenerator.NewEventGenerator(cfg, mockForwarder, mockDPIUpdater, dpiKey, wepCache)
		r.GenerateEventsForWEP(wepKey)
		r.GenerateEventsForWEP(wepKey2)

		Eventually(func() int { return len(mockForwarder.Calls) }, 5*time.Second).Should(Equal(2))

		// StopGeneratingEventsForWEP should delete the alert file after parsing all alerts
		r.Close()

		Eventually(func() error {
			_, err := os.Stat(fmt.Sprintf("%s/%s", path1, expectedFile))
			return err
		}, 5*time.Second).Should(HaveOccurred())

		_, err := os.Stat(fmt.Sprintf("%s/%s", path1, expectedFile))
		Expect(os.IsNotExist(err)).Should(BeTrue())

		Eventually(func() error {
			_, err := os.Stat(fmt.Sprintf("%s/%s", path2, expectedFile))
			return err
		}, 5*time.Second).Should(HaveOccurred())

		_, err = os.Stat(fmt.Sprintf("%s/%s", path2, expectedFile))
		Expect(os.IsNotExist(err)).Should(BeTrue())
	})

	It("should process all previous leftover files during startup", func() {
		numberOfCalls := 20
		var mockResults []rest.MockResult
		for range numberOfCalls {
			mockResults = append(mockResults, rest.MockResult{
				Body: lsv1.BulkResponse{
					Total:     1,
					Succeeded: 1,
				},
			})
		}
		mockLinseedClient.SetResults(mockResults...)

		alertForwarder, err := alert.NewForwarder(mockLinseedClient, elasticRetrySendInterval, "cluster")
		alertForwarder.Run(ctx)
		Expect(err).ShouldNot(HaveOccurred())

		mockDPIUpdater.On("UpdateStatusWithError", mock.Anything, mock.Anything, true, mock.Anything).Return(nil).Times(1)

		// Copy and create an alert file
		path1 := fmt.Sprintf("%s/%s/%s/%s", cfg.SnortAlertFileBasePath, dpiKey.Namespace, dpiKey.Name, podName)
		copyAlertFile(path1, orgFile, expectedFile)
		copyAlertFile(path1, "2_alert_fast.txt", "alert_fast.txt.1631063433")
		copyAlertFile(path1, "3_alert_fast.txt", "alert_fast.txt.1731063433")
		copyAlertFile(path1, "4_alert_fast.txt", "alert_fast.txt.1831063433")

		wepCache := cache2.NewWEPCache()
		r := eventgenerator.NewEventGenerator(cfg, alertForwarder, mockDPIUpdater, dpiKey, wepCache)
		r.GenerateEventsForWEP(wepKey)

		// StopGeneratingEventsForWEP should delete the alert file after parsing all alerts
		r.StopGeneratingEventsForWEP(wepKey)
		Eventually(func() error {
			if _, err := os.Stat(fmt.Sprintf("%s/%s", path1, expectedFile)); err != nil {
				return err
			} else if _, err := os.Stat(fmt.Sprintf("%s/%s", path1, "alert_fast.txt.1631063433")); err != nil {
				return err
			} else if _, err := os.Stat(fmt.Sprintf("%s/%s", path1, "alert_fast.txt.1731063433")); err != nil {
				return err
			} else if _, err := os.Stat(fmt.Sprintf("%s/%s", path1, "alert_fast.txt.1831063433")); err != nil {
				return err
			}
			return nil
		}, 5*time.Second).Should(HaveOccurred())

		_, err = os.Stat(fmt.Sprintf("%s/%s", path1, expectedFile))
		Expect(os.IsNotExist(err)).Should(BeTrue())
	})
})

func copyAlertFile(path, src, dst string) {
	input, err := os.ReadFile(fmt.Sprintf("test/data/%s", src))
	Expect(err).ShouldNot(HaveOccurred())
	err = os.WriteFile(fmt.Sprintf("%s/%s", path, dst), input, 0o644)
	Expect(err).ShouldNot(HaveOccurred())
}

func mustParseNet(n string) net.IPNet {
	_, cidr, err := net.ParseCIDR(n)
	Expect(err).ShouldNot(HaveOccurred())
	return *cidr
}
