// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

package capture_test

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/capture"
	"github.com/projectcalico/calico/felix/proto"
)

var _ = Describe("PacketCapture Capture Tests", func() {
	const podName = "test"
	const deviceName = "eth0"
	const namespace = "ns"
	const name = "capture"

	var currentOrderTwoFileSizeOnePacket = outputFile{
		Name:  fmt.Sprintf("%s_%s.pcap", podName, deviceName),
		Size:  capture.GlobalHeaderLen + dummyPacketDataSize() + capture.PacketInfoLen,
		Order: 2,
	}
	var currentOrderTwoFileSizeTwoPackets = outputFile{
		Name:  fmt.Sprintf("%s_%s.pcap", podName, deviceName),
		Size:  capture.GlobalHeaderLen + 2*(dummyPacketDataSize()+capture.PacketInfoLen),
		Order: 2,
	}

	var currentFileOrderOneSizeFivePackets = outputFile{
		Name:  fmt.Sprintf("%s_%s.pcap", podName, deviceName),
		Size:  capture.GlobalHeaderLen + 5*(dummyPacketDataSize()+capture.PacketInfoLen),
		Order: 1,
	}

	var rotatedFileOrderOneSizeOnePacket = outputFile{
		Name:  fmt.Sprintf("%s_%s.[\\d]+.pcap", podName, deviceName),
		Size:  capture.GlobalHeaderLen + dummyPacketDataSize() + capture.PacketInfoLen,
		Order: 1,
	}

	var rotatedFileOrderZeroSizeOnePacket = outputFile{
		Name:  fmt.Sprintf("%s_%s.[\\d]+.pcap", podName, deviceName),
		Size:  capture.GlobalHeaderLen + dummyPacketDataSize() + capture.PacketInfoLen,
		Order: 0,
	}

	var rotatedFileOrderZeroSizeFivePackets = outputFile{
		Name:  fmt.Sprintf("%s_%s.[\\d]+.pcap", podName, deviceName),
		Size:  capture.GlobalHeaderLen + 5*(dummyPacketDataSize()+capture.PacketInfoLen),
		Order: 0,
	}

	var baseDir string
	var captureDir string

	BeforeEach(func() {
		defer GinkgoRecover()

		var err error

		baseDir, err = os.MkdirTemp("/tmp", "pcap-tests")
		Expect(err).NotTo(HaveOccurred())
		captureDir = fmt.Sprintf("%s/%s/%s", baseDir, namespace, name)
	})

	AfterEach(func() {
		defer GinkgoRecover()

		var err = os.RemoveAll(baseDir)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Writes 1 packet in a pcap file", func(done Done) {
		defer close(done)
		var wg sync.WaitGroup
		var err error
		var numberOfPackets = 1
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap capture.PcapFile
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates)
		defer pcap.Done()

		// Capture listens to incoming packets
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Write 1 packet
		wg.Add(numberOfPackets)
		go func() {
			var packet = dummyPacket()

			packets <- packet
			wg.Done()
		}()

		// Wait for all the packets to be written to file
		wg.Wait()

		// Define expected files
		var expectedFiles = []outputFile{
			currentOrderTwoFileSizeOnePacket,
		}

		// Assert written files on disk
		assertPcapFiles(captureDir, expectedFiles)

		// Assert that an update was sent
		var waitingForTrafficUpdate *proto.PacketCaptureStatusUpdate
		var capturingUpdate *proto.PacketCaptureStatusUpdate
		Eventually(updates).Should(Receive(&waitingForTrafficUpdate))
		Eventually(updates).Should(Receive(&capturingUpdate))
		assertStatusUpdates(waitingForTrafficUpdate, []outputFile{}, namespace, name, proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(capturingUpdate, expectedFiles, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
	}, 10)

	It("Writes 10 packet in a pcap file", func(done Done) {
		defer close(done)
		var wg sync.WaitGroup
		var err error
		var numberOfPackets = 10
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap capture.PcapFile
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates)
		defer pcap.Done()

		// Capture listens to incoming packets
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Write 10 packets
		wg.Add(numberOfPackets)
		go func() {

			for i := 0; i < numberOfPackets; i++ {
				packet := dummyPacket()

				packets <- packet
				wg.Done()
			}
		}()

		// Wait for all the packets to be written to file
		wg.Wait()

		// Define expected files
		var expectedFiles = []outputFile{
			{
				Name: fmt.Sprintf("%s_%s.pcap", podName, deviceName),
				Size: capture.GlobalHeaderLen + numberOfPackets*(dummyPacketDataSize()+capture.PacketInfoLen),
			},
		}

		// Assert written files on disk
		assertPcapFiles(captureDir, expectedFiles)

		// Assert that an update was sent
		var waitingForTrafficUpdate *proto.PacketCaptureStatusUpdate
		var capturingUpdate *proto.PacketCaptureStatusUpdate
		Eventually(updates).Should(Receive(&waitingForTrafficUpdate))
		Eventually(updates).Should(Receive(&capturingUpdate))
		assertStatusUpdates(waitingForTrafficUpdate, []outputFile{}, namespace, name, proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(capturingUpdate, expectedFiles, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
	}, 10)

	It("Rotates pcap files using size", func(done Done) {
		defer close(done)
		var wg sync.WaitGroup
		var err error
		var numberOfPackets = 3
		var maxSize = capture.GlobalHeaderLen + (dummyPacketDataSize() + capture.PacketInfoLen)
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap capture.PcapFile
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates,
			capture.WithMaxSizeBytes(maxSize))
		defer pcap.Done()

		// Capture listens to incoming packets
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Write 10 packets
		wg.Add(numberOfPackets)
		go func() {
			for i := 0; i < numberOfPackets; i++ {
				packet := dummyPacket()

				packets <- packet
				wg.Done()
			}
		}()

		// Wait for all the packets to be written to file
		wg.Wait()

		// Define expected files
		var expectedFiles = []outputFile{
			currentOrderTwoFileSizeOnePacket,
			rotatedFileOrderOneSizeOnePacket,
			rotatedFileOrderZeroSizeOnePacket,
		}

		// Assert written files on disk
		assertPcapFiles(captureDir, expectedFiles)

		// Assert that three updates were sent
		var update = make([]*proto.PacketCaptureStatusUpdate, 4)
		Eventually(updates).Should(Receive(&update[0]))
		Eventually(updates).Should(Receive(&update[1]))
		Eventually(updates).Should(Receive(&update[2]))
		Eventually(updates).Should(Receive(&update[3]))
		assertStatusUpdates(update[0], []outputFile{}, namespace, name, proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(update[1], []outputFile{currentOrderTwoFileSizeOnePacket}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
		assertStatusUpdates(update[2], []outputFile{currentOrderTwoFileSizeOnePacket, rotatedFileOrderOneSizeOnePacket}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
		assertStatusUpdates(update[3], expectedFiles, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
	}, 10)

	It("Rotates pcap files using time", func(done Done) {
		defer close(done)
		var wg sync.WaitGroup
		var err error
		var maxAge = 1

		var timeChan = make(chan time.Time)
		var ticker = &time.Ticker{C: timeChan}
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap capture.PcapFile
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName,
			updates,
			capture.WithRotationSeconds(maxAge),
			capture.WithTicker(ticker),
		)
		defer pcap.Done()

		// Capture listens to incoming packets
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		wg.Add(1)
		go func() {
			packet := dummyPacket()

			// Write 1 packet and invoke time rotation
			packets <- packet
			timeChan <- time.Now()

			// Write 1 packet and invoke time rotation
			packets <- packet
			time.Sleep(time.Duration(maxAge) * time.Second)
			timeChan <- time.Now()

			// Write 1 packet to flush data being written to current pcap file
			packets <- packet

			wg.Done()
		}()

		// Wait for all the packets to be written to file
		wg.Wait()

		// Assert written files on disk
		assertPcapFiles(captureDir, []outputFile{
			currentOrderTwoFileSizeOnePacket,
			rotatedFileOrderOneSizeOnePacket,
			rotatedFileOrderZeroSizeOnePacket,
		})

		// Assert that three updates were sent
		var update = make([]*proto.PacketCaptureStatusUpdate, 4)
		Eventually(updates).Should(Receive(&update[0]))
		Eventually(updates).Should(Receive(&update[1]))
		Eventually(updates).Should(Receive(&update[2]))
		Eventually(updates).Should(Receive(&update[3]))
		assertStatusUpdates(update[0], []outputFile{}, namespace, name, proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(update[1], []outputFile{currentOrderTwoFileSizeOnePacket}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
		assertStatusUpdates(update[2], []outputFile{
			currentOrderTwoFileSizeOnePacket,
			rotatedFileOrderOneSizeOnePacket}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
		assertStatusUpdates(update[3], []outputFile{
			currentOrderTwoFileSizeOnePacket,
			rotatedFileOrderOneSizeOnePacket,
			rotatedFileOrderZeroSizeOnePacket}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
	}, 10)

	It("No pcap file will be written until first packet", func(done Done) {
		defer close(done)
		var err error
		var maxAge = 1
		var timeChan = make(chan time.Time)
		var ticker = &time.Ticker{C: timeChan}
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap capture.PcapFile
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName,
			updates,
			capture.WithRotationSeconds(maxAge),
			capture.WithTicker(ticker),
		)
		defer pcap.Done()

		// Capture listens to incoming packets
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		// wait for time rotation to be invoked
		timeChan <- time.Now()

		// Assert that an update was sent
		var update *proto.PacketCaptureStatusUpdate
		Eventually(updates).Should(Receive(&update))
		assertStatusUpdates(update, []outputFile{}, namespace, name, proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
	}, 10)

	It("Invoke size rotation before time rotation in a stream of data", func(done Done) {
		defer close(done)
		var wg sync.WaitGroup
		var err error
		var maxAge = 1
		var numberOfPackets = 10
		var half = numberOfPackets / 2
		var maxSize = capture.GlobalHeaderLen + half*(dummyPacketDataSize()+capture.PacketInfoLen)
		var timeChan = make(chan time.Time)
		var ticker = &time.Ticker{C: timeChan}

		// Initialise a new capture
		var pcap capture.PcapFile
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		pcap = capture.NewRotatingPcapFile(baseDir, "", "", podName, deviceName,
			make(chan interface{}, 100),
			capture.WithRotationSeconds(maxAge),
			capture.WithMaxSizeBytes(maxSize),
			capture.WithTicker(ticker),
		)
		defer pcap.Done()

		// Capture listens to incoming packets
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		wg.Add(numberOfPackets)
		go func() {
			packet := dummyPacket()

			for i := 0; i < half; i++ {
				packets <- packet
				wg.Done()
			}

			packets <- packet
			wg.Done()
			timeChan <- time.Now()

			for i := 0; i < half-1; i++ {
				packets <- packet
				wg.Done()
			}
		}()

		// Wait for all the packets to be written to file
		wg.Wait()

		assertPcapFiles(baseDir, []outputFile{
			{
				Name:  fmt.Sprintf("%s_%s.pcap", podName, deviceName),
				Size:  capture.GlobalHeaderLen + half*(dummyPacketDataSize()+capture.PacketInfoLen),
				Order: 1,
			},
			{
				Name:  fmt.Sprintf("%s_%s.[\\d]+.pcap", podName, deviceName),
				Size:  capture.GlobalHeaderLen + half*(dummyPacketDataSize()+capture.PacketInfoLen),
				Order: 0,
			},
		})
	}, 10)

	It("Invoke time rotation before size rotation in a stream of data", func(done Done) {
		defer close(done)
		var wg sync.WaitGroup
		var err error
		var maxAge = 1
		var numberOfPackets = 10
		var half = numberOfPackets / 2
		var maxSize = capture.GlobalHeaderLen + half*(dummyPacketDataSize()+capture.PacketInfoLen)
		var timeChan = make(chan time.Time)
		var ticker = &time.Ticker{C: timeChan}
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap capture.PcapFile
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName,
			updates,
			capture.WithRotationSeconds(maxAge),
			capture.WithMaxSizeBytes(maxSize),
			capture.WithTicker(ticker),
		)
		defer pcap.Done()

		// Capture listens to incoming packets
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		wg.Add(numberOfPackets)
		go func() {
			packet := dummyPacket()

			for i := 0; i < half; i++ {
				packets <- packet
				wg.Done()
			}

			timeChan <- time.Now()
			packets <- packet
			wg.Done()

			for i := 0; i < half-1; i++ {
				packets <- packet
				wg.Done()
			}
		}()

		// Wait for all the packets to be written to file
		wg.Wait()

		// Assert written files on disk
		assertPcapFiles(captureDir, []outputFile{
			currentFileOrderOneSizeFivePackets,
			rotatedFileOrderZeroSizeFivePackets,
		})
		// Assert that two updates were sent
		var update = make([]*proto.PacketCaptureStatusUpdate, 3)
		Eventually(updates).Should(Receive(&update[0]))
		Eventually(updates).Should(Receive(&update[1]))
		Eventually(updates).Should(Receive(&update[2]))
		assertStatusUpdates(update[0], []outputFile{}, namespace, name, proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(update[1], []outputFile{currentFileOrderOneSizeFivePackets}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
		assertStatusUpdates(update[2], []outputFile{
			currentFileOrderOneSizeFivePackets,
			rotatedFileOrderZeroSizeFivePackets}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
	}, 10)

	It("Keeps latest files", func(done Done) {
		defer close(done)
		var wg sync.WaitGroup
		var err error
		var numberOfPackets = 10
		var maxSize = capture.GlobalHeaderLen + (dummyPacketDataSize() + capture.PacketInfoLen)
		var maxFiles = 2
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap capture.PcapFile
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName,
			updates,
			capture.WithMaxFiles(maxFiles),
			capture.WithMaxSizeBytes(maxSize),
		)
		defer pcap.Done()

		// Capture listens to incoming packets
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Write 10 packets
		// We set the max size to one packet and want to keep only 3 files
		wg.Add(numberOfPackets)
		go func() {
			for i := 0; i < numberOfPackets; i++ {
				packet := dummyPacket()

				packets <- packet
				wg.Done()
			}
		}()

		// Wait for all the packets to be written to file
		wg.Wait()

		// Assert written files on disk
		assertPcapFiles(captureDir, []outputFile{
			currentOrderTwoFileSizeOnePacket,
			rotatedFileOrderOneSizeOnePacket,
			rotatedFileOrderZeroSizeOnePacket,
		})

		// Assert that three updates were sent
		var update = make([]*proto.PacketCaptureStatusUpdate, 11)
		for i := 0; i < numberOfPackets; i++ {
			Eventually(updates).Should(Receive(&update[i]))
		}

		assertStatusUpdates(update[0], []outputFile{}, namespace, name, proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(update[1], []outputFile{currentOrderTwoFileSizeOnePacket}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
		assertStatusUpdates(update[2], []outputFile{
			currentOrderTwoFileSizeOnePacket,
			rotatedFileOrderOneSizeOnePacket}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
		for i := 3; i < numberOfPackets; i++ {
			assertStatusUpdates(update[i], []outputFile{
				currentOrderTwoFileSizeOnePacket,
				rotatedFileOrderOneSizeOnePacket,
				rotatedFileOrderZeroSizeOnePacket}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
		}

	}, 20)

	It("Start a capture after it has been stopped", func(done Done) {
		defer close(done)

		var err error
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates)

		// Capture listens to incoming packets
		var packets1 = make(chan gopacket.Packet)
		defer close(packets1)
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets1)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Write 1 packet
		packet := dummyPacket()
		packets1 <- packet

		pcap.Done()

		assertPcapFiles(captureDir, []outputFile{
			currentOrderTwoFileSizeOnePacket,
		})
		// Assert that an update was sent
		var updateOne = make([]*proto.PacketCaptureStatusUpdate, 2)
		Eventually(updates).Should(Receive(&updateOne[0]))
		Eventually(updates).Should(Receive(&updateOne[1]))
		assertStatusUpdates(updateOne[0], []outputFile{}, namespace, name,
			proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(updateOne[1], []outputFile{
			currentOrderTwoFileSizeOnePacket,
		}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)

		// open another packet with the same base name
		var pcap2 = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates)
		// Write again
		var packets2 = make(chan gopacket.Packet)
		defer close(packets2)
		go func() {
			defer GinkgoRecover()

			err = pcap2.Write(packets2)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Write 1 packet
		packets2 <- packet
		defer pcap2.Done()

		assertPcapFiles(captureDir, []outputFile{
			currentOrderTwoFileSizeTwoPackets,
		})
		// Assert that an update was sent
		var updateTwo = make([]*proto.PacketCaptureStatusUpdate, 2)
		Eventually(updates).Should(Receive(&updateTwo[0]))
		Eventually(updates).Should(Receive(&updateTwo[1]))
		assertStatusUpdates(updateTwo[0], []outputFile{
			currentOrderTwoFileSizeTwoPackets,
		}, namespace, name, proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(updateTwo[1], []outputFile{
			currentOrderTwoFileSizeTwoPackets,
		}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
	}, 10)

	It("Close capture after write channel has been stopped", func(done Done) {
		defer close(done)
		var err error
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates)

		// Capture listens to incoming packets
		var packets = make(chan gopacket.Packet)
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Write 1 packet
		packet := dummyPacket()
		packets <- packet

		close(packets)
		pcap.Done()

		assertPcapFiles(captureDir, []outputFile{
			currentOrderTwoFileSizeOnePacket,
		})
		// Assert that an update was sent
		var waitingForTrafficUpdate *proto.PacketCaptureStatusUpdate
		var capturingUpdate *proto.PacketCaptureStatusUpdate
		Eventually(updates).Should(Receive(&waitingForTrafficUpdate))
		Eventually(updates).Should(Receive(&capturingUpdate))
		assertStatusUpdates(waitingForTrafficUpdate, []outputFile{}, namespace, name,
			proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(capturingUpdate, []outputFile{
			currentOrderTwoFileSizeOnePacket,
		}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
	}, 10)

	It("Writes packets after it has been stopped", func(done Done) {
		defer close(done)

		var err error
		var wg sync.WaitGroup

		// Initialise a new capture
		var pcap = capture.NewRotatingPcapFile(baseDir, "", "", podName, deviceName, make(chan interface{}, 100))

		// Capture listens to incoming packets
		var packets = make(chan gopacket.Packet)
		defer close(packets)

		wg.Add(1)
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
			wg.Done()
		}()

		packet := dummyPacket()

		// Write 1 packet
		packets <- packet

		// Close the capture
		pcap.Done()

		// Wait for Write to complete
		wg.Wait()

		// Call write a second time
		err = pcap.Write(packets)
		// Expect an error to be returned
		Expect(err).To(HaveOccurred())

	}, 10)

	It("Provides an update containing previously written files", func(done Done) {
		defer close(done)
		var wg sync.WaitGroup
		var err error
		var numberOfPackets = 1
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Write a pcap file in order to simulate a previous capture
		err = os.MkdirAll(captureDir, 0755)
		defer removeBestEffort(captureDir)
		Expect(err).NotTo(HaveOccurred())
		file, err := os.CreateTemp(captureDir, fmt.Sprintf("%s_%s-*.pcap", podName, deviceName))
		Expect(err).NotTo(HaveOccurred())
		defer removeBestEffort(file.Name())

		// Initialise a new capture
		var pcap capture.PcapFile
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates)
		defer pcap.Done()

		// Capture listens to incoming packets
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Write 1 packet
		wg.Add(numberOfPackets)
		go func() {
			var packet = dummyPacket()

			packets <- packet
			wg.Done()
		}()

		// Wait for all the packets to be written to file
		wg.Wait()

		var dummyFile = outputFile{
			Name:  fmt.Sprintf("%s_%s.[\\d]+.pcap", podName, deviceName),
			Size:  0,
			Order: 0,
		}
		// Assert written files on disk
		assertPcapFiles(captureDir, []outputFile{
			currentOrderTwoFileSizeOnePacket,
			dummyFile,
		})

		// Assert that an update was sent
		var waitingForTrafficUpdate *proto.PacketCaptureStatusUpdate
		var capturingUpdate *proto.PacketCaptureStatusUpdate
		Eventually(updates).Should(Receive(&waitingForTrafficUpdate))
		Eventually(updates).Should(Receive(&capturingUpdate))
		assertStatusUpdates(waitingForTrafficUpdate, []outputFile{
			dummyFile,
		}, namespace, name, proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(capturingUpdate, []outputFile{
			currentOrderTwoFileSizeOnePacket,
			dummyFile,
		}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
	}, 10)

	It("Clean files when calling clean", func(done Done) {
		defer close(done)
		var err error
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates)

		// Capture listens to incoming packets
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Write 1 packet
		packet := dummyPacket()
		packets <- packet

		pcap.Done()

		assertPcapFiles(captureDir, []outputFile{
			currentOrderTwoFileSizeOnePacket,
		})
		// Assert that an update was sent
		var waitingForTrafficUpdate *proto.PacketCaptureStatusUpdate
		var capturingUpdate *proto.PacketCaptureStatusUpdate
		Eventually(updates).Should(Receive(&waitingForTrafficUpdate))
		Eventually(updates).Should(Receive(&capturingUpdate))
		assertStatusUpdates(waitingForTrafficUpdate, []outputFile{}, namespace, name,
			proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(capturingUpdate, []outputFile{
			currentOrderTwoFileSizeOnePacket,
		}, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)

		// Call clean and expect no files to be present
		err = pcap.Clean()
		Expect(err).NotTo(HaveOccurred())
		assertPcapFiles(captureDir, []outputFile{})
	}, 10)

	It("Moves to Finished when endTime is specified", func(done Done) {
		defer close(done)
		var wg sync.WaitGroup
		var err error
		var numberOfPackets = 1
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Initialise a new capture
		var pcap capture.PcapFile
		var packets = make(chan gopacket.Packet)
		defer close(packets)
		var endTime = time.Now().Add(1 * time.Second)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates,
			capture.WithEndTime(endTime))
		defer pcap.Done()

		// Calling Write in order to trigger the start of timer
		go func() {
			defer GinkgoRecover()

			err = pcap.Write(packets)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Write 1 packet
		wg.Add(numberOfPackets)
		go func() {
			var packet = dummyPacket()

			packets <- packet
			wg.Done()
		}()

		// Wait for all the packets to be written to file
		wg.Wait()

		time.Sleep(2 * time.Second)

		// Define expected files
		var expectedFiles = []outputFile{
			currentOrderTwoFileSizeOnePacket,
		}

		// Assert written files on disk
		assertPcapFiles(captureDir, expectedFiles)

		// Assert that an update was sent
		var waitingForTrafficUpdate *proto.PacketCaptureStatusUpdate
		var capturingUpdate *proto.PacketCaptureStatusUpdate
		var finishedUpdate *proto.PacketCaptureStatusUpdate
		Eventually(updates).Should(Receive(&waitingForTrafficUpdate))
		Eventually(updates).Should(Receive(&capturingUpdate))
		Eventually(updates).Should(Receive(&finishedUpdate))
		assertStatusUpdates(waitingForTrafficUpdate, []outputFile{}, namespace, name, proto.PacketCaptureStatusUpdate_WAITING_FOR_TRAFFIC)
		assertStatusUpdates(capturingUpdate, expectedFiles, namespace, name, proto.PacketCaptureStatusUpdate_CAPTURING)
		assertStatusUpdates(finishedUpdate, expectedFiles, namespace, name, proto.PacketCaptureStatusUpdate_FINISHED)
	}, 15)

	It("Moves to Finished when endTime is in the past", func(done Done) {
		defer close(done)
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Write a pcap file in order to simulate a previous capture
		var err = os.MkdirAll(captureDir, 0755)
		defer removeBestEffort(captureDir)
		Expect(err).NotTo(HaveOccurred())
		file, err := os.CreateTemp(captureDir, fmt.Sprintf("%s_%s-*.pcap", podName, deviceName))
		Expect(err).NotTo(HaveOccurred())
		defer removeBestEffort(file.Name())
		var dummyFile = outputFile{
			Name:  fmt.Sprintf("%s_%s.[\\d]+.pcap", podName, deviceName),
			Size:  0,
			Order: 0,
		}

		// Initialise a new capture
		var pcap capture.Capture
		var endTime = time.Unix(0, 0)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates,
			capture.WithEndTime(endTime))
		defer pcap.Stop()

		err = pcap.Start()
		Expect(err).NotTo(HaveOccurred())

		// Assert that an update was sent
		var finishedUpdate *proto.PacketCaptureStatusUpdate
		Eventually(updates).Should(Receive(&finishedUpdate))
		assertStatusUpdates(finishedUpdate, []outputFile{dummyFile}, namespace, name, proto.PacketCaptureStatusUpdate_FINISHED)
	}, 10)

	It("Moves to Scheduled when startTime is defined", func(done Done) {
		defer close(done)
		var updates = make(chan interface{}, 100)
		defer close(updates)

		// Write a pcap file in order to simulate a previous capture
		var err = os.MkdirAll(captureDir, 0755)
		defer removeBestEffort(captureDir)
		Expect(err).NotTo(HaveOccurred())
		file, err := os.CreateTemp(captureDir, fmt.Sprintf("%s_%s-*.pcap", podName, deviceName))
		Expect(err).NotTo(HaveOccurred())
		defer removeBestEffort(file.Name())
		var dummyFile = outputFile{
			Name:  fmt.Sprintf("%s_%s.[\\d]+.pcap", podName, deviceName),
			Size:  0,
			Order: 0,
		}

		// Initialise a new capture
		var pcap capture.Capture
		var startTime = time.Now().Add(3 * time.Hour)
		pcap = capture.NewRotatingPcapFile(baseDir, namespace, name, podName, deviceName, updates,
			capture.WithStartTime(startTime))
		defer pcap.Stop()

		go func() {
			defer GinkgoRecover()

			var err = pcap.Start()
			Expect(err).NotTo(HaveOccurred())
		}()

		// Assert that an update was sent
		var scheduledUpdate *proto.PacketCaptureStatusUpdate
		Eventually(updates).Should(Receive(&scheduledUpdate))
		assertStatusUpdates(scheduledUpdate, []outputFile{dummyFile}, namespace, name, proto.PacketCaptureStatusUpdate_SCHEDULED)
	}, 10)
})

func removeBestEffort(path string) {
	err := os.RemoveAll(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		logrus.WithError(err).WithField("path", path).Warn("Failed to remove directory")
	}
}

type outputFile struct {
	Name  string
	Size  int
	Order int
}

func assertPcapFiles(baseDir string, expected []outputFile) {
	sort.Slice(expected, func(i, j int) bool {
		return expected[i].Order < expected[j].Order
	})

	Eventually(func() error {
		files := read(baseDir)
		if len(files) != len(expected) {
			return fmt.Errorf("expected %d files, got %d", len(expected), len(files))
		}

		for i, exp := range expected {
			if int64(exp.Size) != files[i].Size() {
				return fmt.Errorf("expected file %d size %d, got %d", i, exp.Size, files[i].Size())
			}
			nameRE := regexp.MustCompile(exp.Name)
			if !nameRE.MatchString(files[i].Name()) {
				return fmt.Errorf("expected file %d name %s, got %s", i, exp.Name, files[i].Name())
			}
		}
		return nil
	}).Should(Succeed())
}

func assertStatusUpdates(update *proto.PacketCaptureStatusUpdate, expected []outputFile, expectedNs string,
	expectedCaptureName string, expectedState proto.PacketCaptureStatusUpdate_PacketCaptureState) {
	sort.Slice(expected, func(i, j int) bool {
		return expected[i].Order < expected[j].Order
	})
	Expect(update.CaptureFiles).To(HaveLen(len(expected)), "wrong length in assertStatusUpdates")
	for i := range expected {
		Expect(update.CaptureFiles[i]).To(MatchRegexp(expected[i].Name))
	}
	Expect(update.Id.GetNamespace()).To(Equal(expectedNs))
	Expect(update.Id.GetName()).To(Equal(expectedCaptureName))
	Expect(update.State).To(Equal(expectedState))
}

func read(baseDir string) []os.FileInfo {
	pCaps, err := os.ReadDir(baseDir)
	if err != nil {
		return nil
	}

	var pcapInfo []os.FileInfo
	for _, pc := range pCaps {
		// We used to ignore the error here, but info.Size() sometimes panicked
		// in CI with a nil pointer dereference.  Adding defensive logic here to
		// either fix that or diagnose it.
		info, err := pc.Info()
		if err != nil {
			logrus.WithError(err).WithField("dirInfo", pc).Warn("Failed to get file info for pcap file, skipping.")
			continue
		}
		func() {
			defer func() {
				pv := recover()
				if pv != nil {
					logrus.WithField("dirInfo", pc).WithField("error", pv).Warn("Failed to get file size for pcap file, skipping.")
					return
				}
			}()
			info.Size()
			pcapInfo = append(pcapInfo, info)
		}()
	}
	sort.Slice(pcapInfo, func(i, j int) bool {
		return pCaps[i].Name() < pCaps[j].Name()
	})
	return pcapInfo
}

func dummyPacketDataSize() int {
	return len(dummyPacketData())
}

func dummyPacket() gopacket.Packet {
	data := dummyPacketData()
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().CaptureLength = len(data)
	packet.Metadata().Length = len(data)

	return packet
}

func dummyPacketData() []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	_ = gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC: []byte{0, 0, 0, 0, 0, 1},
			DstMAC: []byte{0, 0, 0, 0, 0, 2},
		},
		&layers.IPv4{
			Version: 4,
			SrcIP:   net.IP{1, 1, 1, 1},
			DstIP:   net.IP{1, 1, 1, 2},
			TTL:     128,
		},
		&layers.TCP{
			SrcPort: layers.TCPPort(1000),
			DstPort: layers.TCPPort(80),
			SYN:     true,
		},
		gopacket.Payload([]byte{1, 2, 3, 4}))
	return buf.Bytes()
}
