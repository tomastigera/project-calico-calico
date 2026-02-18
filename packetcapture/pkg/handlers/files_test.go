// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

package handlers_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/packetcapture/pkg/cache"
	"github.com/projectcalico/calico/packetcapture/pkg/capture"
	"github.com/projectcalico/calico/packetcapture/pkg/handlers"
	"github.com/projectcalico/calico/packetcapture/pkg/middleware"
)

var _ = Describe("FilesDownload", func() {
	var req *http.Request

	BeforeEach(func() {
		// Create a new request
		var err error
		req, err = http.NewRequest("GET", "/download/ns/name/files.zip", nil)
		Expect(err).NotTo(HaveOccurred())

		// Setup the variables on the context to be used for authN/authZ
		req = req.WithContext(middleware.WithClusterID(req.Context(), "cluster"))
		req = req.WithContext(middleware.WithNamespace(req.Context(), "ns"))
		req = req.WithContext(middleware.WithCaptureName(req.Context(), "name"))
	})

	It("should archive a pcap file with only its header", func() {
		// Create a temp directory to store all the files needed for the test
		var tempDir, err = os.MkdirTemp("/tmp", "test")
		Expect(err).NotTo(HaveOccurred())

		// Create dummy files and add them to a tar archive
		var tarFile = createTarArchive(tempDir, filesOnNode1, pcapHeader())
		defer func() { _ = os.RemoveAll(tempDir) }()

		tarFileReader, err := os.Open(tarFile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", point).Return(tarFileReader, nil, nil)
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Download)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusOK))
		Expect(recorder.Header().Get("Content-Type")).To(Equal("application/zip"))
		Expect(recorder.Header().Get("Content-Disposition")).To(Equal("attachment; filename=files.zip"))
		Expect(recorder.Header().Get("Content-Length")).NotTo(Equal(""))

		archive, err := os.CreateTemp(tempDir, "result.*.zip")
		Expect(err).NotTo(HaveOccurred())

		// Write the body to file
		_, err = io.Copy(archive, recorder.Body)
		Expect(err).NotTo(HaveOccurred())
		validateArchive(archive, filesOnNode1, pcapHeader())
	})

	It("should download files from a single node", func() {
		// Create a temp directory to store all the files needed for the test
		var tempDir, err = os.MkdirTemp("/tmp", "test")
		Expect(err).NotTo(HaveOccurred())

		// Create dummy files and add them to a tar archive
		var tarFile = createTarArchive(tempDir, filesOnNode1, []byte("node1"))
		defer func() { _ = os.RemoveAll(tempDir) }()

		tarFileReader, err := os.Open(tarFile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", point).Return(tarFileReader, nil, nil)
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Download)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusOK))
		Expect(recorder.Header().Get("Content-Type")).To(Equal("application/zip"))
		Expect(recorder.Header().Get("Content-Disposition")).To(Equal("attachment; filename=files.zip"))
		Expect(recorder.Header().Get("Content-Length")).NotTo(Equal(""))

		archive, err := os.CreateTemp(tempDir, "result.*.zip")
		Expect(err).NotTo(HaveOccurred())

		// Write the body to file
		_, err = io.Copy(archive, recorder.Body)
		Expect(err).NotTo(HaveOccurred())
		validateArchive(archive, filesOnNode1, []byte("node1"))
	})

	It("should download files from 0 files", func() {
		// Create a temp directory to store all the files needed for the test
		var tempDir, err = os.MkdirTemp("/tmp", "test")
		Expect(err).NotTo(HaveOccurred())

		// Create dummy files and add them to a tar archive
		var tarFile = createTarArchive(tempDir, noFiles, []byte("node1"))
		defer func() { _ = os.RemoveAll(tempDir) }()

		tarFileReader, err := os.Open(tarFile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCaptureNoFiles, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", point).Return(tarFileReader, nil, nil)
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Download)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusNoContent))
		Expect(recorder.Body.String()).To(Equal(""))
		Expect(recorder.Header().Get("Content-Type")).To(Equal(""))
		Expect(recorder.Header().Get("Content-Disposition")).To(Equal(""))
		Expect(recorder.Header().Get("Content-Length")).To(Equal(""))
	})

	It("should download files from multiple nodes", func() {
		// Create a temp directory to store all the files needed for the test
		var tempDir, err = os.MkdirTemp("/tmp", "test")
		Expect(err).NotTo(HaveOccurred())

		// Create dummy files and add them to a tar archive
		var tarFileNode1 = createTarArchive(tempDir, filesOnNode1, []byte("node1"))
		var tarFileNode2 = createTarArchive(tempDir, filesOnNode2, []byte("node2"))
		var tarFileNode3 = createTarArchive(tempDir, filesOnNode3, []byte("node3"))
		defer func() { _ = os.RemoveAll(tempDir) }()

		tarFileReader1, err := os.Open(tarFileNode1.Name())
		Expect(err).NotTo(HaveOccurred())
		tarFileReader2, err := os.Open(tarFileNode2.Name())
		Expect(err).NotTo(HaveOccurred())
		tarFileReader3, err := os.Open(tarFileNode3.Name())
		Expect(err).NotTo(HaveOccurred())

		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCaptureMultipleNodes, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node1").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod1",
			PodNamespace:  "entryNs",
		}, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node2").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod2",
			PodNamespace:  "entryNs",
		}, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node3").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod3",
			PodNamespace:  "entryNs",
		}, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", pointNode1).Return(tarFileReader1, nil, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", pointNode2).Return(tarFileReader2, nil, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", pointNode3).Return(tarFileReader3, nil, nil)
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Download)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusOK))
		Expect(recorder.Header().Get("Content-Type")).To(Equal("application/zip"))
		Expect(recorder.Header().Get("Content-Disposition")).To(Equal("attachment; filename=files.zip"))
		Expect(recorder.Header().Get("Content-Length")).NotTo(Equal(""))

		archive, err := os.CreateTemp(tempDir, "result.*.zip")
		Expect(err).NotTo(HaveOccurred())

		// Write the body to file
		_, err = io.Copy(archive, recorder.Body)
		Expect(err).NotTo(HaveOccurred())
		var allFiles []string
		allFiles = append(allFiles, filesOnNode1...)
		allFiles = append(allFiles, filesOnNode2...)
		allFiles = append(allFiles, filesOnNode3...)
		validateArchive(archive, allFiles,
			[]byte("node1"),
			[]byte("node2"), []byte("node2"),
			[]byte("node3"), []byte("node3"), []byte("node3"))
	})

	It("should downloads files from multiple nodes and ignore errors in between", func() {
		// Create a temp directory to store all the files needed for the test
		var tempDir, err = os.MkdirTemp("/tmp", "test")
		Expect(err).NotTo(HaveOccurred())

		// Create dummy files and add them to a tar archive
		var tarFileNode1 = createTarArchive(tempDir, filesOnNode1, []byte("node1"))
		var tarFileNode3 = createTarArchive(tempDir, filesOnNode3, []byte("node3"))
		defer func() { _ = os.RemoveAll(tempDir) }()

		tarFileReader1, err := os.Open(tarFileNode1.Name())
		Expect(err).NotTo(HaveOccurred())
		tarFileReader3, err := os.Open(tarFileNode3.Name())
		Expect(err).NotTo(HaveOccurred())

		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCaptureMultipleNodes, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node1").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod1",
			PodNamespace:  "entryNs",
		}, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node2").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod2",
			PodNamespace:  "entryNs",
		}, fmt.Errorf("get entry pod error"))
		mockK8sCommands.On("GetEntryPod", "cluster", "node3").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod3",
			PodNamespace:  "entryNs",
		}, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", pointNode1).Return(tarFileReader1, nil, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", pointNode2).Return(nil, nil, fmt.Errorf("open tar reader error"))
		mockFileRetrieval.On("OpenTarReader", "cluster", pointNode3).Return(tarFileReader3, nil, nil)
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Download)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusOK))
		Expect(recorder.Header().Get("Content-Type")).To(Equal("application/zip"))
		Expect(recorder.Header().Get("Content-Disposition")).To(Equal("attachment; filename=files.zip"))
		Expect(recorder.Header().Get("Content-Length")).NotTo(Equal(""))

		archive, err := os.CreateTemp(tempDir, "result.*.zip")
		Expect(err).NotTo(HaveOccurred())

		// Write the body to file
		_, err = io.Copy(archive, recorder.Body)
		Expect(err).NotTo(HaveOccurred())
		var allFiles []string
		allFiles = append(allFiles, filesOnNode1...)
		allFiles = append(allFiles, filesOnNode3...)
		validateArchive(archive, allFiles,
			[]byte("node1"),
			[]byte("node3"), []byte("node3"), []byte("node3"))
	})

	DescribeTable("Failure to get packet capture",
		func(expectedStatus int, expectedError error) {
			// Bootstrap the download
			var mockCache = &cache.MockClientCache{}
			var mockK8sCommands = &capture.MockK8sCommands{}
			var mockFileRetrieval = &capture.MockFileCommands{}
			mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(nil, expectedError)
			var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			handler := http.HandlerFunc(download.Download)
			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(expectedStatus))
			Expect(strings.Trim(recorder.Body.String(), "\n")).To(Equal(expectedError.Error()))
		},
		Entry("Missing resource", http.StatusNotFound, errors.ErrorResourceDoesNotExist{}),
		Entry("Failure to get resource", http.StatusInternalServerError, fmt.Errorf("any error")),
	)

	DescribeTable("PacketCapture has no files attached",
		func(packetCapture *v3.PacketCapture) {
			// Bootstrap the download
			var mockCache = &cache.MockClientCache{}
			var mockK8sCommands = &capture.MockK8sCommands{}
			var mockFileRetrieval = &capture.MockFileCommands{}
			mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCapture, nil)
			var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			handler := http.HandlerFunc(download.Download)
			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusNoContent))
		},
		Entry("Empty status", packetCaptureEmptyStatus),
		Entry("Missing status", packetCaptureNoStatus),
		Entry("No files generated for packet capture", packetCaptureNoFiles),
	)

	It("should ignore tar error", func() {
		var errorWriter bytes.Buffer
		var _, err = errorWriter.WriteString("any error")
		Expect(err).NotTo(HaveOccurred())

		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", point).Return(nil, &errorWriter, nil)
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Download)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusNoContent))
		Expect(recorder.Body.String()).To(BeEmpty())
	})

	It("should ignore tar output removing leading /' from member names", func() {
		// Create a temp directory to store all the files needed for the test
		var tempDir, err = os.MkdirTemp("/tmp", "test")
		Expect(err).NotTo(HaveOccurred())

		// Create dummy files and add them to a tar archive
		var tarFile = createTarArchive(tempDir, filesOnNode1, []byte("node1"))
		defer func() { _ = os.RemoveAll(tempDir) }()

		tarFileReader, err := os.Open(tarFile.Name())
		Expect(err).NotTo(HaveOccurred())

		var errorWriter bytes.Buffer
		_, err = errorWriter.WriteString("tar: removing leading '/' from member names")
		Expect(err).NotTo(HaveOccurred())

		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", point).Return(tarFileReader, &errorWriter, nil)
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Download)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusOK))
		Expect(recorder.Header().Get("Content-Type")).To(Equal("application/zip"))
		Expect(recorder.Header().Get("Content-Disposition")).To(Equal("attachment; filename=files.zip"))
		Expect(recorder.Header().Get("Content-Length")).NotTo(Equal(""))

		archive, err := os.CreateTemp(tempDir, "result.*.zip")
		Expect(err).NotTo(HaveOccurred())

		// Write the body to file
		_, err = io.Copy(archive, recorder.Body)
		Expect(err).NotTo(HaveOccurred())
		validateArchive(archive, filesOnNode1, []byte("node1"))
	})

	It("should ignore tar output No such file or directory", func() {
		// Create a temp directory to store all the files needed for the test
		var tempDir, err = os.MkdirTemp("/tmp", "test")
		Expect(err).NotTo(HaveOccurred())

		// Create dummy files and add them to a tar archive
		var tarFile = createTarArchive(tempDir, noFiles, []byte("node1"))
		defer func() { _ = os.RemoveAll(tempDir) }()

		tarFileReader, err := os.Open(tarFile.Name())
		Expect(err).NotTo(HaveOccurred())

		var errorWriter bytes.Buffer
		_, err = errorWriter.WriteString(
			"tar: /var/log/calico/pcap/tigera-manager/test-delete: No such file or directory" +
				"\ntar: error exit delayed from previous errors")
		Expect(err).NotTo(HaveOccurred())

		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", point).Return(tarFileReader, &errorWriter, nil)
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Download)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusNoContent))
		Expect(recorder.Body.String()).To(Equal(""))
		Expect(recorder.Header().Get("Content-Type")).To(Equal(""))
		Expect(recorder.Header().Get("Content-Disposition")).To(Equal(""))
		Expect(recorder.Header().Get("Content-Length")).To(Equal(""))
	})

	It("should ignore error when failing to locate an entry pod", func() {
		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, fmt.Errorf("any error"))
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Download)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusNoContent))
		Expect(recorder.Body.String()).To(BeEmpty())
	})

	It("should ignore error when failing to open tar reader", func() {
		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod1",
			PodNamespace:  "entryNs",
		}, nil)
		mockFileRetrieval.On("OpenTarReader", "cluster", pointNode1).Return(nil, nil, fmt.Errorf("open tar reader error"))
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Download)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusNoContent))
		Expect(recorder.Body.String()).To(BeEmpty())
	})
})

func pcapHeader() []byte {
	const magicMicroseconds = 0xA1B2C3D4
	const versionMajor = 2
	const versionMinor = 4
	const snapshotLength = 1024
	const linkTypeEthernet = 1

	var pcapHeader = make([]byte, 24)
	binary.LittleEndian.PutUint32(pcapHeader[0:4], magicMicroseconds)
	binary.LittleEndian.PutUint16(pcapHeader[4:6], versionMajor)
	binary.LittleEndian.PutUint16(pcapHeader[6:8], versionMinor)
	binary.LittleEndian.PutUint32(pcapHeader[16:20], snapshotLength)
	binary.LittleEndian.PutUint32(pcapHeader[20:24], uint32(linkTypeEthernet))

	return pcapHeader
}

var _ = Describe("FilesDelete", func() {
	var req *http.Request

	BeforeEach(func() {
		// Create a new request
		var err error
		req, err = http.NewRequest("DELETE", "/files/ns/name", nil)
		Expect(err).NotTo(HaveOccurred())

		// Setup the variables on the context to be used for authN/authZ
		req = req.WithContext(middleware.WithClusterID(req.Context(), "cluster"))
		req = req.WithContext(middleware.WithNamespace(req.Context(), "ns"))
		req = req.WithContext(middleware.WithCaptureName(req.Context(), "name"))
	})

	It("Deletes files from a single node", func() {
		// Bootstrap the files
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(finishedPacketCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, nil)
		mockK8sCommands.On("UpdatePacketCaptureStatusWithNoFiles", "cluster", "name", "ns",
			map[string]struct{}{"node": {}}).Return(nil)
		mockFileRetrieval.On("Delete", "cluster", point).Return(nil, nil)
		var files = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(files.Delete)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusOK))
	})

	It("Delete files from a multiple node", func() {
		// Bootstrap the download
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(finishedPacketCaptureMultipleNodes, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node1").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod1",
			PodNamespace:  "entryNs",
		}, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node2").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod2",
			PodNamespace:  "entryNs",
		}, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node3").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod3",
			PodNamespace:  "entryNs",
		}, nil)
		mockK8sCommands.On("UpdatePacketCaptureStatusWithNoFiles", "cluster", "name", "ns",
			map[string]struct{}{"node1": {}, "node2": {}, "node3": {}}).Return(nil)
		mockFileRetrieval.On("Delete", "cluster", pointNode1).Return(nil, nil)
		mockFileRetrieval.On("Delete", "cluster", pointNode2).Return(nil, nil)
		mockFileRetrieval.On("Delete", "cluster", pointNode3).Return(nil, nil)
		var download = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(download.Delete)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusOK))
	})

	DescribeTable("Failure to get packet capture",
		func(expectedStatus int, expectedError error) {
			// Bootstrap the files
			var mockCache = &cache.MockClientCache{}
			var mockK8sCommands = &capture.MockK8sCommands{}
			var mockFileRetrieval = &capture.MockFileCommands{}
			mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(nil, expectedError)
			var files = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			handler := http.HandlerFunc(files.Delete)
			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(expectedStatus))
			Expect(strings.Trim(recorder.Body.String(), "\n")).To(Equal(expectedError.Error()))
		},
		Entry("Missing resource", http.StatusNotFound, errors.ErrorResourceDoesNotExist{}),
		Entry("Failure to get resource", http.StatusInternalServerError, fmt.Errorf("any error")),
	)

	DescribeTable("Fail to delete files for packetCapture with non-finished states",
		func(packetCapture *v3.PacketCapture, expectedStatus int, expectedErrMsg string) {
			// Bootstrap the files
			var mockCache = &cache.MockClientCache{}
			var mockK8sCommands = &capture.MockK8sCommands{}
			var mockFileRetrieval = &capture.MockFileCommands{}
			mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(packetCapture, nil)
			var files = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			handler := http.HandlerFunc(files.Delete)
			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(expectedStatus))
			Expect(strings.Trim(recorder.Body.String(), "\n")).To(Equal(expectedErrMsg))
		},
		Entry("All nodes in different state", differentStatesPacketCaptureMultipleNodes, http.StatusForbidden, "capture state is not Finished"),
		Entry("Missing finished state", packetCaptureMultipleNodes, http.StatusForbidden, "capture state cannot be determined"),
		Entry("One finished state", oneFinishedPacketCaptureMultipleNodes, http.StatusForbidden, "capture state is not Finished"),
	)

	It("Delete returns an error via io.Reader", func() {
		var errorWriter bytes.Buffer
		var _, err = errorWriter.WriteString("any error")
		Expect(err).NotTo(HaveOccurred())

		// Bootstrap the files
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(finishedPacketCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, nil)
		mockFileRetrieval.On("Delete", "cluster", point).Return(&errorWriter, nil)
		var files = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(files.Delete)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
		Expect(strings.Trim(recorder.Body.String(), "\n")).To(Equal("any error"))
	})

	It("Fails to locate an entry pod", func() {
		// Bootstrap the files
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(finishedPacketCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, fmt.Errorf("any error"))
		var files = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(files.Delete)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
		Expect(strings.Trim(recorder.Body.String(), "\n")).To(Equal("any error"))
	})

	It("Fails to update status", func() {
		// Bootstrap the files
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(finishedPacketCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, nil)
		mockK8sCommands.On("UpdatePacketCaptureStatusWithNoFiles", "cluster", "name", "ns",
			map[string]struct{}{"node": {}}).Return(errors.ErrorResourceUpdateConflict{Identifier: "any"})
		mockFileRetrieval.On("Delete", "cluster", point).Return(nil, nil)
		var files = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(files.Delete)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
		Expect(strings.Trim(recorder.Body.String(), "\n")).To(Equal("update conflict: any"))
		mockK8sCommands.AssertNumberOfCalls(GinkgoT(), "UpdatePacketCaptureStatusWithNoFiles", 4)
	})

	It("Retries to update status", func() {
		// Bootstrap the files
		var mockCache = &cache.MockClientCache{}
		var mockK8sCommands = &capture.MockK8sCommands{}
		var mockFileRetrieval = &capture.MockFileCommands{}
		mockK8sCommands.On("GetPacketCapture", "cluster", "name", "ns").Return(finishedPacketCaptureOneNode, nil)
		mockK8sCommands.On("GetEntryPod", "cluster", "node").Return(&capture.EntryPod{
			ContainerName: "fluentd",
			PodName:       "entryPod",
			PodNamespace:  "entryNs",
		}, nil)
		mockK8sCommands.On("UpdatePacketCaptureStatusWithNoFiles", "cluster", "name", "ns",
			map[string]struct{}{"node": {}}).Return(errors.ErrorResourceUpdateConflict{Identifier: "any"}).Twice()
		mockK8sCommands.On("UpdatePacketCaptureStatusWithNoFiles", "cluster", "name", "ns",
			map[string]struct{}{"node": {}}).Return(nil)
		mockFileRetrieval.On("Delete", "cluster", point).Return(nil, nil)
		var files = handlers.NewFiles(mockCache, mockK8sCommands, mockFileRetrieval)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(files.Delete)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusOK))
		mockK8sCommands.AssertNumberOfCalls(GinkgoT(), "UpdatePacketCaptureStatusWithNoFiles", 3)
	})
})

func validateArchive(archive *os.File, files []string, expectedData ...[]byte) {
	defer GinkgoRecover()

	zipReader, err := zip.OpenReader(archive.Name())
	Expect(err).NotTo(HaveOccurred())
	Expect(len(zipReader.File)).To(Equal(len(files)))

	for idx, f := range zipReader.File {
		file, err := f.Open()
		Expect(err).NotTo(HaveOccurred())
		var content bytes.Buffer
		_, err = io.Copy(&content, file)
		Expect(err).NotTo(HaveOccurred())

		Expect(content.String()).To(Equal(string(expectedData[idx])))
		_ = file.Close()
	}
}

func createTarArchive(dir string, files []string, data []byte) *os.File {
	defer GinkgoRecover()

	// Create the file for the tar archive
	var tarFile, err = os.CreateTemp(dir, "archive.*.tar")
	Expect(err).NotTo(HaveOccurred())

	// Archive the file to the tar archive
	var tarWriter = tar.NewWriter(tarFile)

	for _, file := range files {
		// Create a temporary file with some random data in it
		file, err := os.CreateTemp(dir, fmt.Sprintf("%s.*.txt", file))
		Expect(err).NotTo(HaveOccurred())
		_, err = file.Write(data)
		Expect(err).NotTo(HaveOccurred())
		_ = file.Close()

		// Open a reader for the file
		fileReader, err := os.Open(file.Name())
		Expect(err).NotTo(HaveOccurred())

		// Write the file header to the archive
		info, err := fileReader.Stat()
		Expect(err).NotTo(HaveOccurred())
		header, err := tar.FileInfoHeader(info, info.Name())
		Expect(err).NotTo(HaveOccurred())
		header.Name = fileReader.Name()
		err = tarWriter.WriteHeader(header)
		Expect(err).NotTo(HaveOccurred())

		// Write the content to the tar archive
		_, err = io.Copy(tarWriter, fileReader)
		Expect(err).NotTo(HaveOccurred())

		_ = fileReader.Close()
	}

	_ = tarWriter.Flush()
	_ = tarWriter.Close()

	return tarFile
}
