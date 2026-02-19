// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
)

var _ = Describe("utils", func() {
	DescribeTable("Mesos Labels", func(raw, sanitized string) {
		result := utils.SanitizeMesosLabel(raw)
		Expect(result).To(Equal(sanitized))
	},
		Entry("valid", "k", "k"),
		Entry("dashes", "-my-val", "my-val"),
		Entry("double periods", "$my..val", "my.val"),
		Entry("special chars", "m$y.val", "m-y.val"),
		Entry("slashes", "//my/val/", "my.val"),
		Entry("mix of special chars",
			"some_val-with.lots*of^weird#characters", "some_val-with.lots-of-weird-characters"),
	)
})
var _ = Describe("validate start/endRange of IPAMData", func() {

	subnet := "10.10.0.0/24"

	It("should return expected start/end range for empty IPAMData", func() {
		ipamData := make(map[string]interface{})

		err := utils.UpdateHostLocalIPAMDataForWindows(subnet, ipamData)

		Expect(err).NotTo(HaveOccurred())
		Expect(ipamData["rangeStart"]).To(Equal("10.10.0.3"))
		Expect(ipamData["rangeEnd"]).To(Equal("10.10.0.254"))
	})

	It("should return expected start/end range for invalid Range in IPAMData", func() {
		ipamData := map[string]interface{}{
			"rangeStart": "10.10.1.2",
			"rangeEnd":   "10.10.0.255",
		}

		err := utils.UpdateHostLocalIPAMDataForWindows(subnet, ipamData)

		Expect(err).NotTo(HaveOccurred())
		Expect(ipamData["rangeStart"]).To(Equal("10.10.0.3"))
		Expect(ipamData["rangeEnd"]).To(Equal("10.10.0.254"))
	})

	It("should return same start/end range provided in IPAMData", func() {
		ipamData := map[string]interface{}{
			"rangeStart": "10.10.0.15",
			"rangeEnd":   "10.10.0.50",
		}

		err := utils.UpdateHostLocalIPAMDataForWindows(subnet, ipamData)

		Expect(err).NotTo(HaveOccurred())
		Expect(ipamData["rangeStart"]).To(Equal("10.10.0.15"))
		Expect(ipamData["rangeEnd"]).To(Equal("10.10.0.50"))
	})

	It("should return expected start/end range for empty IPs in IPAMData", func() {
		ipamData := map[string]interface{}{
			"rangeStart": "",
			"rangeEnd":   "",
		}

		err := utils.UpdateHostLocalIPAMDataForWindows(subnet, ipamData)

		Expect(err).NotTo(HaveOccurred())
		Expect(ipamData["rangeStart"]).To(Equal("10.10.0.3"))
		Expect(ipamData["rangeEnd"]).To(Equal("10.10.0.254"))
	})

	It("should return expected start/end range for /23 CIDR", func() {
		subnet = "10.0.0.0/23"
		ipamData := map[string]interface{}{
			"rangeStart": "",
			"rangeEnd":   "",
		}

		err := utils.UpdateHostLocalIPAMDataForWindows(subnet, ipamData)

		Expect(err).NotTo(HaveOccurred())
		Expect(ipamData["rangeStart"]).To(Equal("10.0.0.3"))
		Expect(ipamData["rangeEnd"]).To(Equal("10.0.1.254"))
	})

	It("should fail to validate Invalid Ip in range", func() {
		subnet = "10.10.10.10/24"
		ipamData := map[string]interface{}{
			"rangeStart": "10.10.10.256",
			"rangeEnd":   "0.42.42.42",
		}

		err := utils.UpdateHostLocalIPAMDataForWindows(subnet, ipamData)
		Expect(err).To(HaveOccurred())
	})

	It("should fail to validate Invalid CIDR value", func() {
		subnet = "10.10.10.256/24"
		ipamData := map[string]interface{}{
			"rangeStart": "",
			"rangeEnd":   "",
		}

		err := utils.UpdateHostLocalIPAMDataForWindows(subnet, ipamData)
		Expect(err).To(HaveOccurred())
	})
})

// unit test for MTUFromFile
var _ = Describe("MTUFromFile", func() {
	It("should return the correct MTU value from a valid file", func() {
		// Create a temporary file with a valid MTU value
		file, err := os.CreateTemp("", "mtu_test")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = os.Remove(file.Name()) }()

		_, err = file.WriteString("1500")
		Expect(err).NotTo(HaveOccurred())
		_ = file.Close()

		// Call the function and check the result
		mtu, err := utils.MTUFromFile(file.Name(), types.NetConf{})
		Expect(err).NotTo(HaveOccurred())
		Expect(mtu).To(Equal(1500))
	})

	Context("Error when reading the MTU file", func() {
		It("should not return an error for a non-existent file", func() {
			_, err := utils.MTUFromFile("/non/existent/file", types.NetConf{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error for a non-existent file when RequireMTUFile is true", func() {
			_, err := utils.MTUFromFile("/non/existent/file", types.NetConf{RequireMTUFile: true})
			Expect(err).To(HaveOccurred())
		})

		It("should return an error if reading the file fails with error other than file not found", func() {
			// Create a temporary file with invalid permissions
			file, err := os.CreateTemp("", "mtu_test")
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = os.Remove(file.Name()) }()

			err = os.Chmod(file.Name(), 0o000) // Remove all permissions
			Expect(err).NotTo(HaveOccurred())
			_ = file.Close()

			// Call the function and check the result
			_, err = utils.MTUFromFile(file.Name(), types.NetConf{})
			Expect(err).To(HaveOccurred())
		})
	})
})
