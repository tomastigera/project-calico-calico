// Copyright (c) 2020, 2023 Tigera, Inc. All rights reserved.
package fortimanager_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/jarcoal/httpmock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	fn "github.com/projectcalico/calico/firewall-integration/pkg/fortimanager"
)

const jsonContentType = "application/json"

var testFwAddress = fn.FortiFWAddress{
	Name:    "testAddr-1",
	Type:    "ipmask",
	IpAddr:  "10.128.0.190 255.255.255.255",
	Comment: "Unit test Object",
	SubType: "mask",
}

var testFwAddressGroup = fn.FortiFWAddressGroup{
	Name:    "testAddrGrp-1",
	Comment: "Unit test Object",
	Members: []string{"masternode-1", "masternode-3"},
}

var addrObj1 = fn.RespFortiGateFWAddressData{
	Name:    "masternode-1",
	Type:    "ipmask",
	Subnet:  "10.128.0.190 255.255.255.255",
	Comment: "Unit test Object",
	SubType: "mask",
}

var addrObj2 = fn.RespFortiGateFWAddressData{
	Name:    "masternode-2",
	Type:    "ipmask",
	Subnet:  "10.128.0.190 255.255.255.255",
	Comment: "Unit test Object",
	SubType: "mask",
}

var fwPostRes = fn.RespFortiGateStatus{
	Name:       "testPost",
	HttpStatus: 200,
}

var fwPostErrRes = fn.RespFortiGateStatus{
	Name:       "testPost",
	HttpStatus: fn.FortiGateResourceNotFound,
}
var responseMapSingleNode = fn.RespFortiGateAddress{
	HttpStatus: fn.FortiGateReturnSuccess,
	Result:     []fn.RespFortiGateFWAddressData{addrObj1},
}

var responseMapErrSingleNode = fn.RespFortiGateAddress{
	HttpStatus: fn.FortiGateResourceNotFound,
	Result:     []fn.RespFortiGateFWAddressData{addrObj1},
}

var responseMapTwoNode = fn.RespFortiGateAddress{
	HttpStatus: fn.FortiGateReturnSuccess,
	Result:     []fn.RespFortiGateFWAddressData{addrObj1, addrObj2},
}

var addrGrpObj1 = fn.RespFortiGateFWAddressGrpData{
	Name:    "default.microservice1",
	Comment: "Unit test Object",
	Member: []struct {
		Name string `json:"name"`
	}{
		{
			Name: "masternode-1",
		},
		{
			Name: "masternode-2",
		},
	},
}

var addrGrpObj2 = fn.RespFortiGateFWAddressGrpData{
	Name:    "default.microservice2",
	Comment: "Unit test Object",
	Member: []struct {
		Name string `json:"name"`
	}{
		{
			Name: "masternode-3",
		},
		{
			Name: "masternode-4",
		},
	},
}

var responseMapSingleAddressGrp = fn.RespFortiGateAddressGrp{
	HttpStatus: fn.FortiGateReturnSuccess,
	Result:     []fn.RespFortiGateFWAddressGrpData{addrGrpObj1},
}

var responseMapErrSingleAddressGrp = fn.RespFortiGateAddressGrp{
	HttpStatus: fn.FortiGateResourceNotFound,
	Result:     []fn.RespFortiGateFWAddressGrpData{addrGrpObj1},
}

var responseMapTwoAddressGrp = fn.RespFortiGateAddressGrp{
	HttpStatus: fn.FortiGateReturnSuccess,
	Result:     []fn.RespFortiGateFWAddressGrpData{addrGrpObj1, addrGrpObj2},
}

type mockRestClient struct {
	applicationType    string
	inSecureSkipVerify bool
}

func (f *mockRestClient) FortiGateRestGet(url string) ([]uint8, error) {

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != fn.FortiGateReturnSuccess {
			return nil, fmt.Errorf("Error from FortiGate, GET Status:%s StatusCode:%d", resp.Status, resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		return body, err
	}
	return nil, err
}

func (f *mockRestClient) FortiGateRestPut(url string, payload []uint8) ([]uint8, error) {

	resp, err := http.Post(url, f.applicationType, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != fn.FortiGateReturnSuccess {
			return nil, fmt.Errorf("Error from FortiGate, PUT Status:%s StatusCode:%d", resp.Status, resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		return body, err
	}
	return nil, err
}

func (f *mockRestClient) FortiGateRestPost(url string, payload []uint8) ([]uint8, error) {
	return nil, nil
}
func (f *mockRestClient) FortiGateRestDelete(url string) ([]uint8, error) {
	return nil, nil
}

func NewMockRestClient(applicationType string, inSecureSkipVerify bool) fn.FortiGateRestClientApi {
	return &mockRestClient{
		applicationType:    applicationType,
		inSecureSkipVerify: inSecureSkipVerify,
	}
}

var _ = Describe("Test Fortigate Address object", func() {

	var fc fn.FortiFWClientApi
	BeforeEach(func() {
		frclient := NewMockRestClient(jsonContentType, false)
		fc = fn.NewFortiGateClient("", "fortigate.dev", "test", "", frclient)
	})

	It("Validate FortiGate Address object", func() {
		By("Reading Address Object master-node-1", func() {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			// Test by reading an address object
			httpmock.RegisterResponder("GET", "https://fortigate.dev/api/v2/cmdb/firewall/address/master-node-1?access_token=test",
				func(req *http.Request) (*http.Response, error) {
					res, _ := httpmock.NewJsonResponse(200, responseMapSingleNode)
					return res, nil
				},
			)
			// Get a Firewall Address Object from mock'd FW and check it's name
			val, err := fc.GetFirewallAddress("master-node-1")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(val.Name).Should(Equal("masternode-1"))
		})
	})
	It("Validate FortiGate Address Objects", func() {
		By("Reading all Address Objects", func() {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			// Get List of Firewall Address Objects and check it's length and name
			httpmock.RegisterResponder("GET", "https://fortigate.dev/api/v2/cmdb/firewall/address?access_token=test",
				func(req *http.Request) (*http.Response, error) {
					res, _ := httpmock.NewJsonResponse(200, responseMapTwoNode)
					return res, nil
				},
			)
			vals, err := fc.ListAllFirewallAddresses()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(len(vals)).Should(Equal(2))
			Expect(vals[1].Name).Should(Equal("masternode-2"))
			Expect(vals[0].Name).Should(Equal("masternode-1"))
		})
	})
	It("Validate FortiGate Address objects by changing its values", func() {
		By("Modifying Address Object testAddr-1", func() {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			// Test by updating value of Address object
			httpmock.RegisterResponder("POST", "https://fortigate.dev/api/v2/cmdb/firewall/address/testAddr-1?access_token=test",
				func(req *http.Request) (*http.Response, error) {
					r := req.Body
					body, err := io.ReadAll(r)
					if err != nil {
						return httpmock.NewStringResponse(500, err.Error()), nil
					}
					err = json.Unmarshal(body, &testFwAddress)
					if err != nil {
						return httpmock.NewStringResponse(500, err.Error()), nil
					}
					response, _ := httpmock.NewJsonResponse(200, fwPostRes)
					return response, nil
				},
			)
			// Copy testFwAddress object into testAddr and modify object
			testAddr := testFwAddress
			testAddr.Comment = "Modified"
			// Send Modified object to Mocked Fw, this will modify testFwAddress
			err := fc.UpdateFirewallAddress(testAddr)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(testAddr.Comment).Should(Equal(testFwAddress.Comment))
		})
	})
	It("Validate FortiGate Address with Invalid values", func() {
		By("Reading Invalid Address Objects", func() {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			// Test by reading an address object
			httpmock.RegisterResponder("GET", "https://fortigate.dev/api/v2/cmdb/firewall/address/default.microservice1?access_token=test",
				func(req *http.Request) (*http.Response, error) {
					res, _ := httpmock.NewJsonResponse(200, responseMapErrSingleNode)
					return res, nil
				},
			)
			// Get a invalid Firewall Address  Object from mock'd FW and check it's name and members name.
			_, err := fc.GetFirewallAddress("dummy")
			Expect(err).Should(HaveOccurred())
			// Get a valid Firewall Address  Object from mock'd FW and check it's returns error.
			_, err = fc.GetFirewallAddress("default.microservice1")
			Expect(err).Should(HaveOccurred())

			// Reactivate Mock
			httpmock.DeactivateAndReset()
			httpmock.Activate()
			httpmock.RegisterResponder("POST", "https://fortigate.dev/api/v2/cmdb/firewall/address/testAddrGrp-1?access_token=test",
				func(req *http.Request) (*http.Response, error) {
					response, _ := httpmock.NewJsonResponse(200, fwPostErrRes)
					return response, nil
				},
			)
			testAddr := testFwAddress
			testAddr.Name = "Dummy"
			// Update an Invalid Firewall Address
			err = fc.UpdateFirewallAddress(testAddr)
			Expect(err).Should(HaveOccurred())

			testAddr = testFwAddress
			// Update an valid Firewall Address,  but expect Error from mock
			err = fc.UpdateFirewallAddress(testAddr)
			Expect(err).Should(HaveOccurred())
		})
	})
})

var _ = Describe("Test Fortigate Address Group Object", func() {

	var fc fn.FortiFWClientApi
	BeforeEach(func() {
		frclient := NewMockRestClient(jsonContentType, false)
		fc = fn.NewFortiGateClient("", "fortigate.dev", "test", "", frclient)
	})

	It("Validate FortiGate Address Groups", func() {
		By("Reading Address Group Objects", func() {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			// Test by reading an address object
			httpmock.RegisterResponder("GET", "https://fortigate.dev/api/v2/cmdb/firewall/addrgrp/default.microservice1?access_token=test",
				func(req *http.Request) (*http.Response, error) {
					res, _ := httpmock.NewJsonResponse(200, responseMapSingleAddressGrp)
					return res, nil
				},
			)
			// Get a Firewall Address Group Object from mock'd FW and check it's name and members name.
			val, err := fc.GetFirewallAddressGroup("default.microservice1")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(val.Name).Should(Equal("default.microservice1"))
			Expect(val.Members[0]).Should(Equal("masternode-1"))
			Expect(val.Members[1]).Should(Equal("masternode-2"))
		})
	})
	It("Validate by reading all FortiGate Address Groups", func() {
		By("Reading all Address Group Objects", func() {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			// Get List of Firewall Address Objects and check it's length and name
			httpmock.RegisterResponder("GET", "https://fortigate.dev/api/v2/cmdb/firewall/addrgrp?access_token=test",
				func(req *http.Request) (*http.Response, error) {
					res, _ := httpmock.NewJsonResponse(200, responseMapTwoAddressGrp)
					return res, nil
				},
			)
			vals, err := fc.ListAllFirewallAddressGroups()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(len(vals)).Should(Equal(2))
			Expect(vals[1].Name).Should(Equal("default.microservice2"))
			Expect(vals[0].Name).Should(Equal("default.microservice1"))
			Expect(vals[0].Members[0]).Should(Equal("masternode-1"))
			Expect(vals[0].Members[1]).Should(Equal("masternode-2"))
			Expect(vals[1].Members[0]).ShouldNot(Equal("masternode-1"))
			Expect(vals[1].Members[1]).ShouldNot(Equal("masternode-1"))
		})
	})
	It("Validate by Modify FortiGate Address Group", func() {
		By("Modify Address Group Object testFwAddressGroup", func() {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			// Test by updating value of Address object
			httpmock.RegisterResponder("POST", "https://fortigate.dev/api/v2/cmdb/firewall/addrgrp/testAddrGrp-1?access_token=test",
				func(req *http.Request) (*http.Response, error) {
					r := req.Body
					body, err := io.ReadAll(r)
					if err != nil {
						return httpmock.NewStringResponse(500, err.Error()), nil
					}
					err = json.Unmarshal(body, &testFwAddressGroup)
					if err != nil {
						return httpmock.NewStringResponse(500, err.Error()), nil
					}
					response, _ := httpmock.NewJsonResponse(200, fwPostRes)
					return response, nil
				},
			)
			// Copy testFwAddress object into testAddr and modify object
			testAddrGrp := testFwAddressGroup
			testAddrGrp.Comment = "Modified"
			Expect(testAddrGrp.Comment).ShouldNot(Equal(testFwAddressGroup.Comment))
			// Send Modified object to Mocked Fw, this will modify testFwAddress
			err := fc.UpdateFirewallAddressGroup(testAddrGrp)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(testAddrGrp.Comment).Should(Equal(testFwAddressGroup.Comment))
		})
	})
	It("Validate FortiGate Address Groups", func() {
		By("Reading Invalid Address Group Objects", func() {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			// Test by reading an address object
			httpmock.RegisterResponder("GET", "https://fortigate.dev/api/v2/cmdb/firewall/addrgrp/default.microservice1?access_token=test",
				func(req *http.Request) (*http.Response, error) {
					res, _ := httpmock.NewJsonResponse(200, responseMapErrSingleAddressGrp)
					return res, nil
				},
			)
			// Get a invalid Firewall Address Group Object from mock'd FW and check it's name and members name.
			_, err := fc.GetFirewallAddressGroup("dummy")
			Expect(err).Should(HaveOccurred())
			// Get a valid Firewall Address Group Object from mock and check it's returns error.
			_, err = fc.GetFirewallAddressGroup("default.microservice1")
			fmt.Println(err)
			Expect(err).Should(HaveOccurred())

			// Reactivate Mock
			httpmock.DeactivateAndReset()
			httpmock.Activate()
			httpmock.RegisterResponder("POST", "https://fortigate.dev/api/v2/cmdb/firewall/addrgrp/testAddrGrp-1?access_token=test",
				func(req *http.Request) (*http.Response, error) {
					response, _ := httpmock.NewJsonResponse(200, fwPostErrRes)
					return response, nil
				},
			)
			testAddrGrp := testFwAddressGroup
			testAddrGrp.Name = "Dummy"
			// Update an Invalid Firewall Address Group
			err = fc.UpdateFirewallAddressGroup(testAddrGrp)
			Expect(err).Should(HaveOccurred())

			testAddrGrp = testFwAddressGroup
			// Update an valid Firewall Address Group, but expect Error from mock
			err = fc.UpdateFirewallAddressGroup(testAddrGrp)
			Expect(err).Should(HaveOccurred())
		})
	})
})

var _ = Describe("Fortigate URL construction", func() {

	It("construct correct Fortigate URL", func() {
		check := func(vdom string) {
			fc := fn.FortiGateClient{
				Name:        "",
				Ip:          "fortigate.dev",
				Vdom:        vdom,
				AccessToken: "test",
				Client:      nil,
			}
			actualURLString := fc.URL("api/v2/cmdb/address")
			actualURL, err := url.Parse(actualURLString)
			Expect(err).To(BeNil())
			Expect(actualURL.Scheme).Should(Equal("https"))
			Expect(actualURL.Host).Should(Equal("fortigate.dev"))
			values := actualURL.Query()
			Expect(values.Get("access_token")).Should(Equal("test"))
			Expect(values.Get("vdom")).Should(Equal(vdom))
		}
		Context("With VDOM", func() {
			check("morpheus")
		})
		Context("Without VDOM", func() {
			check("")
		})
	})
})
