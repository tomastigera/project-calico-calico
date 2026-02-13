// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipsets

import (
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// For now, we only need four IPSets to stage different scenarios around adding, removing and updating members.
const numMembers int = 4

// Basic structure for a test case. The idea is to have at least one for each IPSetType.
type IPSetsMgrTestCase struct {
	ipsetID      string
	ipsetType    proto.IPSetUpdate_IPSetType
	ipsetMembers [numMembers]string
	dnsRecs      map[string][]string
}

// Main array of test cases. We pass each of these to the test routines during execution.
var ipsetsMgrTestCases = []IPSetsMgrTestCase{
	{
		ipsetID:      "id1",
		ipsetType:    proto.IPSetUpdate_IP,
		ipsetMembers: [numMembers]string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
		dnsRecs:      map[string][]string{},
	},
	{
		ipsetID:      "id2",
		ipsetType:    proto.IPSetUpdate_DOMAIN,
		ipsetMembers: [numMembers]string{"abc.com", "DEF.com", "gHi.CoM", "jkl.com"},
		dnsRecs: map[string][]string{
			"abc.com": {"10.0.0.10"},
			"def.com": {"10.0.0.20"},
			"ghi.com": {"10.0.0.30"},
			"jkl.com": {"10.0.0.40"},
		},
	},
}

type mockDomainStore struct {
	mappings map[string][]string
}

func (s *mockDomainStore) RegisterHandler(_ common.DomainInfoChangeHandler) {}

func (s *mockDomainStore) GetDomainIPs(domain string) []string {
	// The domainStore is case insensitive.
	return s.mappings[strings.ToLower(domain)]
}

func allIPsForDomains(mappings map[string][]string, domains ...string) (ips []string) {
	for _, domain := range domains {
		// The domainStore is case insensitive.
		ips = append(ips, mappings[strings.ToLower(domain)]...)
	}
	return
}

var _ = Describe("IP Sets manager", func() {
	var (
		ipsetsMgr   *IPSetsManager
		ipSets      *MockIPSets
		domainStore *mockDomainStore
	)

	BeforeEach(func() {
		domainStore = &mockDomainStore{mappings: make(map[string][]string)}
		ipSets = NewMockIPSets()
		ipsetsMgr = NewIPSetsManager("ipv4", ipSets, 1024, domainStore)
	})

	// Generic assumptions used during tests. Having them here reduces code duplication and improves readability.
	AssertIPSetMembers := func(id string, members []string) {
		It("IPSet should have the right members", func() {
			Expect(ipSets.Members[id]).To(Equal(set.FromArray(members)))
		})
	}

	AssertIPSetNoMembers := func(id string) {
		It("IPSet should have no members", func() {
			Expect(ipSets.Members[id]).To(BeNil())
		})
	}

	AssertIPSetModified := func() {
		It("IPSet should be modified", func() {
			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
		})
	}

	AssertIPSetNotModified := func() {
		It("IPSet should not be modified", func() {
			Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		})
	}

	// Basic add/remove/update test case for different types of IPSets.
	IPsetsMgrTest1 := func(ipsetID string, ipsetType proto.IPSetUpdate_IPSetType, members [numMembers]string, dnsMappings map[string][]string) {
		Describe("after creating an IPSet", func() {
			BeforeEach(func() {
				ipSets.AddOrReplaceCalled = false
				domainStore.mappings = dnsMappings
				ipsetsMgr.OnUpdate(&proto.IPSetUpdate{
					Id:      ipsetID,
					Members: []string{members[0], members[1]},
					Type:    ipsetType,
				})
				err := ipsetsMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			AssertIPSetModified()

			// We match domain ipsets with their respective IP addresses.
			if ipsetType == proto.IPSetUpdate_DOMAIN {
				AssertIPSetMembers(ipsetID, allIPsForDomains(dnsMappings, members[0], members[1]))
			} else {
				AssertIPSetMembers(ipsetID, []string{members[0], members[1]})
			}

			Describe("after sending a delta update", func() {
				BeforeEach(func() {
					ipSets.AddOrReplaceCalled = false
					domainStore.mappings = dnsMappings
					ipsetsMgr.OnUpdate(&proto.IPSetDeltaUpdate{
						Id:             ipsetID,
						AddedMembers:   []string{members[2], members[3]},
						RemovedMembers: []string{members[1]},
					})
					err := ipsetsMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})

				AssertIPSetNotModified()

				if ipsetType == proto.IPSetUpdate_DOMAIN {
					AssertIPSetMembers(ipsetID, allIPsForDomains(dnsMappings, members[0], members[2], members[3]))
				} else {
					AssertIPSetMembers(ipsetID, []string{members[0], members[2], members[3]})
				}

				Describe("after sending a delete", func() {
					BeforeEach(func() {
						domainStore.mappings = dnsMappings
						ipsetsMgr.OnUpdate(&proto.IPSetRemove{
							Id: ipsetID,
						})
						err := ipsetsMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
					})
					AssertIPSetNoMembers(ipsetID)
				})
			})

			Describe("after sending another replace", func() {
				BeforeEach(func() {
					ipSets.AddOrReplaceCalled = false
					domainStore.mappings = dnsMappings
					ipsetsMgr.OnUpdate(&proto.IPSetUpdate{
						Id:      ipsetID,
						Members: []string{members[1], members[2]},
						Type:    ipsetType,
					})
					err := ipsetsMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})

				if ipsetType == proto.IPSetUpdate_DOMAIN {
					AssertIPSetMembers(ipsetID, allIPsForDomains(dnsMappings, members[1], members[2]))
				} else {
					AssertIPSetModified()
					AssertIPSetMembers(ipsetID, []string{members[1], members[2]})
				}
			})

			if ipsetType == proto.IPSetUpdate_DOMAIN {
				Describe("after timing out the mIxEdCaSe DNS entries in lowercase", func() {
					BeforeEach(func() {
						ipSets.AddOrReplaceCalled = false
						ipsetsMgr.OnUpdate(&proto.IPSetUpdate{
							Id:      ipsetID,
							Members: []string{members[1], members[2]},
							Type:    ipsetType,
						})
						err := ipsetsMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
						domainStore.mappings = map[string][]string{
							members[2]: domainStore.GetDomainIPs(members[2]),
						}
						syncNeeded := ipsetsMgr.OnDomainChange(strings.ToLower(members[1]))
						Expect(syncNeeded).To(BeTrue())
						err = ipsetsMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
					})

					AssertIPSetMembers(ipsetID, allIPsForDomains(dnsMappings, members[2]))
				})
			}
		})
	}

	for _, testCase := range ipsetsMgrTestCases {
		IPsetsMgrTest1(testCase.ipsetID, testCase.ipsetType, testCase.ipsetMembers, testCase.dnsRecs)
	}
})

func TestIPSetsManager_GetIPSetMembers(t *testing.T) {
	RegisterTestingT(t)

	domainStore := &mockDomainStore{mappings: make(map[string][]string)}
	ipsetsMgr := NewIPSetsManager("ipv4", nil, 1024, domainStore)

	t.Run("should not panic for BaseIPSetDataplane", func(t *testing.T) {
		baseIPSetsDataplane := &MockBaseIPSets{}
		ipsetsMgr.AddDataplane(baseIPSetsDataplane)

		defer func() {
			Expect(recover()).To(BeNil())
		}()
		_, err := ipsetsMgr.GetIPSetMembers("test-ipset")
		Expect(err).ToNot(HaveOccurred())
	})

	t.Run("should return members for IPSetDataplane", func(t *testing.T) {
		ipsetDataplane := &MockIPSets{
			Members: map[string]set.Set[string]{
				"test-ipset": set.From("192.168.1.1"),
			},
		}

		ipsetsMgr.AddDataplane(ipsetDataplane)
		members, err := ipsetsMgr.GetIPSetMembers("test-ipset")
		Expect(err).ToNot(HaveOccurred())
		Expect(members.ContainsAll(set.FromArray([]string{"192.168.1.1"}))).To(BeTrue())

		// Test case where the IPSet is found but has multiple members.
		ipsetDataplane.Members["test-ipset"] = set.From("192.168.1.1", "192.168.1.2")
		members, err = ipsetsMgr.GetIPSetMembers("test-ipset")
		Expect(err).ToNot(HaveOccurred())
		Expect(members.ContainsAll(set.FromArray([]string{"192.168.1.1", "192.168.1.2"}))).To(BeTrue())
	})
}

type MockBaseIPSets struct{}

func (m *MockBaseIPSets) AddOrReplaceIPSet(setMetadata ipsets.IPSetMetadata, members []string) {}
func (m *MockBaseIPSets) AddMembers(setID string, newMembers []string)                         {}
func (m *MockBaseIPSets) RemoveMembers(setID string, removedMembers []string)                  {}
func (m *MockBaseIPSets) RemoveIPSet(setID string)                                             {}
func (m *MockBaseIPSets) GetIPFamily() ipsets.IPFamily {
	return ipsets.IPFamilyV4
}
func (m *MockBaseIPSets) GetTypeOf(setID string) (ipsets.IPSetType, error) {
	return ipsets.IPSetTypeHashIP, nil
}
func (m *MockBaseIPSets) GetMembers(setID string) ([]string, error) {
	return nil, nil
}
