// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
package client

import (
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// compareStringSlice compares a slice of strings. Each item in the slice is compared side by side.
// Returns -1, 0 or 1 depending on the match condition.
func compareStringSlice(m, n []string) int {
	minLen := len(m)
	if lm := len(n); lm < minLen {
		minLen = lm
	}
	for i := 0; i < minLen; i++ {
		diff := strings.Compare(m[i], n[i])
		if diff != 0 {
			return diff
		}
	}
	return len(m) - len(n)
}

// compareIPv4StringSlice compares a slice of strings representing IPs. This differs from
// compareStringSlice since it requires breaking up the IP to do comparisons on the separate
// numbers that make it up. Ex: 10.10.1.1 should be larger than 10.9.1.1
func compareIPv4StringSlice(m, n []string) int {
	minLen := len(m)
	if lm := len(n); lm < minLen {
		minLen = lm
	}
	for i := 0; i < minLen; i++ {
		mIP := convertIPv4ToInt64(m[i])
		nIP := convertIPv4ToInt64(n[i])
		diff := mIP - nIP
		if diff != 0 {
			return int(diff)
		}
	}
	return len(m) - len(n)
}

// convertIPv4ToInt64 converts an IPv4 string into an int64 for easy comparison. This also
// converts the bit mask to an int so that can also be compared if necessary.
func convertIPv4ToInt64(ipString string) int64 {
	ipNumStrs := strings.Split(ipString, ".")
	if len(ipNumStrs) > 4 {
		// IP address provided is invalid. Return nothing.
		return 0
	}
	var ipInt int64
	var mask int
	for i := range 4 {
		ipNumStr := ipNumStrs[i]
		if strings.Contains(ipNumStr, "/") {
			split := strings.Split(ipNumStr, "/")
			ipNumStr = split[0]
			mask, _ = strconv.Atoi(split[1])
		}
		num, _ := strconv.ParseInt(ipNumStr, 10, 64)
		// Shift the bit octets over by 1 since the last octet will hold the mask
		ipInt = ipInt + (num * expBySquare64(int64(255), int64(4-i)))
	}
	// Add the mask value at the end of the int64
	ipInt = ipInt + int64(mask)
	return ipInt
}

// expBySquare64 gets the result of n to the exp power using exponentiation by squaring.
func expBySquare64(n, exp int64) int64 {
	base := int64(1)
	if exp%2 != 0 {
		base = base * n
		exp = exp - 1
	}
	for exp > 1 {
		base = base * base
		exp = exp / 2
	}
	return base
}

// sortNodes sorts the nodes based on the order requirements specified in the Page request.
func sortNodes(items []Node, s *Sort) {
	ns := nodeSorter{items: items}
	if s != nil {
		for _, sb := range s.SortBy {
			ndf, ok := nodeDiffFuncs[sb]
			if !ok {
				// Skip any sort column that is not valid.
				log.WithField("column", sb).Debug("Invalid node sort column - skipping")
				continue
			}
			ns.diff = append(ns.diff, ndf)
		}
		ns.reverse = s.Reverse
	}
	ns.diff = append(ns.diff, nodeDiffFuncs[nodeDefaultSortField])

	// Sort the entries using the specified sort columns.
	sort.Sort(ns)
}

type nodeDiffFunc func(p, q *Node) int

var nodeDiffFuncs = map[string]nodeDiffFunc{
	"name":                 func(p, q *Node) int { return strings.Compare(p.Name, q.Name) },
	"numHostEndpoints":     func(p, q *Node) int { return p.NumHostEndpoints - q.NumHostEndpoints },
	"numWorkloadEndpoints": func(p, q *Node) int { return p.NumWorkloadEndpoints - q.NumWorkloadEndpoints },
	"numEndpoints": func(p, q *Node) int {
		return p.NumWorkloadEndpoints + p.NumHostEndpoints - q.NumHostEndpoints - q.NumWorkloadEndpoints
	},
	"bgpIPAddresses": func(p, q *Node) int { return compareStringSlice(p.BGPIPAddresses, q.BGPIPAddresses) },
	"addresses":      func(p, q *Node) int { return compareStringSlice(p.Addresses, q.Addresses) },
}

const nodeDefaultSortField = "name"

type nodeSorter struct {
	items   []Node
	diff    []nodeDiffFunc
	reverse bool
}

func (s nodeSorter) Len() int {
	return len(s.items)
}
func (s nodeSorter) Less(i, j int) bool {
	p, q := &s.items[i], &s.items[j]
	for _, df := range s.diff {
		d := df(p, q)
		if d < 0 {
			return !s.reverse
		} else if d > 0 {
			return s.reverse
		}
	}
	return false
}
func (s nodeSorter) Swap(i, j int) {
	s.items[i], s.items[j] = s.items[j], s.items[i]
}

// sortEndpoints sorts the Endpoints based on the order requirements specified in the Page request.
func sortEndpoints(items []Endpoint, s *Sort) {
	ns := endpointSorter{items: items}
	if s != nil {
		for _, sb := range s.SortBy {
			ndf, ok := endpointDiffFuncs[sb]
			if !ok {
				// Skip any sort column that is not valid.
				log.WithField("column", sb).Debug("Invalid endpoints sort column - skipping")
				continue
			}
			ns.diff = append(ns.diff, ndf)
		}
		ns.reverse = s.Reverse
	}
	ns.diff = append(ns.diff, endpointDiffFuncs[endpointDefaultSortField1], endpointDiffFuncs[endpointDefaultSortField2])

	// Sort the entries using the specified sort columns.
	sort.Sort(ns)
}

type endpointDiffFunc func(p, q *Endpoint) int

var endpointDiffFuncs = map[string]endpointDiffFunc{
	"kind":                     func(p, q *Endpoint) int { return strings.Compare(p.Kind, q.Kind) },
	"name":                     func(p, q *Endpoint) int { return strings.Compare(p.Name, q.Name) },
	"namespace":                func(p, q *Endpoint) int { return strings.Compare(p.Namespace, q.Namespace) },
	"node":                     func(p, q *Endpoint) int { return strings.Compare(p.Node, q.Node) },
	"workload":                 func(p, q *Endpoint) int { return strings.Compare(p.Workload, q.Workload) },
	"orchestrator":             func(p, q *Endpoint) int { return strings.Compare(p.Orchestrator, q.Orchestrator) },
	"pod":                      func(p, q *Endpoint) int { return strings.Compare(p.Pod, q.Pod) },
	"interfaceName":            func(p, q *Endpoint) int { return strings.Compare(p.InterfaceName, q.InterfaceName) },
	"ipNetworks":               func(p, q *Endpoint) int { return compareIPv4StringSlice(p.IPNetworks, q.IPNetworks) },
	"numGlobalNetworkPolicies": func(p, q *Endpoint) int { return p.NumGlobalNetworkPolicies - q.NumGlobalNetworkPolicies },
	"numNetworkPolicies":       func(p, q *Endpoint) int { return p.NumNetworkPolicies - q.NumNetworkPolicies },
	"numPolicies": func(p, q *Endpoint) int {
		return p.NumGlobalNetworkPolicies + p.NumNetworkPolicies - q.NumGlobalNetworkPolicies - q.NumNetworkPolicies
	},
}

const endpointDefaultSortField1 = "name"
const endpointDefaultSortField2 = "namespace"

type endpointSorter struct {
	items   []Endpoint
	diff    []endpointDiffFunc
	reverse bool
}

func (s endpointSorter) Len() int {
	return len(s.items)
}
func (s endpointSorter) Less(i, j int) bool {
	p, q := &s.items[i], &s.items[j]
	for _, df := range s.diff {
		d := df(p, q)
		if d < 0 {
			return !s.reverse
		} else if d > 0 {
			return s.reverse
		}
	}
	return false
}
func (s endpointSorter) Swap(i, j int) {
	s.items[i], s.items[j] = s.items[j], s.items[i]
}

// sortPolicies sorts the Policies based on the order requirements specified in the Page request.
func sortPolicies(items []Policy, s *Sort) {
	ns := policySorter{items: items}
	if s != nil {
		for _, sb := range s.SortBy {
			ndf, ok := policyDiffFuncs[sb]
			if !ok {
				// Skip any sort column that is not valid.
				log.WithField("column", sb).Debug("Invalid policies sort column - skipping")
				continue
			}
			ns.diff = append(ns.diff, ndf)
		}
		ns.reverse = s.Reverse
	}
	ns.diff = append(ns.diff, policyDiffFuncs[policyDefaultSortField])

	// Sort the entries using the specified sort columns.
	sort.Sort(ns)
}

type policyDiffFunc func(p, q *Policy) int

var policyDiffFuncs = map[string]policyDiffFunc{
	"index":                func(p, q *Policy) int { return p.Index - q.Index },
	"kind":                 func(p, q *Policy) int { return strings.Compare(p.Kind, q.Kind) },
	"name":                 func(p, q *Policy) int { return strings.Compare(p.Name, q.Name) },
	"namespace":            func(p, q *Policy) int { return strings.Compare(p.Namespace, q.Namespace) },
	"tier":                 func(p, q *Policy) int { return strings.Compare(p.Tier, q.Tier) },
	"numHostEndpoints":     func(p, q *Policy) int { return p.NumHostEndpoints - q.NumHostEndpoints },
	"numWorkloadEndpoints": func(p, q *Policy) int { return p.NumWorkloadEndpoints - q.NumWorkloadEndpoints },
	"numEndpoints": func(p, q *Policy) int {
		return p.NumWorkloadEndpoints + p.NumHostEndpoints - q.NumHostEndpoints - q.NumWorkloadEndpoints
	},
	"order": func(p, q *Policy) int {
		if p.Order != nil && q.Order != nil {
			return int(*p.Order - *q.Order)
		} else if p.Order == nil && q.Order == nil {
			return 0
		} else if p.Order != nil {
			return 1
		} else if q.Order != nil {
			return -1
		}
		return 0
	},
	"creation-time": func(p, q *Policy) int {
		return int(p.CreationTime.Unix() - q.CreationTime.Unix())
	},
}

const policyDefaultSortField = "index"

type policySorter struct {
	items   []Policy
	diff    []policyDiffFunc
	reverse bool
}

func (s policySorter) Len() int {
	return len(s.items)
}
func (s policySorter) Less(i, j int) bool {
	p, q := &s.items[i], &s.items[j]
	for _, df := range s.diff {
		d := df(p, q)
		if d < 0 {
			return !s.reverse
		} else if d > 0 {
			return s.reverse
		}
	}
	return false
}
func (s policySorter) Swap(i, j int) {
	s.items[i], s.items[j] = s.items[j], s.items[i]
}
