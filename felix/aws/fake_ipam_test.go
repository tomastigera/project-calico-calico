// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package aws

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/testutils"
	calierrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

type ipamAlloc struct {
	Addr   ip.Addr
	Handle string
	Args   ipam.AutoAssignArgs
}

type fakeIPAM struct {
	lock sync.Mutex

	Errors testutils.ErrorProducer

	freeIPs     []string
	requests    []ipam.AutoAssignArgs
	allocations []ipamAlloc
	origNumIPs  int
}

func newFakeIPAM() *fakeIPAM {
	return &fakeIPAM{
		freeIPs: []string{
			calicoHostIP1Str,
			calicoHostIP2Str,
		},
		Errors: testutils.NewErrorProducer(),
	}
}

func (m *fakeIPAM) Allocations() []ipamAlloc {
	m.lock.Lock()
	defer m.lock.Unlock()
	out := make([]ipamAlloc, len(m.allocations))
	copy(out, m.allocations)
	return out
}

func (m *fakeIPAM) AutoAssign(ctx context.Context, args ipam.AutoAssignArgs) (*ipam.IPAMAssignments, *ipam.IPAMAssignments, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	logrus.Infof("FakeIPAM allocation request: %v", args)

	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	if err := m.Errors.NextErrorByCaller(); err != nil {
		return nil, nil, err
	}

	m.requests = append(m.requests, args)
	if args.Num6 > 0 {
		panic("IPV6 not supported")
	}
	if args.Num4 <= 0 {
		panic("expected some v4 addresses")
	}
	if args.HandleID == nil {
		return nil, nil, errors.New("missing handle")
	}
	if args.Hostname == "" {
		return nil, nil, errors.New("missing hostname")
	}
	if args.IntendedUse != v3.IPPoolAllowedUseHostSecondary {
		return nil, nil, errors.New("expected AllowedUseHostSecondary")
	}
	if len(args.AWSSubnetIDs) != 1 {
		return nil, nil, errors.New("AWSSubnetIDs to be set")
	}

	v4Allocs := &ipam.IPAMAssignments{
		IPs:          nil,
		IPVersion:    4,
		NumRequested: args.Num4,
	}
	for i := 0; i < args.Num4; i++ {
		if len(m.freeIPs) == 0 {
			return v4Allocs, nil, errors.New("couldn't alloc all IPs")
		}
		chosenIP := m.freeIPs[0]
		m.allocations = append(m.allocations, ipamAlloc{
			Addr:   ip.FromString(chosenIP),
			Handle: *args.HandleID,
			Args:   args,
		})
		m.freeIPs = m.freeIPs[1:]
		_, addr, err := cnet.ParseCIDROrIP(chosenIP)
		if err != nil {
			panic("failed to parse test IP")
		}
		v4Allocs.IPs = append(v4Allocs.IPs, *addr)
	}

	logrus.Infof("FakeIPAM allocation: %v", v4Allocs)

	return v4Allocs, nil, nil
}

func (m *fakeIPAM) ReleaseIPs(ctx context.Context, ips ...ipam.ReleaseOptions) ([]cnet.IP, []ipam.ReleaseOptions, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if err := m.Errors.NextErrorByCaller(); err != nil {
		return nil, nil, err
	}

	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	releaseCount := 0
	var out []cnet.IP
	var newAllocs []ipamAlloc
	for _, ipToRelease := range ips {
		logrus.Infof("Fake IPAM releasing IP: %v", ipToRelease.Address)
		addrToRelease := ip.FromString(ipToRelease.Address)
		for _, alloc := range m.allocations {
			if alloc.Addr == addrToRelease {
				out = append(out, addrToRelease.AsCalicoNetIP())
				releaseCount++
				m.freeIPs = append(m.freeIPs, alloc.Addr.String())
				continue
			}
			newAllocs = append(newAllocs, alloc)
		}
	}
	m.allocations = newAllocs

	if releaseCount != len(ips) {
		// TODO not sure how calico IPAM handles this
		panic("asked to release non-allocated IP")
	}

	return out, ips, nil
}

func (m *fakeIPAM) IPsByHandle(ctx context.Context, handleID string) ([]cnet.IP, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if err := m.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var out []cnet.IP
	for _, alloc := range m.allocations {
		if alloc.Handle == handleID {
			out = append(out, alloc.Addr.AsCalicoNetIP())
		}
	}

	if len(out) == 0 {
		return nil, calierrors.ErrorResourceDoesNotExist{
			Err:        fmt.Errorf("something from k8s"),
			Identifier: "id",
		}
	}

	logrus.Infof("Fake IPAM IPsByHandle %q = %v", handleID, out)

	return out, nil
}

func (m *fakeIPAM) NumFreeIPs() int {
	m.lock.Lock()
	defer m.lock.Unlock()

	return len(m.freeIPs)
}

func (m *fakeIPAM) NumUsedIPs() int {
	m.lock.Lock()
	defer m.lock.Unlock()

	return len(m.allocations)
}

func (m *fakeIPAM) setFreeIPs(ips ...string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.freeIPs = ips
}
