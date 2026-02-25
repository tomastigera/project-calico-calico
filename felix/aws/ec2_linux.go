// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

//go:build linux

package aws

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func nlGetDefaultRouteLink(family int) (string, error) {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return "", err
	}

	for _, rt := range routes {
		if rt.Dst != nil {
			if ones, _ := rt.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		// nil or explicitly 0.0.0.0/0.
		link, err := netlink.LinkByIndex(rt.LinkIndex)
		if err != nil {
			return "", fmt.Errorf("link index %d: %q", rt.LinkIndex, err)
		}

		if attrs := link.Attrs(); attrs != nil {
			return attrs.Name, nil
		}

		return "", fmt.Errorf("link index %d: no attributes", rt.LinkIndex)
	}

	return "", fmt.Errorf("no default route")
}

func nlGetIfaceByMAC(mac net.HardwareAddr) (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", err
	}

	equal := func(a, b net.HardwareAddr) bool {
		if len(a) != len(b) {
			return false
		}

		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}

		return true
	}

	for _, link := range links {
		if attrs := link.Attrs(); attrs != nil && equal(attrs.HardwareAddr, mac) {
			return attrs.Name, nil
		}
	}

	return "", fmt.Errorf("no matching link for mac %s", mac)
}

func PrimaryInterfaceName() (string, error) {
	ifaceName := ""

	err := func() error {
		eksPrimaryENI, err := PrimaryInterface()
		if err != nil {
			return err
		}

		if eksPrimaryENI.MacAddress == nil {
			return fmt.Errorf("primary interface does not have MAC")
		}

		mac, err := net.ParseMAC(*eksPrimaryENI.MacAddress)
		if err != nil {
			return err
		}

		ifaceName, err = nlGetIfaceByMAC(mac)
		if err != nil {
			return err
		}

		return nil
	}()

	if err != nil {
		log.WithError(err).Warn("Failed to find primary EKS link name based on AWS api")

		ifaceName, err = nlGetDefaultRouteLink(netlink.FAMILY_ALL)
	}

	return ifaceName, err
}
