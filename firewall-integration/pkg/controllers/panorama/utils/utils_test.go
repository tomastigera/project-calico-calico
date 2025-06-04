// Copyright 2021-2025 Tigera Inc. All rights reserved.
package utils

import (
	"errors"
	"fmt"
	"strings"

	panw "github.com/PaloAltoNetworks/pango"
	"github.com/PaloAltoNetworks/pango/objs/addr"
	"github.com/PaloAltoNetworks/pango/objs/addrgrp"
	dvgrp "github.com/PaloAltoNetworks/pango/pnrm/dg"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/projectcalico/calico/firewall-integration/tests/mocks"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	addressesDeviceGroup1Test = []addr.Entry{
		{
			Name:        "address1",
			Value:       "10.10.10.10/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address2",
			Value:       "10.10.10.11/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag2", "tag3"}, // ordered
		},
		{
			Name:        "address3",
			Value:       "10.10.10.12/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address4",
			Value:       "10.10.10.13/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address5",
			Value:       "10.10.10.14/32",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address6",
			Value:       "10.10.10.14/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address7",
			Value:       "www.tigera-test1.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address8",
			Value:       "www.tigera-test6.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address9",
			Value:       "www.tigera-test5.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address10",
			Value:       "www.tigera-test4.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address25",
			Value:       "www.tigera-test2.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address11",
			Value:       "192.168.0.1-192.168.0.15",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address12",
			Value:       "222.168.0.1-222.168.0.111",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag3"}, // ordered
		},
		{
			Name:        "address13",
			Value:       "192.167.0.1-192.167.0.22",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address14",
			Value:       "10.168.0.1-10.168.0.34",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag2", "tag3"}, // ordered
		},
		{
			Name:        "address15",
			Value:       "10.12.0.1-11.10.0.85",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address16",
			Value:       "25.168.0.1-25.168.0.4",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address17",
			Value:       "111.9.0.1-111.9.0.111",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address18",
			Value:       "192.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address19",
			Value:       "222.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag3"}, // ordered
		},
		{
			Name:        "address20",
			Value:       "192.167.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address21",
			Value:       "10.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag2", "tag3"}, // ordered
		},
		{
			Name:        "address22",
			Value:       "10.12.0.1/10.0.0.33",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address23",
			Value:       "25.168.0.1/10.1.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address24",
			Value:       "111.9.0.1/9.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address25",
			Value:       "222.222.221.14/5",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"%^@$&and%$*^OR(& () (__*+~`\"$# @!$"}, // ordered
		},
	}

	addressesDeviceGroup2Test = []addr.Entry{
		{
			Name:        "address1",
			Value:       "10.10.10.10/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address2",
			Value:       "10.10.10.11/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{}, // ordered
		},
		{
			Name:        "address3",
			Value:       "10.10.10.12/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address4",
			Value:       "10.10.10.13/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address5",
			Value:       "10.10.10.14/32",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address6",
			Value:       "10.10.10.14/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address7",
			Value:       "www.tigera-test1.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address8",
			Value:       "www.tigera-test6.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address9",
			Value:       "www.tigera-test5.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{}, // ordered
		},
		{
			Name:        "address10",
			Value:       "www.tigera-test4.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address25",
			Value:       "www.tigera-test2.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address11",
			Value:       "192.168.0.1-192.168.0.15",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address12",
			Value:       "222.168.0.1-222.168.0.111",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag3"}, // ordered
		},
		{
			Name:        "address13",
			Value:       "192.167.0.1-192.167.0.22",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address14",
			Value:       "10.168.0.1-10.168.0.34",
			Type:        IpRange,
			Description: "",
			Tags:        []string{}, // ordered
		},
		{
			Name:        "address15",
			Value:       "10.12.0.1-11.10.0.85",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address16",
			Value:       "25.168.0.1-25.168.0.4",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address17",
			Value:       "111.9.0.1-111.9.0.111",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address18",
			Value:       "192.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address19",
			Value:       "222.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag3"}, // ordered
		},
		{
			Name:        "address20",
			Value:       "192.167.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{}, // ordered
		},
		{
			Name:        "address21",
			Value:       "10.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag2", "tag3"}, // ordered
		},
		{
			Name:        "address22",
			Value:       "10.12.0.1/10.0.0.33",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address23",
			Value:       "25.168.0.1/10.1.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address24",
			Value:       "111.9.0.1/9.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
	}

	addressesDeviceGroup3Test = []addr.Entry{
		{
			Name:        "address1",
			Value:       "10.10.10.10/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1", "%^@$&and%$*^OR(& () (__*+~`\"$# @!$", "tag3"}, // ordered
		},
		{
			Name:        "address2",
			Value:       "10.10.10.11/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{}, // ordered
		},
		{
			Name:        "address3",
			Value:       "10.10.10.12/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1", "%^@$&and%$*^OR(& () (__*+~`\"$# @!$"}, // ordered
		},
		{
			Name:        "address4",
			Value:       "10.10.10.13/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address5",
			Value:       "10.10.10.14/32",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'"}, // ordered
		},
		{
			Name:        "address6",
			Value:       "10.10.10.14/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address7",
			Value:       "www.tigera-test1.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1", "'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'", "tag3"}, // ordered
		},
		{
			Name:        "address8",
			Value:       "www.tigera-test6.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address9",
			Value:       "www.tigera-test5.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{}, // ordered
		},
		{
			Name:        "address10",
			Value:       "www.tigera-test4.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address25",
			Value:       "www.tigera-test2.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'"}, // ordered
		},
		{
			Name:        "address11",
			Value:       "192.168.0.1-192.168.0.15",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'", "tag3"}, // ordered
		},
		{
			Name:        "address12",
			Value:       "222.168.0.1-222.168.0.111",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag3"}, // ordered
		},
		{
			Name:        "address13",
			Value:       "192.167.0.1-192.167.0.22",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'"}, // ordered
		},
		{
			Name:        "address14",
			Value:       "10.168.0.1-10.168.0.34",
			Type:        IpRange,
			Description: "",
			Tags:        []string{}, // ordered
		},
		{
			Name:        "address15",
			Value:       "10.12.0.1-11.10.0.85",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address16",
			Value:       "25.168.0.1-25.168.0.4",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'"}, // ordered
		},
		{
			Name:        "address17",
			Value:       "111.9.0.1-111.9.0.111",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address18",
			Value:       "192.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'", "tag3"}, // ordered
		},
		{
			Name:        "address19",
			Value:       "222.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag3"}, // ordered
		},
		{
			Name:        "address20",
			Value:       "192.167.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{}, // ordered
		},
		{
			Name:        "address21",
			Value:       "10.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'", "tag3"}, // ordered
		},
		{
			Name:        "address22",
			Value:       "10.12.0.1/10.0.0.33",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address23",
			Value:       "25.168.0.1/10.1.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'"}, // ordered
		},
		{
			Name:        "address24",
			Value:       "111.9.0.1/9.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
	}

	addressesDeviceGroup4Test = []addr.Entry{
		{
			Name:        "address1",
			Value:       "10.10.10.10/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address2",
			Value:       "10.10.10.11/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag2", "tag3"}, // ordered
		},
		{
			Name:        "address3",
			Value:       "10.10.10.12/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address4",
			Value:       "10.10.10.13/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address5",
			Value:       "10.10.10.14/32",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address6",
			Value:       "10.10.10.14/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address7",
			Value:       "www.tigera-test1.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address8",
			Value:       "www.tigera-test6.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address9",
			Value:       "www.tigera-test5.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address10",
			Value:       "www.tigera-test4.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address25",
			Value:       "www.tigera-test2.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address11",
			Value:       "192.168.0.1-192.168.0.15",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address12",
			Value:       "222.168.0.1-222.168.0.111",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag3"}, // ordered
		},
		{
			Name:        "address13",
			Value:       "192.167.0.1-192.167.0.22",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address14",
			Value:       "10.168.0.1-10.168.0.34",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag2", "tag3"}, // ordered
		},
		{
			Name:        "address15",
			Value:       "10.12.0.1-11.10.0.85",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address16",
			Value:       "25.168.0.1-25.168.0.4",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address17",
			Value:       "111.9.0.1-111.9.0.111",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address18",
			Value:       "192.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address19",
			Value:       "222.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag3"}, // ordered
		},
		{
			Name:        "address20",
			Value:       "192.167.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address21",
			Value:       "10.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag2", "tag3"}, // ordered
		},
		{
			Name:        "address22",
			Value:       "10.12.0.1/10.0.0.33",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address23",
			Value:       "25.168.0.1/10.1.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address24",
			Value:       "111.9.0.1/9.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
	}

	addressesDeviceGroup5Test = []addr.Entry{
		{
			Name:        "address1",
			Value:       "10.10.10.10/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"8$`()5043jgfj$%#", "tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address2",
			Value:       "10.10.10.11/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag2", "tag3"}, // ordered
		},
		{
			Name:        "address3",
			Value:       "10.10.10.12/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address4",
			Value:       "10.10.10.13/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address5",
			Value:       "10.10.10.14/32",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address6",
			Value:       "10.10.10.14/31",
			Type:        IpNetmask,
			Description: "",
			Tags:        []string{"8$`()5043jgfj$%#", "tag3"}, // ordered
		},
		{
			Name:        "address7",
			Value:       "www.tigera-test1.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address8",
			Value:       "www.tigera-test6.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
		{
			Name:        "address9",
			Value:       "www.tigera-test5.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address10",
			Value:       "www.tigera-test4.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"8$`()5043jgfj$%#", "tag1"}, // ordered
		},
		{
			Name:        "address25",
			Value:       "www.tigera-test2.gr",
			Type:        Fqdn,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address11",
			Value:       "192.168.0.1-192.168.0.15",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address12",
			Value:       "222.168.0.1-222.168.0.111",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"8$`()5043jgfj$%#", "tag1", "tag3"}, // ordered
		},
		{
			Name:        "address13",
			Value:       "192.167.0.1-192.167.0.22",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1", "tag2"}, // ordered
		},
		{
			Name:        "address14",
			Value:       "10.168.0.1-10.168.0.34",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag2", "tag3"}, // ordered
		},
		{
			Name:        "address15",
			Value:       "10.12.0.1-11.10.0.85",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address16",
			Value:       "25.168.0.1-25.168.0.4",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address17",
			Value:       "111.9.0.1-111.9.0.111",
			Type:        IpRange,
			Description: "",
			Tags:        []string{"8$`()5043jgfj$%#", "tag3"}, // ordered
		},
		{
			Name:        "address18",
			Value:       "192.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
		},
		{
			Name:        "address19",
			Value:       "222.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1", "tag3"}, // ordered
		},
		{
			Name:        "address20",
			Value:       "192.167.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"8$`()5043jgfj$%#", "tag2"}, // ordered
		},
		{
			Name:        "address21",
			Value:       "10.168.0.1/10.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag2", "tag3"}, // ordered
		},
		{
			Name:        "address22",
			Value:       "10.12.0.1/10.0.0.33",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag1"}, // ordered
		},
		{
			Name:        "address23",
			Value:       "25.168.0.1/10.1.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag2"}, // ordered
		},
		{
			Name:        "address24",
			Value:       "111.9.0.1/9.0.0.15",
			Type:        IpWildcard,
			Description: "",
			Tags:        []string{"tag3"}, // ordered
		},
	}

	addressGroupsDeviceGroup1Test = []addrgrp.Entry{
		{
			Name:            "address_group1",
			Description:     "",
			StaticAddresses: []string{},
			DynamicMatch:    "tag1",
			Tags:            []string{"tag1"},
		},
		{
			Name:            "address_group2",
			Description:     "",
			StaticAddresses: []string{"address5, address3, address11"},
			DynamicMatch:    "",
			Tags:            []string{"tag2", "tag3"},
		},
		{
			Name:            "address_group3",
			Description:     "",
			StaticAddresses: []string{},
			DynamicMatch:    "tag1 OR tag3",
			Tags:            []string{"tag3"},
		},
		{
			Name:            "address_group4",
			Description:     "",
			StaticAddresses: []string{},
			DynamicMatch:    "tag1 AND tag2",
			Tags:            []string{"tag1", "tag3"},
		},
		{
			Name:            "address_group5",
			Description:     "",
			StaticAddresses: []string{"address4", "address7", "address1", "address10"},
			DynamicMatch:    "",
			Tags:            []string{"tag1", "tag3"},
		},
		{
			Name:            "address_group6",
			Description:     "",
			StaticAddresses: []string{"address2", "address7", "address5", "address1", "address4"},
			DynamicMatch:    "",
			Tags:            []string{"tag1", "tag2"},
		},
		{
			Name:            "address_group7",
			Description:     "",
			StaticAddresses: []string{},
			DynamicMatch:    "tag1 OR ('tag3' AND tag2)",
			Tags:            []string{"tag1", "tag3"},
		},
		{
			Name:            "address_group8",
			Description:     "",
			StaticAddresses: []string{},
			DynamicMatch:    "tag1 OR('tag3'AND tag2)",
			Tags:            []string{"tag1", "tag3"},
		},
		{
			Name:            "address_group9",
			Description:     "",
			StaticAddresses: []string{},
			DynamicMatch:    "tag1 OR \"8$`()5043jgfj$%#\" OR tag6",
			Tags:            []string{"8$`()5043jgfj$%#", "tag3"},
		},
		{
			Name:            "address_group10",
			Description:     "",
			StaticAddresses: []string{},
			DynamicMatch:    "(\"tag1\" AND tag2) OR tag6",
			Tags:            []string{"tag2"},
		},
		{
			Name:            "address_group11",
			Description:     "",
			StaticAddresses: []string{},
			DynamicMatch:    "'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'OR\"8$`()5043jgfj$%#\"",
			Tags:            []string{"tag1", "tag3"},
		},
	}

	deviceGroupsTest1 = dvgrp.Entry{
		Name: "device_group1",
	}
)

// GetAddressGroups
var _ = DescribeTable(
	"GetAddressGroups",
	func(tags []string, dg string, addrs []addr.Entry, addrgrps []addrgrp.Entry, expectedAddresses []Addresses) {
		filter := set.FromArray(tags)

		// Define a mock Panorama client.
		mc := &mocks.MockPanoramaClient{}
		mc.On("GetAddressEntries", dg).Return(addrs, nil)
		mc.On("GetAddressGroupEntries", dg).Return(addrgrps, nil)
		mc.On("GetClient").Return(&panw.Panorama{})
		mc.On("GetDeviceGroupEntry", dg).Return(deviceGroupsTest1.Name, nil)
		mc.On("GetDeviceGroups").Return([]string{""}, nil)

		// For this test GetAddressGroupEntries has been defined to return the list of address groups
		// defined by addressGroupsDeviceGroup1Test.
		//
		// Verify address groups are tagged appropriately and their dynamic, or statically mapped
		// addresses are the expected ones, by comparing the address buckets returned.
		addressGroups, _ := GetAddressGroups(mc, filter, dg)
		for i, addressGroup := range addressGroups {
			Expect(addressGroup.Addresses).To(Equal(expectedAddresses[i]))
		}
	},
	Entry(
		"Device Group 1",
		[]string{},
		"device_group1",
		addressesDeviceGroup1Test,
		addressGroupsDeviceGroup1Test,
		[]Addresses{{}},
	),
	Entry(
		"Device Group 1",
		[]string{"8$`()5043jgfj$%#"},
		"device_group1",
		addressesDeviceGroup1Test,
		addressGroupsDeviceGroup1Test,
		[]Addresses{
			{
				[]string{"10.10.10.10/31", "10.10.10.12/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr", "www.tigera-test5.gr"},
				[]string{"10.12.0.1-11.10.0.85", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "192.167.0.1/10.0.0.15", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
		},
	),
	Entry(
		"Device Group 1",
		[]string{"tag1", "tag3"},
		"device_group1",
		addressesDeviceGroup1Test,
		addressGroupsDeviceGroup1Test,
		[]Addresses{
			{
				[]string{"10.10.10.10/31", "10.10.10.12/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr", "www.tigera-test5.gr"},
				[]string{"10.12.0.1-11.10.0.85", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "192.167.0.1/10.0.0.15", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
			{
				[]string{},
				[]string{},
				[]string{},
				[]string{},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.11/31", "10.10.10.12/31", "10.10.10.13/31", "10.10.10.14/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr", "www.tigera-test5.gr", "www.tigera-test6.gr"},
				[]string{"10.12.0.1-11.10.0.85", "10.168.0.1-10.168.0.34", "111.9.0.1-111.9.0.111", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "10.168.0.1/10.0.0.15", "111.9.0.1/9.0.0.15", "192.167.0.1/10.0.0.15", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.12/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test5.gr"},
				[]string{"192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15"},
				[]string{"192.167.0.1/10.0.0.15", "192.168.0.1/10.0.0.15"},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr"},
				[]string{},
				[]string{},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.11/31", "10.10.10.13/31", "10.10.10.14/32"},
				[]string{"www.tigera-test1.gr"},
				[]string{},
				[]string{},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.11/31", "10.10.10.12/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr", "www.tigera-test5.gr"},
				[]string{"10.12.0.1-11.10.0.85", "10.168.0.1-10.168.0.34", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "10.168.0.1/10.0.0.15", "192.167.0.1/10.0.0.15", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.11/31", "10.10.10.12/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr", "www.tigera-test5.gr"},
				[]string{"10.12.0.1-11.10.0.85", "10.168.0.1-10.168.0.34", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "10.168.0.1/10.0.0.15", "192.167.0.1/10.0.0.15", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.12/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr", "www.tigera-test5.gr"},
				[]string{"10.12.0.1-11.10.0.85", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "192.167.0.1/10.0.0.15", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
			{
				[]string{"222.222.221.14/5"},
				[]string{},
				[]string{},
				[]string{},
			},
		},
	),
	Entry(
		"Device Group 1",
		[]string{"tag1", "tag3"},
		"device_group1",
		addressesDeviceGroup2Test,
		addressGroupsDeviceGroup1Test,
		[]Addresses{
			{
				[]string{"10.10.10.10/31", "10.10.10.12/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr"},
				[]string{"10.12.0.1-11.10.0.85", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
			{
				[]string{},
				[]string{},
				[]string{},
				[]string{},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.12/31", "10.10.10.13/31", "10.10.10.14/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr", "www.tigera-test6.gr"},
				[]string{"10.12.0.1-11.10.0.85", "111.9.0.1-111.9.0.111", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "10.168.0.1/10.0.0.15", "111.9.0.1/9.0.0.15", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.12/31"},
				[]string{"www.tigera-test1.gr"},
				[]string{"192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15"},
				[]string{"192.168.0.1/10.0.0.15"},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr"},
				[]string{},
				[]string{},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.11/31", "10.10.10.13/31", "10.10.10.14/32"},
				[]string{"www.tigera-test1.gr"},
				[]string{},
				[]string{},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.12/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr"},
				[]string{"10.12.0.1-11.10.0.85", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "10.168.0.1/10.0.0.15", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.12/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr"},
				[]string{"10.12.0.1-11.10.0.85", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "10.168.0.1/10.0.0.15", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
			{
				[]string{"10.10.10.10/31", "10.10.10.12/31", "10.10.10.13/31"},
				[]string{"www.tigera-test1.gr", "www.tigera-test4.gr"},
				[]string{"10.12.0.1-11.10.0.85", "192.167.0.1-192.167.0.22", "192.168.0.1-192.168.0.15", "222.168.0.1-222.168.0.111"},
				[]string{"10.12.0.1/10.0.0.33", "192.168.0.1/10.0.0.15", "222.168.0.1/10.0.0.15"},
			},
			{
				[]string{},
				[]string{},
				[]string{},
				[]string{},
			},
		},
	),
)

// QueryDeviceGroup
var _ = DescribeTable(
	"QueryDeviceGroup",
	func(dg string, dgerr error, expectedError error) {
		// Context defined for MockDeviceGroupPanoramaClientTest adjusts the output of
		// GetDeviceGroupEntry per entry.
		mc := &mocks.MockPanoramaClient{}
		mc.On("GetDeviceGroups").Return([]string{dg}, dgerr)

		// Verify that the device group query returns a valid response depending on the queried name,
		// and the value returned by the GetDeviceGroupEntry call to Panorama.
		err := QueryDeviceGroup(mc, dg)
		if expectedError == nil {
			Expect(err).To(BeNil())
		} else {
			Expect(err).To(Equal(expectedError))
		}
	},
	Entry(
		"Some device group",
		"device_group1",
		nil,
		nil,
	),
	Entry(
		"Some device group returns an error",
		"device_group1",
		errors.New("device group does not exist"),
		errors.New("device group does not exist"),
	),
	Entry(
		"Shared device group",
		"shared",
		nil,
		nil,
	),
	Entry(
		"Shared device group where GetDeviceGroups returns an error.",
		"shared",
		errors.New("device group does not exist"),
		nil,
	),
	Entry(
		"Shared where GetDeviceGroups returns non empty device group struct and an error.",
		"shared",
		errors.New("device group does not exist"),
		nil,
	),
)

// isValidRFC1123Name
var _ = DescribeTable(
	"isValidRFC1123Name",
	func(name string, expectedVal bool) {
		// Verify that the converted match is converted correctly.
		containsOnlyRFC1123Chars := isValidRFC1123Name(name)
		Expect(containsOnlyRFC1123Chars).To(Equal(expectedVal))
	},
	Entry(
		"Empty string",
		"",
		false,
	),
	Entry(
		"single character alhpabetic",
		"a",
		true,
	),
	Entry(
		"single character digit",
		"9",
		true,
	),
	Entry(
		"single character (.))",
		".",
		false,
	),
	Entry(
		"single character (-))",
		"-",
		false,
	),
	Entry(
		"simple name",
		"somename",
		true,
	),
	Entry(
		"simple name with a hyphen",
		"some-name",
		true,
	),
	Entry(
		"simple name with a period",
		"some.name",
		true,
	),
	Entry(
		"simple name with a period and a hyphen",
		"som-e.n-ame",
		true,
	),
	Entry(
		"simple name with a period and a hyphen and digits",
		"s9om-e.n-a0me",
		true,
	),
	Entry(
		"simple name with a period the invalid character (~)",
		"s~om-e.n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (!)",
		"s!om-e.n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (@)",
		"s@om-e.n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (`)",
		"s`om-e.n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (`)",
		"s`om-e.n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (#)",
		"som-e.n-a#me",
		false,
	),
	Entry(
		"simple name with a period an invalid character ($)",
		"som-e.$n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (%)",
		"som-e.%n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (^)",
		"som-^e.n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (&)",
		"som-&e.n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (*)",
		"som-e.*n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (()",
		"som-(e.n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character ())",
		"som-)e.n-ame",
		false,
	),
	Entry(
		"simple name with a period an invalid character (+)",
		"som-e.+n-ame",
		false,
	),
	Entry(
		"Name with invalid prefix (.).",
		".so9m-e.n-ame",
		false,
	),
	Entry(
		"Name with invalid prefix (-)",
		"-so9m-e.n-ame",
		false,
	),
	Entry(
		"Name with invalid suffix (.)",
		"so9m-e.n-ame.",
		false,
	),
	Entry(
		"Name with invalid suffix (-)",
		"so9m-e.n-ame-",
		false,
	),
	Entry(
		"Name with valid multiple (-)",
		"so9m-----e.n-ame",
		true,
	),
	Entry(
		"Name with invalid (.-)",
		"so9m-----e.-a.n-ame",
		false,
	),
)

// getRFC1123Name
var _ = DescribeTable(
	"getRFC1123Name",
	func(name, expectedName string, expectedConversion bool) {
		// Verify that the converted match is converted correctly.
		rfc1123Name := GetRFC1123Name(name)
		Expect(rfc1123Name).To(Equal(expectedName))
		namesDiffer := rfc1123Name != name
		Expect(namesDiffer).To(Equal(expectedConversion))
		isLessThanDNS1123LabelMaxLength := len(rfc1123Name) <= k8svalidation.DNS1123LabelMaxLength
		Expect(isLessThanDNS1123LabelMaxLength).To(BeTrue())
	},
	Entry(
		"Empty string",
		"",
		"z-seoc8",
		true,
	),
	Entry(
		"Contains a-z characters",
		"abcdefghijklmnopqrstuvwxyz",
		"abcdefghijklmnopqrstuvwxyz",
		false,
	),
	Entry(
		"Contains 0-9 characters",
		"0123456789",
		"0123456789",
		false,
	),
	Entry(
		"Contains a-z,0-9 characters, starts with a character",
		"g0a1b2c3d4e5f6g7h8i9j",
		"g0a1b2c3d4e5f6g7h8i9j",
		false,
	),
	Entry(
		"Contains a-z,0-9 characters, starts with a digit",
		"0a1b2c3d4e5f6g7h8i9j",
		"0a1b2c3d4e5f6g7h8i9j",
		false,
	),
	Entry(
		"Contains a-z,0-9,(.) characters, starts with a digit, a digit follows a (.)",
		"0a1b2c3d4e.5f6g7h8i9j",
		"0a1b2c3d4e.5f6g7h8i9j",
		false,
	),
	Entry(
		"Contains a-z,0-9,(.),(-) characters",
		"0a1b-2c3d4e.5f6g7h-8i9j",
		"0a1b-2c3d4e.5f6g7h-8i9j",
		false,
	),
	Entry(
		"Contains a-z,0-9,(.),(-) characters, with an invalid prefix (.)",
		".0a1b-2c3d4e.5f6g7h-8i9j",
		"0a1b-2c3d4e.5f6g7h-8i9j-k17sm",
		true,
	),
	Entry(
		"Contains a-z,0-9,(.),(-) characters, with an invalid prefix (-)",
		"-0a1b-2c3d4e.5f6g7h-8i9j",
		"0a1b-2c3d4e.5f6g7h-8i9j-sr1s8",
		true,
	),
	Entry(
		"Contains a-z,0-9,(.),(-) characters, with an invalid suffix (.)",
		"0a1b-2c3d4e.5f6g7h-8i9j.",
		"0a1b-2c3d4e.5f6g7h-8i9j-uhnh5",
		true,
	),
	Entry(
		"Contains a-z,0-9,(.),(-) characters, with an invalid suffix (-)",
		"0a1b-2c3d4e.5f6g7h-8i9j-",
		"0a1b-2c3d4e.5f6g7h-8i9j-i8mpf",
		true,
	),
	Entry(
		"Contains a-z,0-9,(.),(-) characters, contains an invalid character",
		"0a1b-2c3d&4e.5f6g7h-8i9j",
		"0a1b-2c3d4e.5f6g7h-8i9j-kdr36",
		true,
	),
	Entry(
		"Contains a-z,0-9,(.),(-), and invalid characters",
		"0a1b-2c3d&4e.5f6+_)(*&^%$#`!@g7h-8i9j",
		"0a1b-2c3d4e.5f6g7h-8i9j-74u0r",
		true,
	),
	Entry(
		"Contains invalid characters",
		"+_)(*&^% $#`!@",
		"z-o1pua",
		true,
	),
	Entry(
		"Contains a-z,0-9,(.),(-), and invalid characters, consecutive (.)",
		"0a1b-2c3d------&4e.5f6+_)(*&......^%$#------`!@g7h-8i9j",
		"0a1b-2c3d------4e.5f6.g7h-8i9j-l9n5l",
		true,
	),
	Entry(
		"Contains a-z,0-9,(.),(-), and invalid characters, consecutive (.)",
		"0a1b-2c3d------&4e.5f6+_)(*&......^%$#------`!@g7h-8i9j-rewqon84q64-302-9%^-#%&$&.^$,*.3421kfsafida....dhfks---------alhr",
		"0a1b-2c3d------4e.5f6.g7h-8i9j-rewqon84q64-302-9.3421kfsa-t7j2p",
		true,
	),
	Entry(
		"Contains a-z,0-9,(.),(-), and invalid characters in the prefix and suffix, consecutive (.) and (-)",
		"...-.-----0a1b-2c3d------&4e.5f6+_)(*&......^%$#------`!@g7h-8i9j-rewqon84q64-302-9%^-#%&$&.^$,*.3421kfsafida....dhfks---------alhr...-.-----...",
		"0a1b-2c3d------4e.5f6.g7h-8i9j-rewqon84q64-302-9.3421kfsa-1nlgc",
		true,
	),
	Entry(
		"Contains a-z,0-9,(.),(-), and invalid characters in the prefix and suffix, consecutive (.) and (-)",
		"...-.-----0a1b-2c3d------&4e.5f6+_)(*&......^%$#------`!@g7h-8i9j-rewqon84q64-302-9%^-#%&$&.^$,*.3421kfs.dhfks---------alhr",
		"0a1b-2c3d------4e.5f6.g7h-8i9j-rewqon84q64-302-9.3421kfs-cl8gt",
		true,
	),
)

// convertMatchFilterToSelector
// Characters in the AND OR, must either be all upper or all lower case.
// The to selector is built over the Panorama parser rules.
var _ = DescribeTable(
	"convertMatchFilterToSelector",
	func(match, expectedVal string) {
		// Verify that the converted match is converted correctly.
		sel, _ := ConvertMatchFilterToSelector(match)
		Expect(sel).To(Equal(expectedVal))
		// Verify that the converted match can be parsed without an error.
		_, err := selector.Parse(sel)
		Expect(err).To(BeNil())
	},
	Entry(
		"empty string",
		"",
		"",
	),
	Entry(
		"simple tag name",
		"tag1",
		"has(tag1)",
	),
	Entry(
		"simple tag name encapsulated by single quotes",
		"'tag1'",
		"has(tag1)",
	),
	Entry(
		"simple tag name encapsulated by single quotes",
		"\"tag1\"",
		"has(tag1)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta~g'",
		"has(tag-kicoo)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta`g'",
		"has(tag-6n5ts)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta!g'",
		"has(tag-linv6)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta@g'",
		"has(tag-hvgtu)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta#g'",
		"has(tag-tlbj2)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta$g'",
		"has(tag-c1nhi)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta%g'",
		"has(tag-5u7ed)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta^g'",
		"has(tag-nv7d8)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta&g'",
		"has(tag-i3md8)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta*g'",
		"has(tag-he702)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta(g'",
		"has(tag-7fqol)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta)g'",
		"has(tag-t92aa)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta_g'",
		"has(tag-nivhv)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta-g'",
		"has(ta-g)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta+g'",
		"has(tag-11j64)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta,g'",
		"has(tag-9vg4t)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta.g'",
		"has(ta.g)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta]g'",
		"has(tag-ggjvm)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'ta\"g'",
		"has(tag-brkd7)",
	),
	Entry(
		"complex tag name encapsulated by single quotes",
		"'^&%%&54 nmn$^%#'",
		"has(54nmn-cudoo)",
	),
	Entry(
		"simple tag names with 'or'",
		"tag1 or tag2",
		"has(tag1) || has(tag2)",
	),
	Entry(
		"simple tag names with 'OR'",
		"tag1 OR tag2",
		"has(tag1) || has(tag2)",
	),
	Entry(
		"simple tag names with 'and'",
		"tag1 and tag2",
		"has(tag1) && has(tag2)",
	),
	Entry(
		"simple tag names with 'AND'",
		"tag1 AND tag2",
		"has(tag1) && has(tag2)",
	),
	Entry(
		"simple tag names with 'AND'",
		"tag1 AND tag2",
		"has(tag1) && has(tag2)",
	),
	Entry(
		"simple tag names with parenthesis with many whitespaces 'AND'",
		"(tag1)      AND           tag2",
		"(has(tag1))      &&           has(tag2)",
	),
	Entry(
		"simple tag names with parenthesis with starting and ending without a delimeter",
		"'tag1'and'tag2'or\"tag3\"AND\"tag4\"",
		"has(tag1)&&has(tag2)||has(tag3)&&has(tag4)",
	),
	Entry(
		"complex tag names with AND/OR/&&/|| with the tagged name in the name and a parentheses encapsulating an 'OR'",
		"griag84960gjrrmw OR ('lwphm.io59-56' AND \"opireopwqtnn536n56\")",
		"has(griag84960gjrrmw) || (has(lwphm.io59-56) && has(opireopwqtnn536n56))",
	),
	Entry(
		"complex tag names with AND/OR/&&/|| in the untagged and tagged name and a parentheses encapsulating an 'OR'",
		"griandag84960gjrormw OR ('lwphm.io59-56' AND \"opireopwqtnn536n562n56lnmkl24356\")",
		"has(griandag84960gjrormw) || (has(lwphm.io59-56) && has(opireopwqtnn536n562n56lnmkl24356))",
	),
	Entry(
		"complex tag names with AND/OR/&&/|| in the untagged and tagged name, and no whitespace between statements and a parentheses encapsulating an 'OR'",
		"'griandag84960gjrormw'OR('lwphm.io59-56'AND\"opireopwqtnn536n562n56lnmkl24356\")",
		"has(griandag84960gjrormw)||(has(lwphm.io59-56)&&has(opireopwqtnn536n562n56lnmkl24356))",
	),
	Entry(
		"complex statement",
		"hello000w   or'ld00or00n'and ((umber0000 or   010)and'garg')or'0test00'and 'opireopwqtnn536n562n56lnmkl24356' AND es AND b9 or t20",
		"has(hello000w)   ||has(ld00or00n)&& ((has(umber0000) ||   has(010))&&has(garg))||has(0test00)&& has(opireopwqtnn536n562n56lnmkl24356) && has(es) && has(b9) || has(t20)",
	),
	Entry(
		"complex statement",
		"hello000w   or'ld00or()?%$^00n'and ((umber0000 or   010)and'garg')or'0test00'and 'opireopwqtnn536n562n56lnmkl24356' AND es AND b9 or t20",
		"has(hello000w)   ||has(ld00or00n-psnon)&& ((has(umber0000) ||   has(010))&&has(garg))||has(0test00)&& has(opireopwqtnn536n562n56lnmkl24356) && has(es) && has(b9) || has(t20)",
	),
	// A Panorama name, ex. &^&&$%#^%*, must be surrounded by single quotes, to be a valid dynamic match.
	// (tag1)AND&^&&$%#^%* will produce a dynamic match invalid. Error: syntax error at end of input
	Entry(
		"complex tag names with parenthesis with no whitespaces 'AND'",
		"(tag1)AND'&^&&$%#^%*'",
		"(has(tag1))&&has(z-i73jk)",
	),
	Entry(
		"simple tag names with a parentheses encapsulating an 'OR'",
		"(tag1 OR tag2) AND tag3",
		"(has(tag1) || has(tag2)) && has(tag3)",
	),
	Entry(
		"simple tag names with a parentheses encapsulating an 'AND'",
		"tag1 OR (tag2 AND tag3)",
		"has(tag1) || (has(tag2) && has(tag3))",
	),
	Entry(
		"complex tag names with a parentheses encapsulating an 'OR'",
		"('~!@#$%^&*() _+-' OR tag2) AND 'tag3'",
		"(has(z-cgp6c) || has(tag2)) && has(tag3)",
	),
	Entry(
		"complex tag names with a parentheses encapsulating an 'AND'",
		"tag1 OR (tag2 AND '~!@#$%^&*() _+-')",
		"has(tag1) || (has(tag2) && has(z-cgp6c))",
	),
	Entry(
		"complex tag names with AND/OR in the name and a parentheses encapsulating an 'OR'",
		"tag1 OR (tag2 AND '~!@#$ OR %^ AND &*() _+-')",
		"has(tag1) || (has(tag2) && has(orand-1jtnd))",
	),
	Entry(
		"complex tag names with AND/OR/&&/|| in the name and a parentheses encapsulating an 'OR'",
		"tag1 OR (tag2 AND '~! && @#$ OR %^ AND &* || () _+-')",
		"has(tag1) || (has(tag2) && has(orand-iebsl))",
	),
	Entry(
		"complex tag names with AND/OR/&&/|| with the tagged name in the name and a parentheses encapsulating an 'OR'",
		"griag84960gjrrmw OR ('lwphm.io59-56' AND '~! && @#$ OR %^ AND &* || () _+-')",
		"has(griag84960gjrrmw) || (has(lwphm.io59-56) && has(orand-iebsl))",
	),
	Entry(
		"complex tag names with AND/OR/&&/|| in the untagged and tagged name and a parentheses encapsulating an 'OR'",
		"griandag84960gjrormw OR ('lwphm.io59-56' AND '~! && @#$ OR %^ AND &* || () _+-')",
		"has(griandag84960gjrormw) || (has(lwphm.io59-56) && has(orand-iebsl))",
	),
	Entry(
		"complex tag names with AND/OR/&&/|| in the untagged and tagged name, and no whitespace between statements and a parentheses encapsulating an 'OR'",
		"griandag84960gjrormw OR('lwphm.io59-56'AND'~! && @#$ OR %^ AND &* || () _+-')",
		"has(griandag84960gjrormw) ||(has(lwphm.io59-56)&&has(orand-iebsl))",
	),
	Entry(
		"complex statement",
		"hello000w   or'ld00or00n'and ((umber0000 or   010)and'garg')or' 0test00'and '&%^% || $* && !~@$' AND es AND b9 or t20",
		"has(hello000w)   ||has(ld00or00n)&& ((has(umber0000) ||   has(010))&&has(garg))||has(0test00-6ncng)&& has(z-kpb0p) && has(es) && has(b9) || has(t20)",
	),
	// Entry(
	// 	"complex invalid statement",
	// 	"tag1 or 'tag2' and ((tag3 or \"tag4\") and 'tag5') or 'tag6' and 'tag7 AND es AND b9 or t20",
	// 	"has(tag1) || has(tag2) && ((has(tag3) || has(tag4)) && has(tag5)) || has(tag6) && 'has(tag7) && has(es) && has(b9) || has(t20)",
	// ),
)

// setAddressBucketsByDynamicMatch
var _ = DescribeTable(
	"setAddressBucketsByDynamicMatch",
	func(match string, addresses []addr.Entry, matchedAddresses *Addresses) {
		buckets := &Addresses{
			IpNetmasks:  make([]string, 0),
			Fqdns:       make([]string, 0),
			IpRanges:    make([]string, 0),
			IpWildcards: make([]string, 0),
		}
		// Verify that the converted match is converted correctly.
		_ = setAddressBucketsByDynamicMatch(buckets, match, addresses)
		Expect(buckets).To(Equal(matchedAddresses))
	},
	Entry(
		"simple match statement",
		"",
		addressesDeviceGroup1Test,
		&Addresses{
			// IpNetmasks type addresses.
			IpNetmasks: []string{}, // ordered
			// Fqdn type addresses.
			Fqdns: []string{}, // ordered
			// IpRange type addresses.
			IpRanges: []string{}, // ordered
			// IpWildcard type addresses.
			IpWildcards: []string{}, // ordered
		},
	),
	Entry(
		"simple match statement",
		"tag1",
		addressesDeviceGroup2Test,
		&Addresses{
			// IpNetmasks type addresses.
			IpNetmasks: []string{ // ordered
				"10.10.10.10/31",
				"10.10.10.12/31",
				"10.10.10.13/31",
			}, // ordered
			// Fqdn type addresses.
			Fqdns: []string{
				"www.tigera-test1.gr",
				"www.tigera-test4.gr",
			}, // ordered
			// IpRange type addresses.
			IpRanges: []string{
				"10.12.0.1-11.10.0.85",
				"192.167.0.1-192.167.0.22",
				"192.168.0.1-192.168.0.15",
				"222.168.0.1-222.168.0.111",
			}, // ordered
			// IpWildcard type addresses.
			IpWildcards: []string{
				"10.12.0.1/10.0.0.33",
				"192.168.0.1/10.0.0.15",
				"222.168.0.1/10.0.0.15",
			}, // ordered
		},
	),
	Entry(
		"simple match statement",
		"'%^@$&and%$*^OR(& () (__*+~`\"$# @!$'or tag1", // has(%^@$&and%$*^OR(& () (__*+~`\"$# @!$) || has(tag1)
		addressesDeviceGroup3Test,
		&Addresses{
			// IpNetmasks type addresses.
			IpNetmasks: []string{ // ordered
				"10.10.10.10/31",
				"10.10.10.12/31",
				"10.10.10.13/31",
			}, // ordered
			// Fqdn type addresses.
			Fqdns: []string{
				"www.tigera-test1.gr",
				"www.tigera-test4.gr",
			}, // ordered
			// IpRange type addresses.
			IpRanges: []string{
				"10.12.0.1-11.10.0.85",
				"192.167.0.1-192.167.0.22",
				"192.168.0.1-192.168.0.15",
				"222.168.0.1-222.168.0.111",
			}, // ordered
			// IpWildcard type addresses.
			IpWildcards: []string{
				"10.12.0.1/10.0.0.33",
				"192.168.0.1/10.0.0.15",
				"222.168.0.1/10.0.0.15",
			}, // ordered
		},
	),
	Entry(
		"simple match statement",
		"(tag1 and 'tag2') or tag3",
		addressesDeviceGroup4Test,
		&Addresses{
			// IpNetmasks type addresses.
			IpNetmasks: []string{ // ordered
				"10.10.10.10/31",
				"10.10.10.11/31",
				"10.10.10.12/31",
				"10.10.10.14/31",
			}, // ordered
			// Fqdn type addresses.
			Fqdns: []string{
				"www.tigera-test1.gr",
				"www.tigera-test5.gr",
				"www.tigera-test6.gr",
			}, // ordered
			// IpRange type addresses.
			IpRanges: []string{
				"10.168.0.1-10.168.0.34",
				"111.9.0.1-111.9.0.111",
				"192.167.0.1-192.167.0.22",
				"192.168.0.1-192.168.0.15",
				"222.168.0.1-222.168.0.111",
			}, // ordered
			// IpWildcard type addresses.
			IpWildcards: []string{
				"10.168.0.1/10.0.0.15",
				"111.9.0.1/9.0.0.15",
				"192.167.0.1/10.0.0.15",
				"192.168.0.1/10.0.0.15",
				"222.168.0.1/10.0.0.15",
			}, // ordered
		},
	),
	Entry(
		"simple match statement",
		"(tag1 and 'tag2') or (tag3 and '8$`()5043jgfj$%#')",
		addressesDeviceGroup5Test,
		&Addresses{
			// IpNetmasks type addresses.
			IpNetmasks: []string{ // ordered
				"10.10.10.10/31",
				"10.10.10.12/31",
				"10.10.10.14/31",
			}, // ordered
			// Fqdn type addresses.
			Fqdns: []string{
				"www.tigera-test1.gr",
				"www.tigera-test5.gr",
			}, // ordered
			// IpRange type addresses.
			IpRanges: []string{
				"111.9.0.1-111.9.0.111",
				"192.167.0.1-192.167.0.22",
				"192.168.0.1-192.168.0.15",
				"222.168.0.1-222.168.0.111",
			}, // ordered
			// IpWildcard type addresses.
			IpWildcards: []string{
				"192.168.0.1/10.0.0.15",
			}, // ordered
		},
	),
)

// setAddressBucketsByStaticAddresses
var _ = DescribeTable(
	"setAddressBucketsByStaticAddresses",
	func(straticAddresses []string, addresses []addr.Entry, matchedAddresses *Addresses) {
		buckets := &Addresses{
			IpNetmasks:  make([]string, 0),
			Fqdns:       make([]string, 0),
			IpRanges:    make([]string, 0),
			IpWildcards: make([]string, 0),
		}
		// Verify that the converted match is converted correctly.
		setAddressBucketsByStaticAddresses(buckets, straticAddresses, addresses)
		Expect(buckets).To(Equal(matchedAddresses))
	},
	Entry(
		"empty static address",
		[]string{},
		[]addr.Entry{
			{
				Name:        "address1",
				Value:       "10.10.10.10/31",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
			},
			{
				Name:        "address2",
				Value:       "10.10.10.11/31",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag2", "tag3"}, // ordered
			},
			{
				Name:        "address3",
				Value:       "10.10.10.12/31",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag1", "tag2"}, // ordered
			},
			{
				Name:        "address4",
				Value:       "10.10.10.13/31",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag1"}, // ordered
			},
			{
				Name:        "address5",
				Value:       "10.10.10.14/32",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag2"}, // ordered
			},
			{
				Name:        "address6",
				Value:       "10.10.10.14/31",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag3"}, // ordered
			},
			{
				Name:        "address7",
				Value:       "www.tigera-test1.gr",
				Type:        Fqdn,
				Description: "",
				Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
			},
			{
				Name:        "address8",
				Value:       "www.tigera-test6.gr",
				Type:        Fqdn,
				Description: "",
				Tags:        []string{"tag3"}, // ordered
			},
			{
				Name:        "address9",
				Value:       "www.tigera-test5.gr",
				Type:        Fqdn,
				Description: "",
				Tags:        []string{"tag1", "tag2"}, // ordered
			},
			{
				Name:        "address10",
				Value:       "www.tigera-test4.gr",
				Type:        Fqdn,
				Description: "",
				Tags:        []string{"tag1"}, // ordered
			},
			{
				Name:        "address25",
				Value:       "www.tigera-test2.gr",
				Type:        Fqdn,
				Description: "",
				Tags:        []string{"tag2"}, // ordered
			},
			{
				Name:        "address11",
				Value:       "192.168.0.1-192.168.0.15",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
			},
			{
				Name:        "address12",
				Value:       "222.168.0.1-222.168.0.111",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag1", "tag3"}, // ordered
			},
			{
				Name:        "address13",
				Value:       "192.167.0.1-192.167.0.22",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag1", "tag2"}, // ordered
			},
			{
				Name:        "address14",
				Value:       "10.168.0.1-10.168.0.34",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag2", "tag3"}, // ordered
			},
			{
				Name:        "address15",
				Value:       "10.12.0.1-11.10.0.85",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag1"}, // ordered
			},
			{
				Name:        "address16",
				Value:       "25.168.0.1-25.168.0.4",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag2"}, // ordered
			},
			{
				Name:        "address17",
				Value:       "111.9.0.1-111.9.0.111",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag3"}, // ordered
			},
			{
				Name:        "address18",
				Value:       "192.168.0.1/10.0.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
			},
			{
				Name:        "address19",
				Value:       "222.168.0.1/10.0.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag1", "tag3"}, // ordered
			},
			{
				Name:        "address20",
				Value:       "192.167.0.1/10.0.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag1", "tag2"}, // ordered
			},
			{
				Name:        "address21",
				Value:       "10.168.0.1/10.0.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag2", "tag3"}, // ordered
			},
			{
				Name:        "address22",
				Value:       "10.12.0.1/10.0.0.33",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag1"}, // ordered
			},
			{
				Name:        "address23",
				Value:       "25.168.0.1/10.1.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag2"}, // ordered
			},
			{
				Name:        "address24",
				Value:       "111.9.0.1/9.0.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag3"}, // ordered
			},
		},
		&Addresses{
			// IpNetmasks type addresses.
			IpNetmasks: []string{}, // ordered
			// Fqdn type addresses.
			Fqdns: []string{}, // ordered
			// IpRange type addresses.
			IpRanges: []string{}, // ordered
			// IpWildcard type addresses.
			IpWildcards: []string{}, // ordered
		},
	),
	Entry(
		"simple match statement",
		[]string{"address19", "address7", "address4", "address3", "address1", "address13", "address10",
			"address15", "address22", "address11", "address12", "address18",
		},
		[]addr.Entry{
			{
				Name:        "address1",
				Value:       "10.10.10.10/31",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
			},
			{
				Name:        "address2",
				Value:       "10.10.10.11/31",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{}, // ordered
			},
			{
				Name:        "address3",
				Value:       "10.10.10.12/31",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag1", "tag2"}, // ordered
			},
			{
				Name:        "address4",
				Value:       "10.10.10.13/31",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag1"}, // ordered
			},
			{
				Name:        "address5",
				Value:       "10.10.10.14/32",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag2"}, // ordered
			},
			{
				Name:        "address6",
				Value:       "10.10.10.14/31",
				Type:        IpNetmask,
				Description: "",
				Tags:        []string{"tag3"}, // ordered
			},
			{
				Name:        "address7",
				Value:       "www.tigera-test1.gr",
				Type:        Fqdn,
				Description: "",
				Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
			},
			{
				Name:        "address8",
				Value:       "www.tigera-test6.gr",
				Type:        Fqdn,
				Description: "",
				Tags:        []string{"tag3"}, // ordered
			},
			{
				Name:        "address9",
				Value:       "www.tigera-test5.gr",
				Type:        Fqdn,
				Description: "",
				Tags:        []string{}, // ordered
			},
			{
				Name:        "address10",
				Value:       "www.tigera-test4.gr",
				Type:        Fqdn,
				Description: "",
				Tags:        []string{"tag1"}, // ordered
			},
			{
				Name:        "address25",
				Value:       "www.tigera-test2.gr",
				Type:        Fqdn,
				Description: "",
				Tags:        []string{"tag2"}, // ordered
			},
			{
				Name:        "address11",
				Value:       "192.168.0.1-192.168.0.15",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
			},
			{
				Name:        "address12",
				Value:       "222.168.0.1-222.168.0.111",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag1", "tag3"}, // ordered
			},
			{
				Name:        "address13",
				Value:       "192.167.0.1-192.167.0.22",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag1", "tag2"}, // ordered
			},
			{
				Name:        "address14",
				Value:       "10.168.0.1-10.168.0.34",
				Type:        IpRange,
				Description: "",
				Tags:        []string{}, // ordered
			},
			{
				Name:        "address15",
				Value:       "10.12.0.1-11.10.0.85",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag1"}, // ordered
			},
			{
				Name:        "address16",
				Value:       "25.168.0.1-25.168.0.4",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag2"}, // ordered
			},
			{
				Name:        "address17",
				Value:       "111.9.0.1-111.9.0.111",
				Type:        IpRange,
				Description: "",
				Tags:        []string{"tag3"}, // ordered
			},
			{
				Name:        "address18",
				Value:       "192.168.0.1/10.0.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag1", "tag2", "tag3"}, // ordered
			},
			{
				Name:        "address19",
				Value:       "222.168.0.1/10.0.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag1", "tag3"}, // ordered
			},
			{
				Name:        "address20",
				Value:       "192.167.0.1/10.0.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{}, // ordered
			},
			{
				Name:        "address21",
				Value:       "10.168.0.1/10.0.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag2", "tag3"}, // ordered
			},
			{
				Name:        "address22",
				Value:       "10.12.0.1/10.0.0.33",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag1"}, // ordered
			},
			{
				Name:        "address23",
				Value:       "25.168.0.1/10.1.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag2"}, // ordered
			},
			{
				Name:        "address24",
				Value:       "111.9.0.1/9.0.0.15",
				Type:        IpWildcard,
				Description: "",
				Tags:        []string{"tag3"}, // ordered
			},
		},
		&Addresses{
			// IpNetmasks type addresses.
			IpNetmasks: []string{ // ordered
				"10.10.10.10/31",
				"10.10.10.12/31",
				"10.10.10.13/31",
			}, // ordered
			// Fqdn type addresses.
			Fqdns: []string{
				"www.tigera-test1.gr",
				"www.tigera-test4.gr",
			}, // ordered
			// IpRange type addresses.
			IpRanges: []string{
				"10.12.0.1-11.10.0.85",
				"192.167.0.1-192.167.0.22",
				"192.168.0.1-192.168.0.15",
				"222.168.0.1-222.168.0.111",
			}, // ordered
			// IpWildcard type addresses.
			IpWildcards: []string{
				"10.12.0.1/10.0.0.33",
				"192.168.0.1/10.0.0.15",
				"222.168.0.1/10.0.0.15",
			}, // ordered
		},
	),
)

// splitTags
var _ = DescribeTable(
	"convertMatchFilterToSelector",
	func(tags string, expectedResult []string) {
		// Verify that the converted match is converted correctly.
		tagsArray, _ := SplitTags(tags)
		Expect(tagsArray).To(Equal(expectedResult))
	},
	Entry(
		"Empty list of tags",
		"",
		[]string{},
	),
	Entry(
		"A list of tags with empty values",
		",,,,tag1,tag2,tag3",
		[]string{"tag1", "tag2", "tag3"},
	),
	Entry(
		"A list of tags with empty values, unordered",
		",tag2,,,tag1,,tag3,,,,",
		[]string{"tag1", "tag2", "tag3"},
	),
	Entry(
		"Simple list of tags",
		"tag1, tag2, tag3",
		[]string{"tag1", "tag2", "tag3"},
	),
	Entry(
		"Simple list of tags, multiple spaces",
		"tag1,  tag2,     tag3",
		[]string{"tag1", "tag2", "tag3"},
	),
	Entry(
		"Simple list of tags, unordered input",
		"tag2, tag1, tag3",
		[]string{"tag1", "tag2", "tag3"},
	),
	Entry(
		"Simple list of tags, no spaces",
		"tag2,tag1,tag3",
		[]string{"tag1", "tag2", "tag3"},
	),
	Entry(
		"List of tags with complex tag name",
		"tag2,'&*%$^*&(,   &*,%(*(, %#^%$#^%@^#&^$#&^)))',tag3",
		[]string{"&*%$^*&(,   &*,%(*(, %#^%$#^%@^#&^$#&^)))", "tag2", "tag3"},
	),
	Entry(
		"List of tags with complex tag name, with extra spaces",
		"tag2,   '&*%$^*&(,   &*,%(*(, %#^%$#^%@^#&^$#&^)))',     tag3",
		[]string{"&*%$^*&(,   &*,%(*(, %#^%$#^%@^#&^$#&^)))", "tag2", "tag3"},
	),
)

// GetRFC1123PolicyName
var _ = DescribeTable(
	"GetRFC1123PolicyName",
	func(rawName, tierName, expectedPolicyName string, expectedConversion bool, expectedError error) {
		// Verify that the converted match is converted correctly.
		convertedPolicyName, err := GetRFC1123PolicyName(tierName, rawName)
		if err != nil {
			Expect(err).To(Equal(expectedError))
		} else {
			Expect(convertedPolicyName).To(Equal(expectedPolicyName))
			// If names differ, then there is at least one character that is unsupported and a convertsion
			// occured.
			convertedNameWithoutTierPrefix := strings.TrimPrefix(convertedPolicyName, fmt.Sprintf("%s.", tierName))
			namesDiffer := convertedNameWithoutTierPrefix != rawName
			Expect(namesDiffer).To(Equal(expectedConversion))
			// Max allowed len is 63 characters, all names will be boxed within that boundary.
			isLessThanDNS1123LabelMaxLength := len(convertedPolicyName) <= k8svalidation.DNS1123LabelMaxLength
			Expect(isLessThanDNS1123LabelMaxLength).To(BeTrue())
		}
	},
	Entry(
		"Empty name, Empty tier",
		"",
		"",
		"",
		false,
		errors.New("invalid tier name: ''"),
	),
	Entry(
		"Empty name",
		"",
		"mytier",
		"mytier.z-seoc8",
		true,
		nil,
	),
	Entry(
		"Contains a-z characters",
		"abcdefghijklmnopqrstuvwxyz",
		"mytier",
		"mytier.abcdefghijklmnopqrstuvwxyz",
		false,
		nil,
	),
	Entry(
		"Contains 0-9 characters",
		"0123456789",
		"mytier",
		"mytier.0123456789",
		false,
		nil,
	),
	Entry(
		"Contains a-z,0-9 characters, starts with a character",
		"g0a1b2c3d4e5f6g7h8i9j",
		"mytier",
		"mytier.g0a1b2c3d4e5f6g7h8i9j",
		false,
		nil,
	),
	Entry(
		"Contains valid a-z,0-9 characters, starts with a digit",
		"0a1b2c3d4e5f6g7h8i9j",
		"mytier",
		"mytier.0a1b2c3d4e5f6g7h8i9j",
		false,
		nil,
	),
	Entry(
		"Contains valid a-z,0-9, and invalid (.) characters, starts with a digit, a digit follows a (.)",
		"0a1b2c3d4e.5f6g7h8i9j",
		"mytier",
		"mytier.0a1b2c3d4e-5f6g7h8i9j-4fiqk",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,(-), and invalid (.) characters characters",
		"0a1b-2c3d4e.5f6g7h-8i9j",
		"mytier",
		"mytier.0a1b-2c3d4e-5f6g7h-8i9j-m0vrj",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,(-), and invalid (.) characters, with an invalid prefix (.)",
		".0a1b-2c3d4e.5f6g7h-8i9j",
		"mytier",
		"mytier.0a1b-2c3d4e-5f6g7h-8i9j-k17sm",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,(-), and invalid (.) characters, with an invalid prefix (-)",
		"-0a1b-2c3d4e.5f6g7h-8i9j",
		"mytier",
		"mytier.0a1b-2c3d4e-5f6g7h-8i9j-sr1s8",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,'-', and invalid '.' characters, with an invalid suffix '.'",
		"0a1b-2c3d4e.5f6g7h-8i9j.",
		"mytier",
		"mytier.0a1b-2c3d4e-5f6g7h-8i9j-uhnh5",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,'-', and invalid '.' characters, with an invalid suffix '-'",
		"0a1b-2c3d4e.5f6g7h-8i9j-",
		"mytier",
		"mytier.0a1b-2c3d4e-5f6g7h-8i9j-i8mpf",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,'-', and invalid '.', '&' characters, contains an invalid character",
		"0a1b-2c3d&4e.5f6g7h-8i9j",
		"mytier",
		"mytier.0a1b-2c3d-4e-5f6g7h-8i9j-kdr36",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,'-', and invalid characters",
		"0a1b-2c_3d&4e.5f6+_)(*&^%$#`!@g7h-8i9j",
		"mytier",
		"mytier.0a1b-2c-3d-4e-5f6-g7h-8i9j-onpsm",
		true,
		nil,
	),
	Entry(
		"Contains invalid characters",
		"+_)(*&^% $#`!@",
		"mytier",
		"mytier.z-o1pua",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,'.','-', invalid characters, and consecutive '.'",
		"0a1b-2c3d------&4e.5f6+_)(*&......^%$#------`!@g7h-8i9j",
		"mytier",
		"mytier.0a1b-2c3d-------4e-5f6--------g7h-8i9j-l9n5l",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,'-', and invalid characters, consecutive '.'",
		"0a1b-2c3d------&4e.5f6+_)(*&......^%$#------`!@g7h-8i9j-rewqon84q64-302-9%^-#%&$&.^$,*.3421kfsafida....dhfks---------alhr",
		"mytier",
		"mytier.0a1b-2c3d-------4e-5f6--------g7h-8i9j-rewqon84q64-t7j2p",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,'-', and invalid characters in the prefix and suffix, consecutive '.' and '-'",
		"...-.-----0a1b-2c3d------&4e.5f6+_)(*&......^%$#------`!@g7h-8i9j-rewqon84q64-302-9%^-#%&$&.^$,*.3421kfsafida....dhfks---------alhr...-.-----...",
		"mytier",
		"mytier.0a1b-2c3d-------4e-5f6--------g7h-8i9j-rewqon84q64-1nlgc",
		true,
		nil,
	),
	Entry(
		"Contains a-z,0-9,(.),(-), and invalid characters in the prefix and suffix, consecutive (.) and (-)",
		"...-.-----0a1b-2c3d------&4e.5f6+_)(*&......^%$#------`!@g7h-8i9j-rewqon84q64-302-9%^-#%&$&.^$,*.3421kfs.dhfks---------alhr",
		"mytier",
		"mytier.0a1b-2c3d-------4e-5f6--------g7h-8i9j-rewqon84q64-cl8gt",
		true,
		nil,
	),
)
