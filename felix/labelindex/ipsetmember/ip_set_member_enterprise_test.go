// Copyright (c) 2025 Tigera, Inc. All rights reserved

package ipsetmember

import (
	"fmt"
	"testing"
	"time"

	"github.com/projectcalico/calico/felix/ip"
)

func TestMakeEgressGateway(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")

	tsBad, _ := time.Parse(time.RFC3339, "9999-01-02T15:04:05Z")
	tsBad = tsBad.Add(time.Hour * 24 * 400) // Year 10k causes error in MarshalText.

	for _, test := range []struct {
		addr                       ip.V4Addr
		deletionTimestamp          time.Time
		deletionGracePeriodSeconds int64
		hostname                   string
		healthPort                 uint16

		expected string
	}{
		{
			addr:       ip.MustParseCIDROrIP("10.0.0.1").Addr().(ip.V4Addr),
			hostname:   "host",
			healthPort: 1234,

			expected: "10.0.0.1/32,,,1234,host",
		},
		{
			addr:                       ip.MustParseCIDROrIP("10.0.0.1").Addr().(ip.V4Addr),
			hostname:                   "host",
			healthPort:                 1234,
			deletionTimestamp:          ts,
			deletionGracePeriodSeconds: 30,

			expected: "10.0.0.1/32,2006-01-02T15:03:35Z,2006-01-02T15:04:05Z,1234,host",
		},
		{
			addr:                       ip.MustParseCIDROrIP("10.0.0.1").Addr().(ip.V4Addr),
			hostname:                   "host",
			healthPort:                 1234,
			deletionTimestamp:          tsBad,
			deletionGracePeriodSeconds: 30,

			expected: "10.0.0.1/32,,,1234,host",
		},
	} {
		t.Run(fmt.Sprint(test), func(t *testing.T) {
			member := MakeEgressGateway(
				test.addr,
				test.deletionTimestamp,
				test.deletionGracePeriodSeconds,
				test.hostname,
				test.healthPort,
			)
			if member.ToProtobufFormat() != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, member.ToProtobufFormat())
			}
		})
	}
}
