// Copyright (c) 2019 Tigera Inc. All rights reserved.

package puller

import (
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

func TestParseIP(t *testing.T) {
	f := func(entry string, out []any) func(*testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			res := parseIP(entry, log.WithFields(nil), 0, &sync.Once{})
			g.Expect(res).Should(ConsistOf(out...))
		}
	}

	t.Run("ipv4", f("127.0.0.1", []any{"127.0.0.1/32"}))
	t.Run("ipv4 invalid", f("127.0.0.", nil))
	t.Run("ipv4 with brackets", f("[127.0.0.1]", []any{"127.0.0.1/32"}))
	t.Run("ipv4 cidr", f("127.0.0.0/8", []any{"127.0.0.0/8"}))
	t.Run("ipv4 cidr invalid", f("127.0.0.0/", nil))
	t.Run("ipv4 range (not supported)", f("127.0.0.1-10", nil))

	t.Run("ipv6 no brackets", f("2000::1", []any{"2000::1/128"}))
	t.Run("ipv6 invalid", f("2000", nil))
	t.Run("ipv6 with brackets", f("[2000::1]", []any{"2000::1/128"}))
	t.Run("ipv6 cidr", f("[2000::/8]", []any{"2000::/8"}))
	t.Run("ipv6 invalid", f("[2000::/]", nil))
	t.Run("ipv6 range (not supported)", f("2000::1-10", nil))
}
