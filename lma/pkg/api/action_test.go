// Copyright (c) 2020 Tigera, Inc. All rights reserved.
package api_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lma/pkg/api"
)

var _ = Describe("Test action flags", func() {
	It("handles conversion correctly", func() {
		By("checking flags to names")
		Expect(api.ActionFlagAllow.ToFlowActionString()).To(Equal(string(api.ActionAllow)))
		Expect(api.ActionFlagDeny.ToFlowActionString()).To(Equal(string(api.ActionDeny)))
		Expect(api.ActionFlagEndOfTierDeny.ToFlowActionString()).To(Equal(string(api.ActionDeny)))
		Expect((api.ActionFlagDeny | api.ActionFlagEndOfTierDeny).ToFlowActionString()).To(Equal(string(api.ActionDeny)))
		Expect(api.ActionFlagNextTier.ToFlowActionString()).To(Equal(string(api.ActionInvalid)))
		Expect((api.ActionFlagAllow | api.ActionFlagDeny).ToFlowActionString()).To(Equal(string(api.ActionUnknown)))
		Expect((api.ActionFlagAllow | api.ActionFlagEndOfTierDeny).ToFlowActionString()).To(Equal(string(api.ActionUnknown)))
		Expect((api.ActionFlagAllow | api.ActionFlagNextTier).ToFlowActionString()).To(Equal(string(api.ActionAllow)))
		Expect((api.ActionFlagDeny | api.ActionFlagNextTier).ToFlowActionString()).To(Equal(string(api.ActionDeny)))
	})
})
