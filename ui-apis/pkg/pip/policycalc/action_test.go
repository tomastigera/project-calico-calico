package policycalc_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lma/pkg/api"
	"github.com/projectcalico/calico/ui-apis/pkg/pip/policycalc"
)

var _ = Describe("Test action flags", func() {
	It("handles flag checks correctly", func() {
		By("checking for indeterminate")
		Expect(policycalc.Indeterminate(api.ActionFlagAllow | api.ActionFlagDeny)).To(BeTrue())
		Expect(policycalc.Indeterminate(api.ActionFlagAllow | api.ActionFlagDeny | api.ActionFlagNextTier)).To(BeTrue())
		Expect(policycalc.Indeterminate(api.ActionFlagDeny)).To(BeFalse())
		Expect(policycalc.Indeterminate(api.ActionFlagAllow | api.ActionFlagNextTier)).To(BeFalse())
	})
})
