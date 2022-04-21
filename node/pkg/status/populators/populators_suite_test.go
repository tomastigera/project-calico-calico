package populator

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"


	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestCommands(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/statuspopulators_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "StatusPopulators Suite", []Reporter{junitReporter})
}
