package syncclientutils_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/typha/pkg/syncclientutils"
)

var _ = Describe("Test TyphaConfig", func() {

	BeforeEach(func() {
		err := os.Setenv("FELIX_TYPHACAFILE", "cafile")
		Expect(err).NotTo(HaveOccurred())
		err = os.Setenv("FELIX_TYPHAREADTIMEOUT", "100")
		Expect(err).NotTo(HaveOccurred())

	})

	It("should be able to read all types", func() {
		typhaConfig := syncclientutils.ReadTyphaConfig([]string{"FELIX_"})
		Expect(typhaConfig.CAFile).To(Equal("cafile"))
		Expect(typhaConfig.ReadTimeout.Seconds()).To(Equal(100.))
	})
})
