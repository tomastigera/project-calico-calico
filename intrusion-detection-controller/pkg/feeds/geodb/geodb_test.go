package geodb

import (
	"net"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

var (
	ip = net.ParseIP("95.179.135.3")
)

var _ = Describe("GeoIP database path constants", func() {
	It("should use /usr/share/GeoIP/ with DB-IP filenames", func() {
		Expect(cityDatabaseFilepath).To(Equal("/usr/share/GeoIP/dbip-city-lite.mmdb"))
		Expect(asnDatabaseFilepath).To(Equal("/usr/share/GeoIP/dbip-asn-lite.mmdb"))
	})
})

var _ = Describe("GeoIP lookup tests", func() {

	Context("GeoIP lookup", func() {
		BeforeEach(func() {
			_, err := os.Stat(cityDatabaseFilepath)
			Expect(err).NotTo(HaveOccurred())
			_, err = os.Stat(asnDatabaseFilepath)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should lookup country", func() {
			geodb, err := NewGeoDB()
			Expect(err).NotTo(HaveOccurred())

			city, err := geodb.City(ip)
			Expect(err).NotTo(HaveOccurred())

			Expect(city.CountryName).To(Equal("The Netherlands"))
			Expect(city.ISO).To(Equal("NL"))
			Expect(city.CityName).To(Equal("Haarlem"))
		})

		It("should lookup ASN", func() {
			geodb, err := NewGeoDB()
			Expect(err).NotTo(HaveOccurred())

			asn, err := geodb.ASN(ip)
			Expect(err).NotTo(HaveOccurred())

			Expect(asn).To(Equal("20473"))
		})

		It("should lookup private IP", func() {
			geodb, err := NewGeoDB()
			Expect(err).NotTo(HaveOccurred())

			city, err := geodb.City(net.ParseIP("192.168.1.0"))
			Expect(err).NotTo(HaveOccurred())

			Expect(city).To(Equal(v1.IPGeoInfo{}))
		})

		It("should lookup private IP", func() {
			geodb, err := NewGeoDB()
			Expect(err).NotTo(HaveOccurred())

			_, err = geodb.City(net.ParseIP("tigera"))
			Expect(err).To(HaveOccurred())

		})
	})
})
