// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package bootstrap_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/voltron/internal/pkg/bootstrap"
)

var _ = Describe("Loading routes from files", func() {
	Context("TLSTerminatedRoutesFromFile", func() {
		It("loads a single route", func() {
			routes, err := bootstrap.TLSTerminatedRoutesFromFile("testdata/tlsTerminatedSingleRoute.json")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(routes).Should(Equal([]bootstrap.Target{{
				Dest:           "https://foo.bar:9443",
				Path:           "/foo/",
				PathRegexp:     []byte("^/foo/?"),
				PathReplace:    []byte("/"),
				CABundlePath:   "/somebundle.crt",
				ClientCertPath: "/somecert.pem",
				ClientKeyPath:  "/somekey.pem",
			}}))
		})

		It("loads multiple routes", func() {
			routes, err := bootstrap.TLSTerminatedRoutesFromFile("testdata/tlsTerminatedMultipleRoutes.json")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(routes).Should(Equal([]bootstrap.Target{{
				Dest:           "https://foo.bar:9443",
				Path:           "/foo/",
				PathRegexp:     []byte("^/foo/?"),
				PathReplace:    []byte("/"),
				CABundlePath:   "/somebundle.crt",
				ClientCertPath: "/somecert.pem",
				ClientKeyPath:  "/somekey.pem",
			}, {
				Dest:           "https://zaz.bar:9443",
				Path:           "/zaz/",
				PathRegexp:     []byte("^/zaz/?"),
				PathReplace:    []byte("/z"),
				CABundlePath:   "/someotherbundle.crt",
				ClientCertPath: "/someothercert.pem",
				ClientKeyPath:  "/someotherkey.pem",
			}}))
		})
	})

	Context("TLSPassThroughRoutesFromFile", func() {
		It("loads a single route", func() {
			routes, err := bootstrap.TLSPassThroughRoutesFromFile("testdata/tlsPassThroughSingleRoute.json")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(err).ShouldNot(HaveOccurred())
			Expect(routes).Should(Equal([]bootstrap.TLSPassThroughRoute{{
				Destination: "https://foo.bar:9443",
				ServerName:  "foobar",
			}}))
		})

		It("loads multiple routes", func() {
			routes, err := bootstrap.TLSPassThroughRoutesFromFile("testdata/tlsPassThroughMultipleRoutes.json")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(err).ShouldNot(HaveOccurred())
			Expect(routes).Should(Equal([]bootstrap.TLSPassThroughRoute{{
				Destination: "https://foo.bar:9443",
				ServerName:  "foobar",
			}, {
				Destination: "https://zaz.bar:9443",
				ServerName:  "zazbar",
			}}))
		})
	})
})
