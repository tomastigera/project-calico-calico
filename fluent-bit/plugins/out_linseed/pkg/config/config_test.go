// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package config

import (
	_ "embed"
	"os"
	"unsafe"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	//go:embed testdata/kubeconfig
	validKubeconfig string
	//go:embed testdata/kubeconfig_no_context
	kubeconfigNoContext string
	//go:embed testdata/kubeconfig_no_current-context
	kubeconfigNoCurrentContext string
)

var _ = Describe("Linseed out plugin config tests", func() {
	var (
		f                 *os.File
		pluginConfigKeyFn PluginConfigKeyFunc
	)

	BeforeEach(func() {
		var err error
		f, err = os.CreateTemp("", "kubeconfig")
		Expect(err).NotTo(HaveOccurred())

		pluginConfigKeyFn = func(plugin unsafe.Pointer, key string) string {
			if key == "tls.verify" {
				return "true"
			}
			return ""
		}
	})

	AfterEach(func() {
		_ = os.Remove(f.Name())
	})

	Context("Config tests", func() {
		It("should create a plugin config from a valid kubeconfig", func() {
			_, err := f.WriteString(validKubeconfig)
			_ = f.Close()
			Expect(err).NotTo(HaveOccurred())

			err = os.Setenv("KUBECONFIG", f.Name())
			Expect(err).NotTo(HaveOccurred())
			err = os.Setenv("ENDPOINT", "https://1.2.3.4:5678")
			Expect(err).NotTo(HaveOccurred())

			cfg, err := NewConfig(nil, pluginConfigKeyFn)
			Expect(err).NotTo(HaveOccurred())

			Expect(cfg.Endpoint).To(Equal("https://1.2.3.4:5678"))
			Expect(cfg.InsecureSkipVerify).To(BeFalse())
			Expect(cfg.Kubeconfig).To(Equal(f.Name()))

			Expect(cfg.RestConfig).NotTo(BeNil())
		})

		It("should return error when kubeconfig path is invalid", func() {
			err := os.Setenv("KUBECONFIG", "some/invalid/path")
			Expect(err).NotTo(HaveOccurred())

			cfg, err := NewConfig(nil, pluginConfigKeyFn)
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("should return error when current-context is missing from kubeconfig", func() {
			_, err := f.WriteString(kubeconfigNoCurrentContext)
			_ = f.Close()
			Expect(err).NotTo(HaveOccurred())

			err = os.Setenv("KUBECONFIG", f.Name())
			Expect(err).NotTo(HaveOccurred())

			cfg, err := NewConfig(nil, pluginConfigKeyFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid configuration: no configuration has been provided"))
			Expect(cfg).To(BeNil())
		})

		It("should return error when context is missing from kubeconfig", func() {
			_, err := f.WriteString(kubeconfigNoContext)
			_ = f.Close()
			Expect(err).NotTo(HaveOccurred())

			err = os.Setenv("KUBECONFIG", f.Name())
			Expect(err).NotTo(HaveOccurred())

			cfg, err := NewConfig(nil, pluginConfigKeyFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`invalid configuration: [context was not found for specified context: noncluster-hosts,`))
			Expect(cfg).To(BeNil())
		})
	})
})
