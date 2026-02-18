package benchmark_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

var _ = Describe("Benchmark", func() {
	It("should properly compute Benchmarks equality", func() {
		By("empty benchmarks")
		Expect((v1.Benchmarks{}).Equal(v1.Benchmarks{})).To(BeTrue())

		By("error field")
		Expect((v1.Benchmarks{Error: "an error"}).Equal(v1.Benchmarks{Error: "an error"})).To(BeTrue())
		Expect((v1.Benchmarks{Error: "an error"}).Equal(v1.Benchmarks{Error: "diff error"})).To(BeFalse())

		By("metadata fields")
		Expect((v1.Benchmarks{Version: "1.1"}).Equal(v1.Benchmarks{Version: "1.1"})).To(BeTrue())
		Expect((v1.Benchmarks{Version: "1.1"}).Equal(v1.Benchmarks{Version: "1.1.1"})).To(BeFalse())
		Expect((v1.Benchmarks{Type: v1.TypeKubernetes}).Equal(v1.Benchmarks{Type: v1.TypeKubernetes})).To(BeTrue())
		Expect((v1.Benchmarks{Type: v1.TypeKubernetes}).Equal(v1.Benchmarks{Type: "docker"})).To(BeFalse())
		Expect((v1.Benchmarks{NodeName: "kadm-ms"}).Equal(v1.Benchmarks{NodeName: "kadm-ms"})).To(BeTrue())
		Expect((v1.Benchmarks{NodeName: "kadm-ms"}).Equal(v1.Benchmarks{NodeName: "kadm-node-0"})).To(BeFalse())

		By("tests")
		Expect((v1.Benchmarks{Tests: []v1.BenchmarkTest{{Section: "section", SectionDesc: "sectionDesc", TestNumber: "testNum", TestDesc: "testDesc", TestInfo: "testInfo", Status: "status", Scored: true}}}).Equal(
			v1.Benchmarks{Tests: []v1.BenchmarkTest{{Section: "section", SectionDesc: "sectionDesc", TestNumber: "testNum", TestDesc: "testDesc", TestInfo: "testInfo", Status: "status", Scored: true}}},
		)).To(BeTrue())

		Expect((v1.Benchmarks{Tests: []v1.BenchmarkTest{{Section: "section", SectionDesc: "sectionDesc", TestNumber: "testNum", TestDesc: "testDesc", TestInfo: "testInfo", Status: "status", Scored: true}}}).Equal(
			v1.Benchmarks{Tests: []v1.BenchmarkTest{{Section: "section", SectionDesc: "sectionDesc", TestNumber: "testNum", TestDesc: "testDesc", TestInfo: "testInfo", Status: "status", Scored: false}}},
		)).To(BeFalse())
	})
})
