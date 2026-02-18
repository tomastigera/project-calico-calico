// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package xrefcache

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("inscope endpoint helpers", func() {
	// Ensure  the client resource list is in-sync with the resource helper.
	It("Empty selectors selects everything", func() {
		r, s, err := calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{})
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("all()"))
		Expect(r.Name).To(Equal("all()"))
		Expect(r.TypeMeta).To(Equal(KindInScopeSelection))
	})

	It("Handles EP selector but no NS or SA", func() {
		_, s, err := calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			Selector: "x == \"a\"",
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("x == \"a\""))
	})

	It("Handles NS names and labels match but no EP or SA", func() {
		By("calculating with no namespace selector or name")
		_, s, err := calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			Namespaces: &apiv3.NamesAndLabelsMatch{},
		})
		By("checking it does not do a namespace check")
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("all()"))

		By("calculating with namespace selector all()")
		_, s, err = calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			Namespaces: &apiv3.NamesAndLabelsMatch{
				Selector: "all()",
			},
		})
		By("including the namespace label to ensure the namespace label only selects namespaced endpoints")
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("(all() && has(projectcalico.org/namespace))"))

		By("calculating with namespace names")
		_, s, err = calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			Namespaces: &apiv3.NamesAndLabelsMatch{
				Names: []string{"ns1"},
			},
		})
		By("including the namespace label to ensure the namespace label only selects namespaced endpoints")
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("projectcalico.org/namespace in {\"ns1\"}"))

		By("calculating with namespace selector and names")
		_, s, err = calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			Namespaces: &apiv3.NamesAndLabelsMatch{
				Selector: "x == \"a\"",
				Names:    []string{"ns1"},
			},
		})
		By("including the namespace label and prefixing the label")
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("(pcns.x == \"a\" && projectcalico.org/namespace in {\"ns1\"})"))
	})

	It("Handles SA names and labels match but no EP or NS", func() {
		By("calculating with no service account selector or name")
		_, s, err := calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			ServiceAccounts: &apiv3.NamesAndLabelsMatch{},
		})
		By("checking it does not do a service account check")
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("all()"))

		By("calculating with service account selector all()")
		_, s, err = calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			ServiceAccounts: &apiv3.NamesAndLabelsMatch{
				Selector: "all()",
			},
		})
		By("including the service account label to ensure the service account label only selects endpoints w/ service account")
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("(all() && has(projectcalico.org/serviceaccount))"))

		By("calculating with service account names")
		_, s, err = calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			ServiceAccounts: &apiv3.NamesAndLabelsMatch{
				Names: []string{"sa1"},
			},
		})
		By("including the service account label to ensure the service account label only selects endpoints w/ service accounts")
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("projectcalico.org/serviceaccount in {\"sa1\"}"))

		By("calculating with service account selector and names")
		_, s, err = calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			ServiceAccounts: &apiv3.NamesAndLabelsMatch{
				Selector: "x == \"a\"",
				Names:    []string{"sa1"},
			},
		})
		By("including the service account label and prefixing the label")
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("(pcsa.x == \"a\" && projectcalico.org/serviceaccount in {\"sa1\"})"))
	})

	It("Handles SA and NS match but no EP", func() {
		By("calculating with SA and NS name match")
		_, s, err := calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			Namespaces: &apiv3.NamesAndLabelsMatch{
				Names: []string{"ns1"},
			},
			ServiceAccounts: &apiv3.NamesAndLabelsMatch{
				Names: []string{"sa1"},
			},
		})
		By("checking the combined selector")
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("(projectcalico.org/namespace in {\"ns1\"} && projectcalico.org/serviceaccount in {\"sa1\"})"))
	})

	It("Handles EP, SA and NS match", func() {
		By("calculating with SA and NS name match")
		_, s, err := calculateInScopeEndpointsSelector(&apiv3.EndpointsSelection{
			Selector: "x == \"y\"",
			Namespaces: &apiv3.NamesAndLabelsMatch{
				Names: []string{"ns1"},
			},
			ServiceAccounts: &apiv3.NamesAndLabelsMatch{
				Names: []string{"sa1"},
			},
		})
		By("checking the combined selector")
		Expect(err).ToNot(HaveOccurred())
		Expect(s).To(Equal("(x == \"y\" && projectcalico.org/namespace in {\"ns1\"} && projectcalico.org/serviceaccount in {\"sa1\"})"))
	})
})
