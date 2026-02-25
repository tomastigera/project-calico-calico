package event_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/compliance/mockdata/replayer"
	. "github.com/projectcalico/calico/compliance/pkg/event"
)

var _ = Describe("Event", func() {
	Context("ExtractResourceFromAuditEvent", func() {
		It("should produce a resource GVK that the resources package can work with", func() {
			kubeEvents, err := replayer.GetKubeAuditEvents()
			Expect(err).ToNot(HaveOccurred())
			eeEvents, err := replayer.GetEEAuditEvents()
			Expect(err).ToNot(HaveOccurred())

			for _, ev := range append(kubeEvents, eeEvents...) {
				res, err := ExtractResourceFromAuditEvent(ev)
				Expect(err).ToNot(HaveOccurred())

				if ev.ObjectRef.Resource == "services" {
					// Test data has services in, but we don't archive or use services at the moment.
					Expect(res).To(BeNil())
					continue
				}

				if ev.ResponseStatus.Status == "Failure" {
					Expect(res).To(BeNil())
					continue
				}

				Expect(res).ToNot(BeNil())
				gvk := res.GetObjectKind().GroupVersionKind()
				Expect(gvk.Group).To(Equal(ev.ObjectRef.APIGroup))
				Expect(gvk.Version).To(Equal(ev.ObjectRef.APIVersion))
			}
		})
	})
})
