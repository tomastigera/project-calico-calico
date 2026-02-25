package user

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("User", func() {
	Context("EncodedSubjectID", func() {
		It("returns the original subject id if it's already base64 encoded", func() {
			user := OIDCUser{
				SubjectID: "U3ViamVjdElE",
			}
			Expect(user.Base64EncodedSubjectID()).Should(Equal(user.SubjectID))
		})
		It("returns the base64 encoded subject id if it's not already base64 encoded", func() {
			user := OIDCUser{
				SubjectID: "SubjectID",
			}
			Expect(user.Base64EncodedSubjectID()).Should(Equal("U3ViamVjdElE"))
		})
	})
})
