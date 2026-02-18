package auth

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/testing"
)

var _ = Describe("RBACAuthorizer", func() {
	Context("Authorize", func() {
		var fakeK8sCli *fake.Clientset
		var rbacAuthorizer RBACAuthorizer

		BeforeEach(func() {
			fakeK8sCli = new(fake.Clientset)
			rbacAuthorizer = NewRBACAuthorizer(fakeK8sCli)
		})

		It("returns a forbidden status if the user is nil", func() {
			authorized, err := rbacAuthorizer.Authorize(nil, &authzv1.ResourceAttributes{}, &authzv1.NonResourceAttributes{})

			Expect(err).Should(HaveOccurred())
			Expect(authorized).Should(BeFalse())
		})

		It("returns a forbidden status if both the resource and non resource attributes are nil", func() {
			rbacAuthorizer = NewRBACAuthorizer(fakeK8sCli)
			authorized, err := rbacAuthorizer.Authorize(&user.DefaultInfo{}, nil, nil)

			Expect(err).Should(HaveOccurred())
			Expect(authorized).Should(BeFalse())
		})

		It("tests all settable fields in the SubjectAccessReview are set correctly", func() {
			By("adding a reactor to the fake k8s client to check what SubjectAccessReview is passed to the k8s client")
			fakeK8sCli.AddReactor("create", "subjectaccessreviews", func(action testing.Action) (handled bool, ret runtime.Object, err error) {
				createAction, ok := action.(testing.CreateAction)
				if !ok {
					panic("create action was expected")
				}

				Expect(createAction.GetObject()).To(Equal(&authzv1.SubjectAccessReview{
					Spec: authzv1.SubjectAccessReviewSpec{
						User:   "testName",
						UID:    "testUID",
						Groups: []string{"group1", "group2"},
						Extra: map[string]authzv1.ExtraValue{
							"extra1": {"value11", "value12"},
							"extra2": {"value21", "value22"},
						},
						ResourceAttributes: &authzv1.ResourceAttributes{
							Namespace:   "testNamespace",
							Name:        "testName",
							Verb:        "get",
							Group:       "testGroup",
							Version:     "testVersion",
							Resource:    "testResource",
							Subresource: "testSubresource",
						},
						NonResourceAttributes: &authzv1.NonResourceAttributes{
							Verb: "create",
							Path: "testPath",
						},
					},
				}))
				return true, &authzv1.SubjectAccessReview{}, nil
			})

			// We don't care about the return values for this test, this is just to verify the expected SubjectAccessReview
			// is created correctly.
			_, _ = rbacAuthorizer.Authorize(&user.DefaultInfo{
				Name:   "testName",
				UID:    "testUID",
				Groups: []string{"group1", "group2"},
				Extra: map[string][]string{
					"extra1": {"value11", "value12"},
					"extra2": {"value21", "value22"},
				},
			}, &authzv1.ResourceAttributes{
				Namespace:   "testNamespace",
				Name:        "testName",
				Verb:        "get",
				Group:       "testGroup",
				Version:     "testVersion",
				Resource:    "testResource",
				Subresource: "testSubresource",
			}, &authzv1.NonResourceAttributes{
				Verb: "create",
				Path: "testPath",
			})
		})

		DescribeTable("test returned statuses",
			func(allowed bool, sarError error, expectedStatus bool, expectedError error) {
				fakeK8sCli.AddReactor("create", "subjectaccessreviews", func(action testing.Action) (bool, runtime.Object, error) {
					return true, &authzv1.SubjectAccessReview{
						Status: authzv1.SubjectAccessReviewStatus{
							Allowed: allowed, Denied: !allowed,
						}}, sarError
				})

				// The value of the parameters here don't matter because we're controlling the response for the created
				// SubjectAccessReview
				authorized, err := rbacAuthorizer.Authorize(
					&user.DefaultInfo{}, &authzv1.ResourceAttributes{}, &authzv1.NonResourceAttributes{})

				Expect(authorized).Should(Equal(expectedStatus))
				if expectedError == nil {
					Expect(err).Should(BeNil())
				} else {
					Expect(err).Should(Equal(expectedError))
				}
			},
			Entry(
				"returns true if the subject access review returns as status of allowed",
				true, nil, true, nil,
			),
			Entry(
				"returns false if the subject access review returns as status of denied",
				false, nil, false,
				nil,
			),
			Entry("returns a 500 status if the subject access review returns an error",
				false, fmt.Errorf("some error"), false, fmt.Errorf("error performing AccessReview: some error"),
			),
		)
	})
})
