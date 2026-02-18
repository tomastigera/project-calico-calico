package auth

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientsetfake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

var _ = Describe("queryserver resource authorizer tests", func() {
	var authz Authorizer
	var mockClientSetFactory *lmak8s.MockClientSetFactory

	BeforeEach(func() {
		mockClientSet := &lmak8s.MockClientSet{}
		mockClientSetFactory = &lmak8s.MockClientSetFactory{}
		mockClientSetFactory.On("NewClientSetForApplication", mock.Anything, mock.Anything).Return(mockClientSet, nil).Maybe()
		mockClientSet.On("ProjectcalicoV3").Return(clientsetfake.NewSimpleClientset().ProjectcalicoV3()).Maybe()

		authz = NewAuthorizer(mockClientSetFactory)
	})

	Context("Test authorizer.PerformUserAuthorizationReview", func() {
		It("return user unauthorized when user is not set in context", func() {
			_, err := authz.PerformUserAuthorizationReview(context.TODO(), nil)
			Expect(err).Should(HaveOccurred())
		})
		It("return permissions for the set user", func() {
			ctx := request.WithUser(context.TODO(), &user.DefaultInfo{
				Name:   "qs-authz-test",
				UID:    "id-12345",
				Groups: nil,
				Extra:  nil,
			})
			permissions, err := authz.PerformUserAuthorizationReview(ctx, nil)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(permissions).ToNot(BeNil())
		})
	})

	Context("Test permissions", func() {
		authorizedResourceVerbs := []v3.AuthorizedResourceVerbs{
			{
				APIGroup: "projectcalico.org",
				Resource: "networkpolicies",
				Verbs: []v3.AuthorizedResourceVerb{
					{
						Verb:           "get",
						ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "ns-a"}},
					},
					{
						Verb:           "list",
						ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "ns-b"}},
					},
				},
			},
		}
		It("test convertAuthorizationReviewStatusToPermissions", func() {
			permissions, err := convertAuthorizationReviewStatusToPermissions(authorizedResourceVerbs)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(permissions).ToNot(BeNil())

		})

		It("test Permissions.IsAuthorized", func() {
			permissions, err := convertAuthorizationReviewStatusToPermissions(authorizedResourceVerbs)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(permissions).ToNot(BeNil())

			networkpolicy1 := v3.NewNetworkPolicy()
			networkpolicy1.ObjectMeta = metav1.ObjectMeta{
				Name:      "netpolicy1",
				Namespace: "ns-a",
			}
			networkpolicy1.Spec = v3.NetworkPolicySpec{
				Tier: "default",
			}

			Expect(permissions.IsAuthorized(networkpolicy1, nil, []rbac.Verb{rbac.VerbGet})).To(BeTrue())

			networkpolicy2 := v3.NewNetworkPolicy()
			networkpolicy2.ObjectMeta = metav1.ObjectMeta{
				Name:      "netpolicy1",
				Namespace: "ns-b",
			}
			networkpolicy2.Spec = v3.NetworkPolicySpec{
				Tier: "default",
			}
			tier := "default"
			Expect(permissions.IsAuthorized(networkpolicy2, &tier, []rbac.Verb{rbac.VerbGet})).To(BeFalse())
		})
	})

})
