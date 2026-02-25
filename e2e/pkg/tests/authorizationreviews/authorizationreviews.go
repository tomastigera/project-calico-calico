// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authorizationreviews

import (
	"context"
	"fmt"
	"time"

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	calicov3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("AuthorizationReview"),
	describe.WithCategory(describe.Configuration),
	"AuthorizationReview tests",
	func() {
		f := utils.NewDefaultFramework("authorization-review")

		var (
			calicoClient calicov3.ProjectcalicoV3Interface
			ctx          context.Context
		)

		ginkgo.BeforeEach(func() {
			var err error
			calicoClient, err = calicov3.NewForConfig(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			ctx = context.Background()
		})

		ginkgo.It("should return authorized verbs for the current user", func() {
			ar := v3.NewAuthorizationReview()
			ar.GenerateName = "authz-review-"
			ar.Spec = v3.AuthorizationReviewSpec{
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"pods"},
						Verbs:     []string{"list"},
					},
				},
			}

			result, err := calicoClient.AuthorizationReviews().Create(ctx, ar, metav1.CreateOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			// The e2e runner has cluster-admin permissions, so the response should
			// contain an entry for pods with the list verb authorized.
			found := false
			for _, rv := range result.Status.AuthorizedResourceVerbs {
				if rv.APIGroup == "" && rv.Resource == "pods" {
					for _, v := range rv.Verbs {
						if v.Verb == "list" {
							found = true
							break
						}
					}
				}
			}
			Expect(found).To(BeTrue(), "expected pods/list to be authorized for cluster-admin user")
		})

		ginkgo.It("should return authorized verbs matching a custom RBAC setup", func() {
			testUser := "authz-review-test-user"
			crName := "authz-review-test-role"
			crbName := "authz-review-test-binding"

			// Create a ClusterRole that grants get and list on configmaps.
			cr := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: crName},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"configmaps"},
						Verbs:     []string{"get", "list"},
					},
				},
			}
			_, err := f.ClientSet.RbacV1().ClusterRoles().Create(ctx, cr, metav1.CreateOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			ginkgo.DeferCleanup(func() {
				_ = f.ClientSet.RbacV1().ClusterRoles().Delete(context.Background(), crName, metav1.DeleteOptions{})
			})

			// Bind the ClusterRole to the test user.
			crb := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: crbName},
				Subjects: []rbacv1.Subject{
					{
						Kind:     "User",
						Name:     testUser,
						APIGroup: "rbac.authorization.k8s.io",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     crName,
				},
			}
			_, err = f.ClientSet.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			ginkgo.DeferCleanup(func() {
				_ = f.ClientSet.RbacV1().ClusterRoleBindings().Delete(context.Background(), crbName, metav1.DeleteOptions{})
			})

			// RBAC changes may take time to propagate. Use Eventually to handle cache delay.
			Eventually(func() error {
				ar := v3.NewAuthorizationReview()
				ar.GenerateName = "authz-review-"
				ar.Spec = v3.AuthorizationReviewSpec{
					User: testUser,
					ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
						{
							APIGroup:  "",
							Resources: []string{"configmaps"},
							Verbs:     []string{"get", "list"},
						},
					},
				}

				result, err := calicoClient.AuthorizationReviews().Create(ctx, ar, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("failed to create AuthorizationReview: %w", err)
				}

				for _, rv := range result.Status.AuthorizedResourceVerbs {
					if rv.APIGroup == "" && rv.Resource == "configmaps" {
						verbs := map[string]bool{}
						for _, v := range rv.Verbs {
							verbs[v.Verb] = true
						}
						if verbs["get"] && verbs["list"] {
							return nil
						}
						return fmt.Errorf("expected get and list verbs, got %v", verbs)
					}
				}
				return fmt.Errorf("configmaps entry not found in authorized resource verbs")
			}, 30*time.Second, 2*time.Second).ShouldNot(HaveOccurred())
		})

		ginkgo.It("should return empty resource groups for a user with no roles", func() {
			ar := v3.NewAuthorizationReview()
			ar.GenerateName = "authz-review-"
			ar.Spec = v3.AuthorizationReviewSpec{
				User: "nonexistent-user-no-roles",
				ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
					{
						APIGroup:  "",
						Resources: []string{"pods"},
						Verbs:     []string{"list"},
					},
				},
			}

			result, err := calicoClient.AuthorizationReviews().Create(ctx, ar, metav1.CreateOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			// A user with no roles should have no authorized resource groups.
			for _, rv := range result.Status.AuthorizedResourceVerbs {
				for _, v := range rv.Verbs {
					Expect(v.ResourceGroups).To(BeEmpty(),
						fmt.Sprintf("expected empty resource groups for verb %q on %s/%s", v.Verb, rv.APIGroup, rv.Resource))
				}
			}
		})
	})
