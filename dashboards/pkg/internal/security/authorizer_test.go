package security

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakeprojectcalicov3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3/fake"
	"github.com/tigera/tds-apiserver/lib/logging"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/dashboards/pkg/internal/config"
	"github.com/projectcalico/calico/lma/pkg/k8s"
)

func TestAuthorizer(t *testing.T) {

	testCluster := "testCluster"
	logger := logging.New("TestAuthorizer")

	authorizedVerbsCacheRevalidateTimeout := 2 * time.Second

	newAuthorizer := func(
		t *testing.T,
		userName string,
		namespace string,
		cacheTTL time.Duration,
		productMode string,
		namespacedRBAC bool,
		resourceRules []authzv1.ResourceRule,
		groups []string,
	) (Context, Authorizer, *k8s.MockClientSetFactory, *[]string) {
		t.Helper()

		if resourceRules == nil {
			resourceRules = []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{"lma.tigera.io"}, ResourceNames: []string{"dns"}, Resources: []string{testCluster}},
			}
		}

		namespaceHits := new([]string)
		k8sClient := k8sfake.NewClientset()
		k8sClient.PrependReactor("create", "selfsubjectrulesreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			*namespaceHits = append(*namespaceHits, action.(k8stesting.CreateAction).GetObject().(*authzv1.SelfSubjectRulesReview).Spec.Namespace)
			return true, &authzv1.SelfSubjectRulesReview{
				Status: authzv1.SubjectRulesReviewStatus{
					ResourceRules: resourceRules,
				},
			}, nil
		})

		authorizer, err := NewAuthorizer(
			context.Background(),
			logger,
			cacheTTL,
			AuthorizerConfig{
				Namespace:                             namespace,
				ProductMode:                           productMode,
				EnableNamespacedRBAC:                  namespacedRBAC,
				AuthorizedVerbsCacheHardTTL:           10 * time.Second,
				AuthorizedVerbsCacheSoftTTL:           1 * time.Second,
				AuthorizedVerbsCacheReviewsTimeout:    3 * time.Second,
				AuthorizedVerbsCacheRevalidateTimeout: authorizedVerbsCacheRevalidateTimeout,
			},
		)
		require.NoError(t, err)

		mockClientSetFactory := k8s.NewMockClientSetFactory(t)
		ctx := NewUserAuthContext(context.Background(), &user.DefaultInfo{Name: userName}, authorizer, k8sClient, "Bearer fake-token", mockClientSetFactory, "fake-tenant", groups)

		return ctx, authorizer, mockClientSetFactory, namespaceHits
	}

	t.Run("authorization resource", func(t *testing.T) {
		t.Run("any", func(t *testing.T) {
			ctx, authorizer, _, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, "fake-product-mode", false, nil, nil)

			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, nil)
			require.NoError(t, err)
			require.True(t, authorized)
		})

		t.Run("managed cluster", func(t *testing.T) {
			ctx, authorizer, _, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, "fake-product-mode", false, nil, nil)

			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
			require.NoError(t, err)
			require.True(t, authorized)
		})

		t.Run("wildcard", func(t *testing.T) {
			t.Run("resources", func(t *testing.T) {
				resourceRules := []authzv1.ResourceRule{
					{Verbs: []string{"get"}, APIGroups: []string{"lma.tigera.io"}, ResourceNames: []string{"dns"}, Resources: []string{"*"}},
				}
				ctx, authorizer, _, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, "fake-product-mode", false, resourceRules, nil)

				authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
				require.NoError(t, err)
				require.True(t, authorized)

				authorized, err = authorizer.Authorize(ctx, "lma.tigera.io", []string{"flows"}, &testCluster)
				require.NoError(t, err)
				require.False(t, authorized)
			})

			t.Run("resource names", func(t *testing.T) {
				resourceRules := []authzv1.ResourceRule{
					{Verbs: []string{"get"}, APIGroups: []string{"lma.tigera.io"}, ResourceNames: []string{"*"}, Resources: []string{testCluster}},
				}
				ctx, authorizer, _, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, "fake-product-mode", false, resourceRules, nil)

				authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
				require.NoError(t, err)
				require.True(t, authorized)

				testCluster2 := "testCluster2"
				authorized, err = authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster2)
				require.NoError(t, err)
				require.False(t, authorized)
			})

		})
	})

	t.Run("unauthorized", func(t *testing.T) {
		ctx, authorizer, _, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, "fake-product-mode", false, nil, nil)

		testCases := []struct {
			name         string
			resourceName string
			resource     string
		}{
			{
				name:         "unknown resource",
				resourceName: "dns",
				resource:     "unknown-cluster",
			},
			{
				name:         "no rule for resourceName flows",
				resourceName: "flows",
				resource:     testCluster,
			},
			{
				name:         "no rule for resourceName l7",
				resourceName: "l7",
				resource:     testCluster,
			},
			{
				name:         "managed cluster namespace",
				resourceName: "flows",
				resource:     testCluster + "/default",
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				authorized, err := authorizer.Authorize(
					ctx,
					"lma.tigera.io",
					[]string{testCase.resourceName},
					&testCase.resource,
				)
				require.NoError(t, err)
				require.False(t, authorized)
			})
		}

		t.Run("against cluster resource", func(t *testing.T) {
			testClusterResource := "cluster"
			resourceRules := []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{"lma.tigera.io"}, ResourceNames: []string{"dns"}, Resources: []string{testClusterResource}},
			}
			ctx, authorizer, _, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, "fake-product-mode", false, resourceRules, nil)

			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testClusterResource)
			require.NoError(t, err)
			require.False(t, authorized)

			authorized, err = authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, nil)
			require.NoError(t, err)
			require.False(t, authorized)
		})
	})

	t.Run("namespace", func(t *testing.T) {
		t.Run("is set", func(t *testing.T) {
			ctx, authorizer, _, namespaceHits := newAuthorizer(t, "fake-user", "fake-namespace", 1*time.Second, "fake-product-mode", false, nil, nil)

			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
			require.NoError(t, err)
			require.True(t, authorized)
			require.Equal(t, []string{"fake-namespace"}, *namespaceHits)
		})
		t.Run("is unset", func(t *testing.T) {
			ctx, authorizer, _, namespaceHits := newAuthorizer(t, "fake-user", "", 1*time.Second, "fake-product-mode", false, nil, nil)

			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
			require.NoError(t, err)
			require.True(t, authorized)
			require.Equal(t, []string{"default"}, *namespaceHits)
		})
	})

	t.Run("cache", func(t *testing.T) {
		ctx, authorizer, _, namespaceHits := newAuthorizer(t, "fake-user", "", 1*time.Hour, "fake-product-mode", false, nil, nil)

		for i := 0; i < 10; i++ {
			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
			require.NoError(t, err)
			require.True(t, authorized)
			require.Equal(t, 1, len(*namespaceHits))
		}

		mockClientSetFactory := k8s.NewMockClientSetFactory(t)
		ctx = NewUserAuthContext(context.Background(), &user.DefaultInfo{Name: "fake-user2"}, authorizer, ctx.KubernetesClient(), "Bearer fake-token", mockClientSetFactory, "fake-tenant", nil)
		authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
		require.NoError(t, err)
		require.True(t, authorized)
		require.Equal(t, 2, len(*namespaceHits))

		t.Run("key", func(t *testing.T) {
			key := toAuthorizeCacheKey(&user.DefaultInfo{
				Name:   "fake-user",
				UID:    "1000",
				Groups: []string{"fake-group"},
				Extra: map[string][]string{
					"extra1": {"extra-value1", "extra-value2"},
				}})
			require.Equal(t, `{Name:fake-user UID:1000 Groups:[fake-group] Extra:map[extra1:[extra-value1 extra-value2]]}`, key)
		})
	})

	t.Run("authorized resource verbs", func(t *testing.T) {
		t.Run("namespaced RBAC feature disabled", func(t *testing.T) {
			ctx, authorizer, _, _ := newAuthorizer(t, "fake-user", "", 1*time.Hour, "fake-product-mode", false, nil, nil)

			authVerbs, err := authorizer.GetAuthorizedResourceVerbs(ctx, []string{"fake-managed-cluster1", "fake-managed-cluster2"})
			require.NoError(t, err)
			require.Empty(t, authVerbs.Errors)
			require.Empty(t, authVerbs.AuthorizedResourceVerbs)
		})

		t.Run("namespaced RBAC feature enabled", func(t *testing.T) {
			testCases := []struct {
				name                                    string
				groups                                  []string
				productMode                             string
				authReviewError                         map[string]error
				authReviewDelay                         map[string]time.Duration
				authReviewStatusAuthorizedResourceVerbs map[string][]v3.AuthorizedResourceVerbs
				expected                                PermissionsResult
			}{
				{
					name: "with no permissions",
					authReviewStatusAuthorizedResourceVerbs: map[string][]v3.AuthorizedResourceVerbs{
						"fake-managed-cluster1": nil,
						"fake-managed-cluster2": nil,
						"fake-managed-cluster3": nil,
					},
					expected: PermissionsResult{
						Errors: nil,
						AuthorizedResourceVerbs: []v3.AuthorizedResourceVerbs{{
							APIGroup: "projectcalico.org",
						}},
					},
				},
				{
					name: "with permissions set",
					authReviewStatusAuthorizedResourceVerbs: map[string][]v3.AuthorizedResourceVerbs{
						"fake-managed-cluster1": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace1"}},
							}},
						}},
						"fake-managed-cluster2": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace2"}},
							}},
						}},
						"fake-managed-cluster3": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace3"}},
							}},
						}},
					},
					expected: PermissionsResult{
						Errors: nil,
						AuthorizedResourceVerbs: []v3.AuthorizedResourceVerbs{
							{
								APIGroup: "projectcalico.org",
								Resource: "fake-resource",
								Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{
										Namespace:      "fake-namespace1",
										ManagedCluster: "fake-managed-cluster1",
									}},
								}},
							},
							{
								APIGroup: "projectcalico.org",
								Resource: "fake-resource",
								Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{
										Namespace:      "fake-namespace2",
										ManagedCluster: "fake-managed-cluster2",
									}},
								}},
							},
							{
								APIGroup: "projectcalico.org",
								Resource: "fake-resource",
								Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{
										Namespace:      "fake-namespace3",
										ManagedCluster: "fake-managed-cluster3",
									}},
								}},
							},
						},
					},
				},
				{
					name: "with partial permissions",
					authReviewStatusAuthorizedResourceVerbs: map[string][]v3.AuthorizedResourceVerbs{
						"fake-managed-cluster1": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace1"}},
							}},
						}},
						"fake-managed-cluster2": nil,
						"fake-managed-cluster3": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace3"}},
							}},
						}},
					},
					expected: PermissionsResult{
						Errors: nil,
						AuthorizedResourceVerbs: []v3.AuthorizedResourceVerbs{
							{
								APIGroup: "projectcalico.org",
								Resource: "fake-resource",
								Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{
										Namespace:      "fake-namespace1",
										ManagedCluster: "fake-managed-cluster1",
									}},
								}},
							},
							{
								APIGroup: "projectcalico.org",
								Resource: "fake-resource",
								Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{
										Namespace:      "fake-namespace3",
										ManagedCluster: "fake-managed-cluster3",
									}},
								}},
							},
						},
					},
				},
				{
					name: "with partial permissions due to timeout",
					authReviewDelay: map[string]time.Duration{
						// must be greater than authorizedVerbsCacheReviewsTimeout
						"fake-managed-cluster2": 12 * time.Second,
					},
					authReviewStatusAuthorizedResourceVerbs: map[string][]v3.AuthorizedResourceVerbs{
						"fake-managed-cluster1": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace1"}},
							}},
						}},
						"fake-managed-cluster2": nil,
						"fake-managed-cluster3": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace3"}},
							}},
						}},
					},
					expected: PermissionsResult{
						Errors: map[string][]error{
							"fake-managed-cluster2": {ErrAuthorizationReviewTimeout},
						},
						AuthorizedResourceVerbs: []v3.AuthorizedResourceVerbs{
							{
								APIGroup: "projectcalico.org",
								Resource: "fake-resource",
								Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{
										Namespace:      "fake-namespace1",
										ManagedCluster: "fake-managed-cluster1",
									}},
								}},
							},
							{
								APIGroup: "projectcalico.org",
								Resource: "fake-resource",
								Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{
										Namespace:      "fake-namespace3",
										ManagedCluster: "fake-managed-cluster3",
									}},
								}},
							},
						},
					},
				},
				{
					name: "with partial permissions due to error",
					authReviewError: map[string]error{
						"fake-managed-cluster2": fmt.Errorf("an expected error"),
					},
					authReviewStatusAuthorizedResourceVerbs: map[string][]v3.AuthorizedResourceVerbs{
						"fake-managed-cluster1": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace1"}},
							}},
						}},
						"fake-managed-cluster2": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace2"}},
							}},
						}},
						"fake-managed-cluster3": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace3"}},
							}},
						}},
					},
					expected: PermissionsResult{
						Errors: map[string][]error{
							"fake-managed-cluster2": {fmt.Errorf("an expected error")},
						},
						AuthorizedResourceVerbs: []v3.AuthorizedResourceVerbs{
							{
								APIGroup: "projectcalico.org",
								Resource: "fake-resource",
								Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{
										Namespace:      "fake-namespace1",
										ManagedCluster: "fake-managed-cluster1",
									}},
								}},
							},
							{
								APIGroup: "projectcalico.org",
								Resource: "fake-resource",
								Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{
										Namespace:      "fake-namespace3",
										ManagedCluster: "fake-managed-cluster3",
									}},
								}},
							},
						},
					},
				},
				{
					name: "ignores non-list verbs",
					authReviewStatusAuthorizedResourceVerbs: map[string][]v3.AuthorizedResourceVerbs{
						"fake-managed-cluster1": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "create",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace1"}},
							}},
						}},
						"fake-managed-cluster2": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "update",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace2"}},
							}},
						}},
						"fake-managed-cluster3": {{
							APIGroup: "projectcalico.org",
							Resource: "fake-resource",
							Verbs: []v3.AuthorizedResourceVerb{
								{
									Verb:           "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace3"}},
								},
								{
									Verb:           "delete",
									ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace3-1"}},
								},
							},
						}},
					},
					expected: PermissionsResult{
						Errors: nil,
						AuthorizedResourceVerbs: []v3.AuthorizedResourceVerbs{
							{
								APIGroup: "projectcalico.org",
								Resource: "fake-resource",
								Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list",
									ResourceGroups: []v3.AuthorizedResourceGroup{{
										Namespace:      "fake-namespace3",
										ManagedCluster: "fake-managed-cluster3",
									}},
								}},
							},
						},
					},
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ctx, authorizer, mockClientSetFactory, _ := newAuthorizer(t, "fake-user", "", 1*time.Hour, "fake-product-mode", true, nil, nil)

					for resource, authorizedResourceVerbs := range tc.authReviewStatusAuthorizedResourceVerbs {

						// Use a distinct fake.Clientset for each resource (reusing a fake.Clientset will result in the
						// last reactor function getting called for every resource)
						fakeClient := k8sfake.NewClientset()

						fakeCalicoClient := &fakeprojectcalicov3.FakeProjectcalicoV3{Fake: &fakeClient.Fake}
						fakeCalicoClient.PrependReactor("create", "authorizationreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
							createAction, ok := action.(k8stesting.CreateAction)
							if !ok {
								return false, nil, fmt.Errorf("reactor action failed for %v (%T)", action, action)
							}

							object := createAction.GetObject().DeepCopyObject()
							authReview, ok := object.(*v3.AuthorizationReview)
							if !ok {
								return false, nil, fmt.Errorf("invalid reactor object, expecting *v3.AuthorizationReview but got %v (%T)", object, object)
							}

							authReview.Status.AuthorizedResourceVerbs = authorizedResourceVerbs

							time.Sleep(tc.authReviewDelay[resource])
							return true, authReview, tc.authReviewError[resource]
						})

						mockClientSet := k8s.NewMockClientSet(t)
						mockClientSet.On("ProjectcalicoV3").Return(fakeCalicoClient).Once()
						mockClientSetFactory.
							On("NewClientSetForApplication", resource).
							Return(mockClientSet, nil).
							Once()
					}

					permissionsResult, err := authorizer.GetAuthorizedResourceVerbs(ctx, []string{"fake-managed-cluster1", "fake-managed-cluster2", "fake-managed-cluster3"})
					require.NoError(t, err)

					require.ElementsMatch(t, tc.expected.AuthorizedResourceVerbs, permissionsResult.AuthorizedResourceVerbs)
					require.ElementsMatch(t, slices.Collect(maps.Keys(tc.expected.Errors)), slices.Collect(maps.Keys(permissionsResult.Errors)))
					for resource, errors := range permissionsResult.Errors {
						require.ElementsMatch(t, tc.expected.Errors[resource], errors)
					}
				})
			}

			t.Run("cloud group permissions", func(t *testing.T) {

				testCases := []struct {
					name      string
					groupName string
				}{
					{
						name:      "admin",
						groupName: "tigera-auth-fake-tenant-admin",
					},
					{
						name:      "dashboards admin",
						groupName: "tigera-auth-fake-tenant-dashboards-admin",
					},
					{
						name:      "viewer",
						groupName: "tigera-auth-fake-tenant-read-only",
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						ctx, authorizer, _, _ := newAuthorizer(t, "fake-user", "", 1*time.Hour, config.ProductModeCloud, true, nil, []string{tc.groupName})

						permissionsResult, err := authorizer.GetAuthorizedResourceVerbs(ctx, []string{"fake-managed-cluster1", "fake-managed-cluster2", "fake-managed-cluster3"})
						require.NoError(t, err)

						require.Empty(t, permissionsResult.Errors)
						require.Empty(t, permissionsResult.AuthorizedResourceVerbs)

					})
				}
			})
		})

		t.Run("reuse stale cache item", func(t *testing.T) {
			testCases := []struct {
				name                     string
				subsequentAuthReviewFunc func(authReview *v3.AuthorizationReview) (bool, runtime.Object, error)
			}{
				{
					name: "revalidate timeout",
					subsequentAuthReviewFunc: func(authReview *v3.AuthorizationReview) (bool, runtime.Object, error) {
						authReview.Status.AuthorizedResourceVerbs = []v3.AuthorizedResourceVerbs{{
							Resource: "fake-resource",
							APIGroup: "projectcalico.org",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace2"}},
							}},
						}}

						// delay subsequent revalidation
						time.Sleep(authorizedVerbsCacheRevalidateTimeout + 1*time.Second)
						return true, authReview, nil
					},
				},
				{
					name: "revalidate error",
					subsequentAuthReviewFunc: func(authReview *v3.AuthorizationReview) (bool, runtime.Object, error) {
						// fail revalidation
						return true, nil, fmt.Errorf("authorizationreview error")
					},
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ctx, authorizer, mockClientSetFactory, _ := newAuthorizer(t, "fake-user", "", 1*time.Hour, "fake-product-mode", true, nil, nil)

					authReviewFunc := func(authReview *v3.AuthorizationReview) (bool, runtime.Object, error) {
						authReview.Status.AuthorizedResourceVerbs = []v3.AuthorizedResourceVerbs{{
							Resource: "fake-resource",
							APIGroup: "projectcalico.org",
							Verbs: []v3.AuthorizedResourceVerb{{
								Verb:           "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{{Namespace: "fake-namespace1"}},
							}},
						}}

						return true, authReview, nil
					}

					fakeCalicoClient := &fakeprojectcalicov3.FakeProjectcalicoV3{Fake: &k8sfake.NewClientset().Fake}
					fakeCalicoClient.PrependReactor("create", "authorizationreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
						createAction, ok := action.(k8stesting.CreateAction)
						if !ok {
							return false, nil, fmt.Errorf("reactor action failed for %v (%T)", action, action)
						}

						object := createAction.GetObject().DeepCopyObject()
						authReview, ok := object.(*v3.AuthorizationReview)
						if !ok {
							return false, nil, fmt.Errorf("invalid reactor object, expecting *v3.AuthorizationReview but got %v (%T)", object, object)
						}

						return authReviewFunc(authReview)
					})

					mockClientSet := k8s.NewMockClientSet(t)
					mockClientSet.On("ProjectcalicoV3").Return(fakeCalicoClient).Twice()
					mockClientSetFactory.
						On("NewClientSetForApplication", "fake-managed-cluster1").
						Return(mockClientSet, nil).
						Twice()

					expected := []v3.AuthorizedResourceVerbs{{
						APIGroup: "projectcalico.org",
						Resource: "fake-resource",
						Verbs: []v3.AuthorizedResourceVerb{{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{{
								Namespace:      "fake-namespace1",
								ManagedCluster: "fake-managed-cluster1",
							}},
						}},
					}}

					authVerbs, err := authorizer.GetAuthorizedResourceVerbs(ctx, []string{"fake-managed-cluster1"})
					require.NoError(t, err)
					require.Equal(t, expected, authVerbs.AuthorizedResourceVerbs)

					// expire revalidateAt
					cacheKey := toAuthorizeCacheKeyForResource(ctx.UserInfo(), "fake-managed-cluster1")
					cacheEntry, err := authorizer.(*rulesAuthorizer).authorizedResourceVerbsCache.GetOrLoad(cacheKey, func() (*authorizedResourcesVerbsCacheEntry, error) {
						return nil, fmt.Errorf("expected cache item to already exist but it did not")
					})
					require.NoError(t, err)
					cacheEntry.expireRevalidateAt()

					authReviewFunc = tc.subsequentAuthReviewFunc

					authVerbs, err = authorizer.GetAuthorizedResourceVerbs(ctx, []string{"fake-managed-cluster1"})
					require.NoError(t, err)
					require.Equal(t, expected, authVerbs.AuthorizedResourceVerbs)
				})
			}
		})
	})
}
