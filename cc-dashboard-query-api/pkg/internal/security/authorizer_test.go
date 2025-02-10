package security

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/tigera/tds-apiserver/lib/logging"
)

func TestAuthorizer(t *testing.T) {

	testCluster := "testCluster"
	logger := logging.New("TestAuthorizer")

	newAuthorizer := func(
		t *testing.T,
		userName string,
		namespace string,
		cacheTTL time.Duration,
		resourceRules []authzv1.ResourceRule,
	) (Context, Authorizer, *[]string) {
		t.Helper()

		if resourceRules == nil {
			resourceRules = []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{"lma.tigera.io"}, ResourceNames: []string{"dns"}, Resources: []string{testCluster}},
			}
		}

		namespaceHits := new([]string)
		k8sClient := fake.NewSimpleClientset()
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
			namespace,
			cacheTTL,
		)
		require.NoError(t, err)

		ctx := NewUserAuthContext(context.Background(), &user.DefaultInfo{Name: userName}, "tigera-labs", authorizer, k8sClient)

		return ctx, authorizer, namespaceHits
	}

	t.Run("authorization", func(t *testing.T) {
		t.Run("any resource", func(t *testing.T) {
			ctx, authorizer, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, nil)

			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, nil)
			require.NoError(t, err)
			require.True(t, authorized)
		})

		t.Run("a resource", func(t *testing.T) {
			ctx, authorizer, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, nil)

			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
			require.NoError(t, err)
			require.True(t, authorized)

			t.Run("against wildcard", func(t *testing.T) {
				t.Run("resources", func(t *testing.T) {
					resourceRules := []authzv1.ResourceRule{
						{Verbs: []string{"get"}, APIGroups: []string{"lma.tigera.io"}, ResourceNames: []string{"dns"}, Resources: []string{"*"}},
					}
					ctx, authorizer, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, resourceRules)

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
					ctx, authorizer, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, resourceRules)

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
			ctx, authorizer, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, nil)

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
				ctx, authorizer, _ := newAuthorizer(t, "fake-user", "", 1*time.Second, resourceRules)

				authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testClusterResource)
				require.NoError(t, err)
				require.False(t, authorized)

				authorized, err = authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, nil)
				require.NoError(t, err)
				require.False(t, authorized)
			})
		})
	})

	t.Run("namespace", func(t *testing.T) {
		t.Run("is set", func(t *testing.T) {
			ctx, authorizer, namespaceHits := newAuthorizer(t, "fake-user", "fake-namespace", 1*time.Second, nil)

			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
			require.NoError(t, err)
			require.True(t, authorized)
			require.Equal(t, []string{"fake-namespace"}, *namespaceHits)
		})
		t.Run("is unset", func(t *testing.T) {
			ctx, authorizer, namespaceHits := newAuthorizer(t, "fake-user", "", 1*time.Second, nil)

			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
			require.NoError(t, err)
			require.True(t, authorized)
			require.Equal(t, []string{"default"}, *namespaceHits)
		})
	})

	t.Run("cache", func(t *testing.T) {
		ctx, authorizer, namespaceHits := newAuthorizer(t, "fake-user", "", 1*time.Hour, nil)

		for i := 0; i < 10; i++ {
			authorized, err := authorizer.Authorize(ctx, "lma.tigera.io", []string{"dns"}, &testCluster)
			require.NoError(t, err)
			require.True(t, authorized)
			require.Equal(t, 1, len(*namespaceHits))
		}

		ctx = NewUserAuthContext(context.Background(), &user.DefaultInfo{Name: "fake-user2"}, "tigera-labs", authorizer, ctx.KubernetesClient())
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
}
