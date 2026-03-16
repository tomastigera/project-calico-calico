// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package authzreview

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	calicofake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	projectcalicov3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/discovery"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

// mockCalculator is a test double for rbac.Calculator.
type mockCalculator struct {
	permissions rbac.Permissions
	err         error
	calls       int
}

func (m *mockCalculator) CalculatePermissions(u user.Info, rvs []rbac.ResourceVerbs) (rbac.Permissions, error) {
	m.calls++
	return m.permissions, m.err
}

func testUser() user.Info {
	return &user.DefaultInfo{Name: "test-user", Groups: []string{"system:authenticated"}}
}

func testAttrs() []v3.AuthorizationReviewResourceAttributes {
	return []v3.AuthorizationReviewResourceAttributes{
		{
			APIGroup:  "projectcalico.org",
			Resources: []string{"tiers"},
			Verbs:     []string{"get"},
		},
	}
}

// newWorkingClientSet returns a fakeClientSet whose CalculatePermissions will succeed
// (discovery returns the requested resource types).
func newWorkingClientSet() *fakeClientSet {
	return &fakeClientSet{
		Clientset: k8sfake.NewSimpleClientset(),
		calico:    calicofake.NewSimpleClientset().ProjectcalicoV3(),
	}
}

// newForbiddenClientSet returns a fakeClientSet whose discovery returns Forbidden,
// causing CalculatePermissions to fail with a Forbidden error.
func newForbiddenClientSet() *fakeClientSet {
	return &fakeClientSet{
		Clientset:         k8sfake.NewSimpleClientset(),
		calico:            calicofake.NewSimpleClientset().ProjectcalicoV3(),
		discoveryOverride: &forbiddenDiscovery{},
	}
}

// newCRDClientSet returns a fakeClientSet that handles AuthorizationReview CRD
// creation, simulating a managed cluster with the AuthorizationReview API. The
// returned review echoes back the requested attributes as authorized verbs.
func newCRDClientSet() *fakeClientSet {
	calicoFake := calicofake.NewSimpleClientset()
	calicoFake.PrependReactor("create", "authorizationreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		createAction := action.(k8stesting.CreateAction)
		review := createAction.GetObject().(*v3.AuthorizationReview)
		review.Status = v3.AuthorizationReviewStatus{
			AuthorizedResourceVerbs: []v3.AuthorizedResourceVerbs{
				{
					APIGroup: "projectcalico.org",
					Resource: "tiers",
					Verbs: []v3.AuthorizedResourceVerb{
						{Verb: "get"},
					},
				},
			},
		}
		return true, review, nil
	})
	return &fakeClientSet{
		Clientset: k8sfake.NewSimpleClientset(),
		calico:    calicoFake.ProjectcalicoV3(),
	}
}

func TestReviewLocalCluster(t *testing.T) {
	calc := &mockCalculator{
		permissions: rbac.Permissions{
			rbac.ResourceType{APIGroup: "projectcalico.org", Resource: "tiers"}: {
				rbac.VerbGet: []rbac.Match{{Tier: "default"}},
			},
		},
	}
	r := NewAuthzReviewer(calc, nil)

	verbs, err := r.Review(context.Background(), testUser(), "", testAttrs())
	require.NoError(t, err)
	require.Len(t, verbs, 1)
	require.Equal(t, "tiers", verbs[0].Resource)
	require.Equal(t, 1, calc.calls)
}

func TestReviewLocalClusterDefaultClusterName(t *testing.T) {
	calc := &mockCalculator{
		permissions: rbac.Permissions{},
	}
	r := NewAuthzReviewer(calc, nil)

	verbs, err := r.Review(context.Background(), testUser(), lmak8s.DefaultCluster, testAttrs())
	require.NoError(t, err)
	require.Empty(t, verbs)
	require.Equal(t, 1, calc.calls)
}

func TestReviewLocalClusterError(t *testing.T) {
	calc := &mockCalculator{
		err: errors.New("boom"),
	}
	r := NewAuthzReviewer(calc, nil)

	_, err := r.Review(context.Background(), testUser(), "", testAttrs())
	require.Error(t, err)
	require.Contains(t, err.Error(), "boom")
}

func TestReviewLocalClusterZeroPermissions(t *testing.T) {
	calc := &mockCalculator{
		permissions: rbac.Permissions{},
	}
	r := NewAuthzReviewer(calc, nil)

	verbs, err := r.Review(context.Background(), testUser(), "", testAttrs())
	require.NoError(t, err)
	require.Empty(t, verbs)
}

func TestReviewForLogs(t *testing.T) {
	calc := &mockCalculator{
		permissions: rbac.Permissions{},
	}
	r := NewAuthzReviewer(calc, nil)

	verbs, err := r.ReviewForLogs(context.Background(), testUser(), "")
	require.NoError(t, err)
	require.Empty(t, verbs)
	require.Equal(t, 1, calc.calls)
}

// TestReviewManagedClusterFactorySelection tests that the reviewer selects the
// right ClientSetFactory depending on what's available in the context vs. the
// static configuration. This covers the Enterprise (static-only), Cloud
// single-tenant, and Cloud multi-tenant scenarios.
func TestReviewManagedClusterFactorySelection(t *testing.T) {
	t.Run("no factory configured at all", func(t *testing.T) {
		r := NewAuthzReviewer(&mockCalculator{}, nil)

		_, err := r.Review(context.Background(), testUser(), "managed-01", testAttrs())
		require.Error(t, err)
		require.Contains(t, err.Error(), "no ClientSetFactory configured")
	})

	t.Run("static factory only (enterprise mode)", func(t *testing.T) {
		// Enterprise: no context factory, reviewer uses the static factory.
		staticFactory := &lmak8s.MockClientSetFactory{}
		staticFactory.On("NewClientSetForApplication", "managed-01").
			Return(newWorkingClientSet(), nil)

		r := NewAuthzReviewer(&mockCalculator{permissions: rbac.Permissions{}}, staticFactory)

		_, err := r.Review(context.Background(), testUser(), "managed-01", testAttrs())
		require.NoError(t, err)
		staticFactory.AssertCalled(t, "NewClientSetForApplication", "managed-01")
	})

	t.Run("context factory preferred over static (cloud mode)", func(t *testing.T) {
		// Cloud: per-request factory (user JWT) is set in context and should
		// be used instead of the static SA-identity factory.
		staticFactory := &lmak8s.MockClientSetFactory{}

		ctxFactory := &lmak8s.MockClientSetFactory{}
		ctxFactory.On("NewClientSetForApplication", "managed-01").
			Return(newWorkingClientSet(), nil)

		r := NewAuthzReviewer(&mockCalculator{permissions: rbac.Permissions{}}, staticFactory)
		ctx := ContextWithClientSetFactory(context.Background(), ctxFactory)

		_, err := r.Review(ctx, testUser(), "managed-01", testAttrs())
		require.NoError(t, err)
		ctxFactory.AssertCalled(t, "NewClientSetForApplication", "managed-01")
		staticFactory.AssertNotCalled(t, "NewClientSetForApplication", "managed-01")
	})

	t.Run("context factory only, no static (cloud mode)", func(t *testing.T) {
		ctxFactory := &lmak8s.MockClientSetFactory{}
		ctxFactory.On("NewClientSetForApplication", "managed-01").
			Return(newWorkingClientSet(), nil)

		r := NewAuthzReviewer(&mockCalculator{permissions: rbac.Permissions{}}, nil)
		ctx := ContextWithClientSetFactory(context.Background(), ctxFactory)

		_, err := r.Review(ctx, testUser(), "managed-01", testAttrs())
		require.NoError(t, err)
		ctxFactory.AssertCalled(t, "NewClientSetForApplication", "managed-01")
	})

	t.Run("factory returns error", func(t *testing.T) {
		factory := &lmak8s.MockClientSetFactory{}
		factory.On("NewClientSetForApplication", "managed-01").
			Return(nil, errors.New("connection refused"))

		r := NewAuthzReviewer(&mockCalculator{}, factory)

		_, err := r.Review(context.Background(), testUser(), "managed-01", testAttrs())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create client set")
		require.Contains(t, err.Error(), "connection refused")
	})
}

// TestReviewManagedClusterForbiddenFallback tests the CRD fallback path that
// activates when the managed cluster's RBAC returns a Forbidden error (e.g.,
// older cluster without ClusterRole list access, or guardian identity without
// RBAC permissions).
func TestReviewManagedClusterForbiddenFallback(t *testing.T) {
	t.Run("forbidden triggers CRD fallback with context factory", func(t *testing.T) {
		// Simulates Cloud multi-tenant: user's JWT factory is in context.
		// Primary path returns forbidden, fallback creates AuthorizationReview CRD.
		ctxFactory := &lmak8s.MockClientSetFactory{}
		ctxFactory.On("NewClientSetForApplication", "managed-01").
			Return(newForbiddenClientSet(), nil).Once()
		ctxFactory.On("NewClientSetForApplication", "managed-01").
			Return(newCRDClientSet(), nil).Once()

		r := NewAuthzReviewer(&mockCalculator{}, nil)
		ctx := ContextWithClientSetFactory(context.Background(), ctxFactory)

		verbs, err := r.Review(ctx, testUser(), "managed-01", testAttrs())
		require.NoError(t, err)
		require.Len(t, verbs, 1)
		require.Equal(t, "tiers", verbs[0].Resource)
	})

	t.Run("forbidden triggers CRD fallback with static factory", func(t *testing.T) {
		// Simulates Enterprise: no context factory, static factory used for
		// both primary and fallback paths.
		staticFactory := &lmak8s.MockClientSetFactory{}
		staticFactory.On("NewClientSetForApplication", "managed-01").
			Return(newForbiddenClientSet(), nil).Once()
		staticFactory.On("NewClientSetForApplication", "managed-01").
			Return(newCRDClientSet(), nil).Once()

		r := NewAuthzReviewer(&mockCalculator{}, staticFactory)

		verbs, err := r.Review(context.Background(), testUser(), "managed-01", testAttrs())
		require.NoError(t, err)
		require.Len(t, verbs, 1)
		require.Equal(t, "tiers", verbs[0].Resource)
	})

	t.Run("fallback CRD creation fails", func(t *testing.T) {
		ctxFactory := &lmak8s.MockClientSetFactory{}
		ctxFactory.On("NewClientSetForApplication", "managed-01").
			Return(newForbiddenClientSet(), nil).Once()
		ctxFactory.On("NewClientSetForApplication", "managed-01").
			Return(nil, errors.New("fallback factory error")).Once()

		r := NewAuthzReviewer(&mockCalculator{}, nil)
		ctx := ContextWithClientSetFactory(context.Background(), ctxFactory)

		_, err := r.Review(ctx, testUser(), "managed-01", testAttrs())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create fallback client set")
		require.Contains(t, err.Error(), "fallback factory error")
	})

	t.Run("non-forbidden error skips fallback", func(t *testing.T) {
		// If the primary path returns a non-forbidden error (e.g., network
		// timeout), the fallback should NOT be triggered.
		ctxFactory := &lmak8s.MockClientSetFactory{}
		ctxFactory.On("NewClientSetForApplication", "managed-01").
			Return(nil, errors.New("network timeout"))

		r := NewAuthzReviewer(&mockCalculator{}, nil)
		ctx := ContextWithClientSetFactory(context.Background(), ctxFactory)

		_, err := r.Review(ctx, testUser(), "managed-01", testAttrs())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create client set")
		require.Contains(t, err.Error(), "network timeout")
		// Factory should only be called once (primary path), not twice (no fallback).
		ctxFactory.AssertNumberOfCalls(t, "NewClientSetForApplication", 1)
	})
}

// fakeClientSet wraps K8s and Calico fakes, with an optional discovery override for testing
// forbidden scenarios.
type fakeClientSet struct {
	*k8sfake.Clientset
	calico            projectcalicov3.ProjectcalicoV3Interface
	discoveryOverride discovery.DiscoveryInterface
}

func (f *fakeClientSet) Discovery() discovery.DiscoveryInterface {
	if f.discoveryOverride != nil {
		return f.discoveryOverride
	}
	return f.Clientset.Discovery()
}

func (f *fakeClientSet) ProjectcalicoV3() projectcalicov3.ProjectcalicoV3Interface {
	return f.calico
}

// forbiddenDiscovery returns a forbidden error from ServerPreferredResources.
type forbiddenDiscovery struct {
	discovery.DiscoveryInterface
}

func (f *forbiddenDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	return nil, forbiddenErr("serverresources")
}

func forbiddenErr(resource string) error {
	return kerrors.NewForbidden(
		schema.GroupResource{Resource: resource}, "",
		fmt.Errorf("forbidden"),
	)
}

func TestAggregateContains(t *testing.T) {
	forbidden := forbiddenErr("clusterroles")
	notFound := kerrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "foo")
	generic := errors.New("something broke")

	t.Run("direct match", func(t *testing.T) {
		require.True(t, aggregateContains(forbidden, kerrors.IsForbidden))
		require.False(t, aggregateContains(forbidden, kerrors.IsUnauthorized))
	})

	t.Run("aggregate with forbidden", func(t *testing.T) {
		agg := utilerrors.NewAggregate([]error{generic, forbidden})
		require.True(t, aggregateContains(agg, kerrors.IsForbidden))
		require.False(t, aggregateContains(agg, kerrors.IsUnauthorized))
	})

	t.Run("nested aggregate", func(t *testing.T) {
		inner := utilerrors.NewAggregate([]error{forbidden})
		outer := utilerrors.NewAggregate([]error{generic, inner})
		require.True(t, aggregateContains(outer, kerrors.IsForbidden))
	})

	t.Run("aggregate without forbidden", func(t *testing.T) {
		agg := utilerrors.NewAggregate([]error{generic, notFound})
		require.False(t, aggregateContains(agg, kerrors.IsForbidden))
	})

	t.Run("nil error", func(t *testing.T) {
		require.False(t, aggregateContains(nil, kerrors.IsForbidden))
	})

	t.Run("non-aggregate non-match", func(t *testing.T) {
		require.False(t, aggregateContains(generic, kerrors.IsForbidden))
	})
}
