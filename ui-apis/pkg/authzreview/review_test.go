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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/discovery"
	k8sfake "k8s.io/client-go/kubernetes/fake"

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

func TestReviewManagedClusterNilCSFactory(t *testing.T) {
	calc := &mockCalculator{}
	r := NewAuthzReviewer(calc, nil)

	_, err := r.Review(context.Background(), testUser(), "managed-01", testAttrs())
	require.Error(t, err)
	require.Contains(t, err.Error(), "no ClientSetFactory configured")
	require.Contains(t, err.Error(), "managed-01")
	// Local calculator should not have been called.
	require.Equal(t, 0, calc.calls)
}

func TestReviewManagedClusterCSFactoryError(t *testing.T) {
	calc := &mockCalculator{}
	factory := &lmak8s.MockClientSetFactory{}
	factory.On("NewClientSetForApplication", "managed-01").Return(nil, errors.New("connection refused"))

	r := NewAuthzReviewer(calc, factory)

	_, err := r.Review(context.Background(), testUser(), "managed-01", testAttrs())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create client set")
	require.Equal(t, 0, calc.calls)
}

func TestReviewManagedClusterFallbackUsesContextFactory(t *testing.T) {
	// The static factory returns a client whose discovery is forbidden, triggering the fallback.
	staticFactory := &lmak8s.MockClientSetFactory{}
	staticFactory.On("NewClientSetForApplication", "managed-01").Return(nil, errors.New("connection refused"))

	// The context factory should be used for the CRD fallback instead.
	ctxFactory := &lmak8s.MockClientSetFactory{}
	ctxFactory.On("NewClientSetForApplication", "managed-01").Return(nil, errors.New("context factory called"))

	calc := &mockCalculator{}
	r := NewAuthzReviewer(calc, staticFactory)

	ctx := ContextWithClientSetFactory(context.Background(), ctxFactory)
	_, err := r.Review(ctx, testUser(), "managed-01", testAttrs())
	require.Error(t, err)
	// The static factory error ("connection refused") fires first for the calculator path.
	// The context factory should NOT be called because the static factory error is not
	// Forbidden/Unauthorized, so we don't enter the fallback path.
	require.Contains(t, err.Error(), "failed to create client set")
	ctxFactory.AssertNotCalled(t, "NewClientSetForApplication", "managed-01")
}

func TestReviewManagedClusterFallbackPrefersContextFactory(t *testing.T) {
	// Static factory returns a client with forbidden discovery to trigger fallback.
	calc := &mockCalculator{}
	staticFactory := &lmak8s.MockClientSetFactory{}
	forbiddenCS := &fakeClientSet{
		Clientset:         k8sfake.NewSimpleClientset(),
		calico:            calicofake.NewSimpleClientset().ProjectcalicoV3(),
		discoveryOverride: &forbiddenDiscovery{},
	}
	staticFactory.On("NewClientSetForApplication", "managed-01").Return(forbiddenCS, nil)

	// Context factory should be used for the CRD fallback.
	ctxFactory := &lmak8s.MockClientSetFactory{}
	ctxFactory.On("NewClientSetForApplication", "managed-01").Return(nil, errors.New("ctx factory error"))

	r := NewAuthzReviewer(calc, staticFactory)
	ctx := ContextWithClientSetFactory(context.Background(), ctxFactory)

	_, err := r.Review(ctx, testUser(), "managed-01", testAttrs())
	require.Error(t, err)
	// The fallback should have used the context factory, not the static one.
	require.Contains(t, err.Error(), "failed to create fallback client set")
	ctxFactory.AssertCalled(t, "NewClientSetForApplication", "managed-01")
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
