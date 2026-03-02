// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package authzreview

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apiserver/pkg/authentication/user"

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
