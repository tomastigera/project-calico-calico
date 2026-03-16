// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package authzreview

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

// authReviewAttrListEndpoints is the set of authorization resource attributes required for
// filtering flow logs and other log types.
var authReviewAttrListEndpoints = []v3.AuthorizationReviewResourceAttributes{
	{
		APIGroup: "projectcalico.org",
		Resources: []string{
			"hostendpoints",
			"networksets",
			"globalnetworksets",
			"networkpolicies",
			"globalnetworkpolicies",
			"packetcaptures",
		},
		Verbs: []string{"list"},
	},
	{
		APIGroup:  "",
		Resources: []string{"pods", "nodes", "events"},
		Verbs:     []string{"list"},
	},
	{
		APIGroup:  "networking.k8s.io",
		Resources: []string{"networkpolicies"},
		Verbs:     []string{"list"},
	},
}

// Reviewer computes RBAC permissions for users.
type Reviewer interface {
	// Review computes authorization permissions for the given user and resource attributes.
	// Pass "" for cluster to review against the local cluster.
	Review(ctx context.Context, usr user.Info, cluster string, attrs []v3.AuthorizationReviewResourceAttributes) ([]v3.AuthorizedResourceVerbs, error)

	// ReviewForLogs is a convenience that reviews the standard set of log-related resources
	// (pods, nodes, events, hostendpoints, networksets, etc.).
	ReviewForLogs(ctx context.Context, usr user.Info, cluster string) ([]v3.AuthorizedResourceVerbs, error)
}

type csFactoryContextKey struct{}

// ContextWithClientSetFactory returns a new context carrying the given ClientSetFactory.
// When present, the reviewer prefers this factory over the static one configured at
// construction time for all managed cluster operations. This allows callers (e.g., the
// dashboard in Calico Cloud mode) to supply a per-request factory that authenticates as
// the end user rather than the application service account.
func ContextWithClientSetFactory(ctx context.Context, f lmak8s.ClientSetFactory) context.Context {
	return context.WithValue(ctx, csFactoryContextKey{}, f)
}

func clientSetFactoryFromContext(ctx context.Context) lmak8s.ClientSetFactory {
	f, _ := ctx.Value(csFactoryContextKey{}).(lmak8s.ClientSetFactory)
	return f
}

// reviewer is the concrete implementation that wraps an rbac.Calculator for the local
// (management) cluster and optionally a ClientSetFactory for reaching managed clusters.
type reviewer struct {
	calculator rbac.Calculator
	csFactory  lmak8s.ClientSetFactory
}

// NewAuthzReviewer creates a Reviewer. csFactory may be nil if only local cluster reviews
// are needed (e.g., in queryserver).
func NewAuthzReviewer(calculator rbac.Calculator, csFactory lmak8s.ClientSetFactory) Reviewer {
	return &reviewer{calculator: calculator, csFactory: csFactory}
}

// Review computes authorization permissions for the given user and resource attributes.
// For managed clusters, a per-cluster calculator is created via the ClientSetFactory; if
// the managed cluster returns a permission error (older release without RBAC list access),
// the review falls back to the API server AuthorizationReview implementation through the tunnel.
func (r *reviewer) Review(
	ctx context.Context,
	usr user.Info,
	cluster string,
	attrs []v3.AuthorizationReviewResourceAttributes,
) ([]v3.AuthorizedResourceVerbs, error) {
	rvs := requestToResourceVerbs(attrs)

	if cluster == "" || cluster == lmak8s.DefaultCluster {
		// Local cluster: use the provided calculator directly.
		results, err := r.calculator.CalculatePermissions(usr, rvs)
		if err != nil {
			return nil, err
		}
		return permissionsToStatus(results).AuthorizedResourceVerbs, nil
	}

	// Managed cluster: need a ClientSetFactory. Prefer a per-request factory from
	// the context if one was provided. In Calico Cloud, the dashboard's per-request
	// factory authenticates as the end user (via JWT bearer token), which is required
	// because voltron/guardian won't allow the application SA to impersonate through
	// the tunnel. If no context factory is available, fall back to the static
	// application-identity factory.
	csFactory := clientSetFactoryFromContext(ctx)
	if csFactory == nil {
		csFactory = r.csFactory
	}
	if csFactory == nil {
		return nil, fmt.Errorf("cannot review managed cluster %q: no ClientSetFactory configured", cluster)
	}

	cs, err := csFactory.NewClientSetForApplication(cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to create client set for cluster %q: %w", cluster, err)
	}

	mcCalculator := newCalculatorForClientSet(cs)
	results, err := mcCalculator.CalculatePermissions(usr, rvs)
	if err == nil {
		return permissionsToStatus(results).AuthorizedResourceVerbs, nil
	}

	// If the error is forbidden or unauthorized, fall back to the AuthorizationReview
	// CRD (older cluster that doesn't grant RBAC list access). We use
	// aggregateContains because the calculator wraps errors in a utilerrors.Aggregate,
	// which supports errors.Is() but not errors.As(). The kerrors.IsX helpers use
	// errors.As() internally, so they won't match through an aggregate directly.
	if aggregateContains(err, kerrors.IsForbidden) || aggregateContains(err, kerrors.IsUnauthorized) {
		log.WithError(err).WithField("cluster", cluster).Info("Calculator returned permission error, falling back to AuthorizationReview CRD")

		fallbackCS, csErr := csFactory.NewClientSetForApplication(cluster)
		if csErr != nil {
			return nil, fmt.Errorf("failed to create fallback client set for cluster %q: %w", cluster, csErr)
		}

		review := &v3.AuthorizationReview{
			Spec: v3.AuthorizationReviewSpec{
				ResourceAttributes: attrs,
				User:               usr.GetName(),
				Groups:             usr.GetGroups(),
				Extra:              usr.GetExtra(),
			},
		}

		out, crdErr := fallbackCS.ProjectcalicoV3().AuthorizationReviews().Create(ctx, review, metav1.CreateOptions{})
		if crdErr != nil {
			return nil, fmt.Errorf("failed to create AuthorizationReview on cluster %q: %w", cluster, crdErr)
		}
		return out.Status.AuthorizedResourceVerbs, nil
	}

	return nil, fmt.Errorf("failed to calculate permissions on cluster %q: %w", cluster, err)
}

// ReviewForLogs is a convenience that reviews the standard set of log-related resources
// (pods, nodes, events, hostendpoints, networksets, etc.).
func (r *reviewer) ReviewForLogs(
	ctx context.Context,
	usr user.Info,
	cluster string,
) ([]v3.AuthorizedResourceVerbs, error) {
	return r.Review(ctx, usr, cluster, authReviewAttrListEndpoints)
}

// aggregateContains checks whether err (or any error within a utilerrors.Aggregate)
// matches the given predicate. This is needed because utilerrors.Aggregate supports
// errors.Is() but not errors.As(), so kerrors.IsForbidden() and similar helpers that
// rely on errors.As() internally won't match through an aggregate.
func aggregateContains(err error, predicate func(error) bool) bool {
	if predicate(err) {
		return true
	}
	var agg utilerrors.Aggregate
	if errors.As(err, &agg) {
		for _, e := range agg.Errors() {
			if aggregateContains(e, predicate) {
				return true
			}
		}
	}
	return false
}
