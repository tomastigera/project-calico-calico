package checker

import (
	"testing"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/statscache"
)

var _ CheckProvider = (*okProvider)(nil)
var _ CheckProvider = (*denyProvider)(nil)

type okProvider struct{}

func (p *okProvider) Name() string { return "ok-provider" }
func (p *okProvider) EnabledForRequest(*policystore.PolicyStore, *authz.CheckRequest) bool {
	return true
}
func (p *okProvider) Check(*policystore.PolicyStore, *authz.CheckRequest) (*authz.CheckResponse, error) {
	return &authz.CheckResponse{Status: &status.Status{Code: OK}}, nil
}

type denyProvider struct{}

func (p *denyProvider) Name() string { return "deny-provider" }
func (p *denyProvider) EnabledForRequest(*policystore.PolicyStore, *authz.CheckRequest) bool {
	return true
}
func (p *denyProvider) Check(*policystore.PolicyStore, *authz.CheckRequest) (*authz.CheckResponse, error) {
	return &authz.CheckResponse{Status: &status.Status{Code: PERMISSION_DENIED}}, nil
}

type disabledProvider struct{}

func (p *disabledProvider) Name() string { return "disabled-provider" }
func (p *disabledProvider) EnabledForRequest(*policystore.PolicyStore, *authz.CheckRequest) bool {
	return false
}
func (p *disabledProvider) Check(*policystore.PolicyStore, *authz.CheckRequest) (*authz.CheckResponse, error) {
	return &authz.CheckResponse{Status: &status.Status{Code: INVALID_ARGUMENT}}, nil
}

func TestServerCheckerProvidersNone(t *testing.T) {
	ctx := t.Context()

	psm := policystore.NewPolicyStoreManager()
	dpStats := statscache.New()
	uut := NewServer(ctx, psm, dpStats) // no providers.. provided

	req := &authz.CheckRequest{}
	resp, err := uut.Check(ctx, req)
	if err != nil {
		t.Error("error must be nil")
	}

	if resp.Status.Code != UNKNOWN {
		t.Error("with no checkproviders it must be unknown")
	}
}

func TestServerCheckerProvidersAllOK(t *testing.T) {
	ctx := t.Context()

	psm := policystore.NewPolicyStoreManager()
	dpStats := statscache.New()
	uut := NewServer(ctx, psm, dpStats,
		WithRegisteredCheckProvider(new(okProvider)),
		WithRegisteredCheckProvider(new(okProvider)),
	)

	req := &authz.CheckRequest{}
	resp, err := uut.Check(ctx, req)
	if err != nil {
		t.Error("error must be nil")
	}

	if resp.Status.Code != OK {
		t.Error("with all checkproviders returning ok, it must be ok")
	}
}

func TestServerCheckerProvidersAllDeny(t *testing.T) {
	ctx := t.Context()

	psm := policystore.NewPolicyStoreManager()
	dpStats := statscache.New()
	uut := NewServer(ctx, psm, dpStats,
		WithRegisteredCheckProvider(new(denyProvider)),
		WithRegisteredCheckProvider(new(denyProvider)),
	)

	req := &authz.CheckRequest{}
	resp, err := uut.Check(ctx, req)
	if err != nil {
		t.Error("error must be nil")
	}

	if resp.Status.Code == OK {
		t.Error("all checkproviders returns deny so it must not be ok")
	}
}

func TestServerCheckerProvidersAllowWithDisabled(t *testing.T) {
	ctx := t.Context()

	// It should be ok for one disabled and one ok, no matter the order
	for _, providers := range [][]CheckProvider{
		{&disabledProvider{}, &okProvider{}},
		{&okProvider{}, &disabledProvider{}},
	} {
		psm := policystore.NewPolicyStoreManager()
		dpStats := statscache.New()
		uut := NewServer(ctx, psm, dpStats,
			WithRegisteredCheckProvider(providers[0]),
			WithRegisteredCheckProvider(providers[1]),
		)

		req := &authz.CheckRequest{}
		resp, err := uut.Check(ctx, req)
		if err != nil {
			t.Error("error must be nil")
		}

		if resp.Status.Code != OK {
			t.Error("one checkproviders returns ok so it must be ok")
		}
	}
}

func TestServerCheckerProvidersDenyWithDisabled(t *testing.T) {
	ctx := t.Context()

	// It should be ok for one disabled and one ok, no matter the order
	for _, providers := range [][]CheckProvider{
		{&disabledProvider{}, &denyProvider{}},
		{&denyProvider{}, &disabledProvider{}},
	} {
		psm := policystore.NewPolicyStoreManager()
		dpStats := statscache.New()
		uut := NewServer(ctx, psm, dpStats,
			WithRegisteredCheckProvider(providers[0]),
			WithRegisteredCheckProvider(providers[1]),
		)

		req := &authz.CheckRequest{}
		resp, err := uut.Check(ctx, req)
		if err != nil {
			t.Error("error must be nil")
		}

		if resp.Status.Code == OK {
			t.Error("one checkproviders returns deny so it must not be ok")
		}
	}
}

func TestServerCheckerProvidersFiftyFifty(t *testing.T) {
	ctx := t.Context()

	psm := policystore.NewPolicyStoreManager()
	dpStats := statscache.New()
	uut := NewServer(ctx, psm, dpStats,
		WithRegisteredCheckProvider(new(okProvider)),
		WithRegisteredCheckProvider(new(denyProvider)),
	)

	req := &authz.CheckRequest{}
	resp, err := uut.Check(ctx, req)
	if err != nil {
		t.Error("error must be nil")
	}

	if resp.Status.Code == OK {
		t.Error("one of checkproviders is a deny so it must be not ok")
	}
}
