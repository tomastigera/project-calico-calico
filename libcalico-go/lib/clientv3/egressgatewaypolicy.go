// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package clientv3

import (
	"context"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// EgressGatewayPolicyInterface has methods to work with EgressGatewayPolicy resources.
type EgressGatewayPolicyInterface interface {
	Create(ctx context.Context, res *apiv3.EgressGatewayPolicy, opts options.SetOptions) (*apiv3.EgressGatewayPolicy, error)
	Update(ctx context.Context, res *apiv3.EgressGatewayPolicy, opts options.SetOptions) (*apiv3.EgressGatewayPolicy, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.EgressGatewayPolicy, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.EgressGatewayPolicy, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv3.EgressGatewayPolicyList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// EgressGatewayPolicy implements EgressGatewayPolicyInterface
type EgressGatewayPolicy struct {
	client client
}

func fillDefaults(res *apiv3.EgressGatewayPolicy) {
	preferNone := apiv3.GatewayPreferenceNone
	for i := range res.Spec.Rules {
		if res.Spec.Rules[i].GatewayPreference == nil {
			res.Spec.Rules[i].GatewayPreference = &preferNone
		}
	}
}

// Create takes the representation of a EgressGatewayPolicy and creates it. Returns the stored
// representation of the EgressGatewayPolicy, and an error, if there is any.
func (e EgressGatewayPolicy) Create(ctx context.Context, res *apiv3.EgressGatewayPolicy, opts options.SetOptions) (*apiv3.EgressGatewayPolicy, error) {
	fillDefaults(res)
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := e.client.resources.Create(ctx, opts, apiv3.KindEgressGatewayPolicy, res)
	if out != nil {
		return out.(*apiv3.EgressGatewayPolicy), err
	}
	return nil, err
}

// Update takes the representation of a EgressGatewayPolicy and updates it. Returns the stored
// representation of the EgressGatewayPolicy, and an error, if there is any.
func (e EgressGatewayPolicy) Update(ctx context.Context, res *apiv3.EgressGatewayPolicy, opts options.SetOptions) (*apiv3.EgressGatewayPolicy, error) {
	fillDefaults(res)
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := e.client.resources.Update(ctx, opts, apiv3.KindEgressGatewayPolicy, res)
	if out != nil {
		return out.(*apiv3.EgressGatewayPolicy), err
	}
	return nil, err
}

// Delete takes name of the EgressGatewayPolicy and deletes it. Returns an error if one occurs.
func (e EgressGatewayPolicy) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.EgressGatewayPolicy, error) {
	out, err := e.client.resources.Delete(ctx, opts, apiv3.KindEgressGatewayPolicy, noNamespace, name)
	if out != nil {
		return out.(*apiv3.EgressGatewayPolicy), err
	}
	return nil, err
}

// Get takes name of the EgressGatewayPolicy, and returns the corresponding EgressGatewayPolicy object,
// and an error if there is any.
func (e EgressGatewayPolicy) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.EgressGatewayPolicy, error) {
	out, err := e.client.resources.Get(ctx, opts, apiv3.KindEgressGatewayPolicy, noNamespace, name)
	if out != nil {
		return out.(*apiv3.EgressGatewayPolicy), err
	}
	return nil, err
}

// List returns the list of EgressGatewayPolicy objects that match the supplied options.
func (e EgressGatewayPolicy) List(ctx context.Context, opts options.ListOptions) (*apiv3.EgressGatewayPolicyList, error) {
	res := &apiv3.EgressGatewayPolicyList{}
	if err := e.client.resources.List(ctx, opts, apiv3.KindEgressGatewayPolicy, apiv3.KindEgressGatewayPolicyList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the EgressGatewayPolicy that match the
// supplied options.
func (e EgressGatewayPolicy) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return e.client.resources.Watch(ctx, opts, apiv3.KindEgressGatewayPolicy, nil)
}
