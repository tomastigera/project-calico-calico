// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clientv3

import (
	"context"
	"fmt"
	"maps"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// WorkloadEndpointInterface has methods to work with WorkloadEndpoint resources.
type WorkloadEndpointInterface interface {
	Create(ctx context.Context, res *libapiv3.WorkloadEndpoint, opts options.SetOptions) (*libapiv3.WorkloadEndpoint, error)
	CreateNonDefault(ctx context.Context, res *libapiv3.WorkloadEndpoint, opts options.SetOptions) (*libapiv3.WorkloadEndpoint, error)
	Update(ctx context.Context, res *libapiv3.WorkloadEndpoint, opts options.SetOptions) (*libapiv3.WorkloadEndpoint, error)
	UpdateNonDefault(ctx context.Context, res *libapiv3.WorkloadEndpoint, opts options.SetOptions) (*libapiv3.WorkloadEndpoint, error)
	Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*libapiv3.WorkloadEndpoint, error)
	Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*libapiv3.WorkloadEndpoint, error)
	List(ctx context.Context, opts options.ListOptions) (*libapiv3.WorkloadEndpointList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// createNonDefaultInterface is used to check if a the K8sResourceClient implements the CreateNonDefault function
type createNonDefaultInterface interface {
	CreateNonDefault(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error)
}

// updateNonDefaultInterface is used to check if a the K8sResourceClient implements the UpdateNonDefault function
type updateNonDefaultInterface interface {
	UpdateNonDefault(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error)
}

// workloadEndpoints implements WorkloadEndpointInterface
type workloadEndpoints struct {
	client client
}

// create takes the representation of a WorkloadEndpoint and creates it using the given create function.  Returns the stored
// representation of the WorkloadEndpoint, and an error, if there is any.
func (r workloadEndpoints) create(ctx context.Context, res *libapiv3.WorkloadEndpoint, opts options.SetOptions, createFunc func(ctx context.Context, object *model.KVPair) (*model.KVPair, error)) (*libapiv3.WorkloadEndpoint, error) {
	if res != nil {
		// Since we're about to default some fields, take a (shallow) copy of the input data
		// before we do so.
		resCopy := *res
		res = &resCopy
	}
	if err := r.assignOrValidateName(res); err != nil {
		return nil, err
	} else if err := validator.Validate(res); err != nil {
		return nil, err
	}
	r.updateLabelsForStorage(res)
	out, err := createResource(ctx, opts, libapiv3.KindWorkloadEndpoint, res, createFunc)
	if out != nil {
		return out.(*libapiv3.WorkloadEndpoint), err
	}
	return nil, err
}

// CreateNonDefault is a function that should be used if the WorkloadEndpoint being created is not the default one. In KDD
// mode, the default WorkloadEndpoints are "created" different from the additional ones. If the backend client is not a
// k8s.KubeClient, or the WorkloadEndpoint K8sResourceClient does not implement the createNonDefaultInterface then this
// function simple calls Create.
func (r workloadEndpoints) CreateNonDefault(ctx context.Context, res *libapiv3.WorkloadEndpoint, opts options.SetOptions) (*libapiv3.WorkloadEndpoint, error) {
	var createFunc func(ctx context.Context, object *model.KVPair) (*model.KVPair, error)

	// Note on this type switching: We could have added CreateNonDefault to the api.Client interface, but that would mean
	// every implementation of it would have to have this CreateNonDefault function, and it would be a NOOP for every implementation
	// but the WorkloadEndpoint's clients implementation. This type switching isn't the nicest piece of code, but at the
	// time of writing this it seems like the best alternative.
	switch be := r.client.backend.(type) {
	case *k8s.KubeClient:
		rClient := be.GetResourceClientFromResourceKind(libapiv3.KindWorkloadEndpoint)
		if rClient == nil {
			log.Debug("Attempt to 'Create' using kubernetes backend is not supported.")
			return nil, cerrors.ErrorOperationNotSupported{
				Identifier: resourceToKVPair(opts, libapiv3.KindWorkloadEndpoint, res),
				Operation:  "Create",
			}
		}
		wepClient, ok := rClient.(createNonDefaultInterface)
		if ok {
			createFunc = wepClient.CreateNonDefault
		} else {
			// we're purposefully not going to consider this an error if CreateNonDefaultInterface is not implemented
			createFunc = r.client.backend.Create
		}
	default:
		createFunc = r.client.backend.Create
	}

	return r.create(ctx, res, opts, createFunc)
}

// Create takes the representation of a WorkloadEndpoint and creates it.  Returns the stored
// representation of the WorkloadEndpoint, and an error, if there is any.
func (r workloadEndpoints) Create(ctx context.Context, res *libapiv3.WorkloadEndpoint, opts options.SetOptions) (*libapiv3.WorkloadEndpoint, error) {
	return r.create(ctx, res, opts, r.client.backend.Create)
}

// update takes the representation of a WorkloadEndpoint and updates it using the given update function. Returns the stored
// representation of the WorkloadEndpoint, and an error, if there is any.
func (r workloadEndpoints) update(ctx context.Context, res *libapiv3.WorkloadEndpoint, opts options.SetOptions, updateFunc func(ctx context.Context, object *model.KVPair) (*model.KVPair, error)) (*libapiv3.WorkloadEndpoint, error) {
	if res != nil {
		// Since we're about to default some fields, take a (shallow) copy of the input data
		// before we do so.
		resCopy := *res
		res = &resCopy
	}
	if err := r.assignOrValidateName(res); err != nil {
		return nil, err
	} else if err := validator.Validate(res); err != nil {
		return nil, err
	}
	r.updateLabelsForStorage(res)
	out, err := updateResource(ctx, opts, libapiv3.KindWorkloadEndpoint, res, updateFunc)
	if out != nil {
		return out.(*libapiv3.WorkloadEndpoint), err
	}
	return nil, err
}

// UpdateNonDefault is a function that should be used if the WorkloadEndpoint being updated is not the default one. In KDD
// mode, the default WorkloadEndpoints are "updated" different from the additional ones. If the backend client is not a
// k8s.KubeClient, or the WorkloadEndpoint K8sResourceClient does not implement the updateNonDefaultInterface then this
// function simple calls Update.
func (r workloadEndpoints) UpdateNonDefault(ctx context.Context, res *libapiv3.WorkloadEndpoint, opts options.SetOptions) (*libapiv3.WorkloadEndpoint, error) {
	var updateFunc func(ctx context.Context, object *model.KVPair) (*model.KVPair, error)

	// Note on this type switching: We could have added UpdateNonDefault to the api.Client interface, but that would mean
	// every implementation of it would have to have this UpdateNonDefault function, and it would be a NOOP for every implementation
	// but the WorkloadEndpoint's clients implementation. This type switching isn't the nicest piece of code, but at the
	// time of writing this it seems like the best alternative.
	switch be := r.client.backend.(type) {
	case *k8s.KubeClient:
		rClient := be.GetResourceClientFromResourceKind(libapiv3.KindWorkloadEndpoint)
		if rClient == nil {
			log.Debug("Attempt to 'Update' using kubernetes backend is not supported.")
			return nil, cerrors.ErrorOperationNotSupported{
				Identifier: resourceToKVPair(opts, libapiv3.KindWorkloadEndpoint, res),
				Operation:  "Update",
			}
		}

		wepClient, ok := rClient.(updateNonDefaultInterface)
		if ok {
			updateFunc = wepClient.UpdateNonDefault
		} else {
			// we're purposefully not going to consider this an error if UpdateNonDefaultInterface is not implemented
			updateFunc = r.client.backend.Update
		}
	default:
		updateFunc = r.client.backend.Update
	}

	return r.update(ctx, res, opts, updateFunc)
}

// Update takes the representation of a WorkloadEndpoint and updates it. Returns the stored
// representation of the WorkloadEndpoint, and an error, if there is any.
func (r workloadEndpoints) Update(ctx context.Context, res *libapiv3.WorkloadEndpoint, opts options.SetOptions) (*libapiv3.WorkloadEndpoint, error) {
	return r.update(ctx, res, opts, r.client.backend.Update)
}

// Delete takes name of the WorkloadEndpoint and deletes it. Returns an error if one occurs.
func (r workloadEndpoints) Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*libapiv3.WorkloadEndpoint, error) {
	out, err := r.client.resources.Delete(ctx, opts, libapiv3.KindWorkloadEndpoint, namespace, name)
	if out != nil {
		return out.(*libapiv3.WorkloadEndpoint), err
	}
	return nil, err
}

// Get takes name of the WorkloadEndpoint, and returns the corresponding WorkloadEndpoint object,
// and an error if there is any.
func (r workloadEndpoints) Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*libapiv3.WorkloadEndpoint, error) {
	out, err := r.client.resources.Get(ctx, opts, libapiv3.KindWorkloadEndpoint, namespace, name)
	if out != nil {
		return out.(*libapiv3.WorkloadEndpoint), err
	}
	return nil, err
}

// List returns the list of WorkloadEndpoint objects that match the supplied options.
func (r workloadEndpoints) List(ctx context.Context, opts options.ListOptions) (*libapiv3.WorkloadEndpointList, error) {
	res := &libapiv3.WorkloadEndpointList{}
	if err := r.client.resources.List(ctx, opts, libapiv3.KindWorkloadEndpoint, libapiv3.KindWorkloadEndpointList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the NetworkPolicies that match the
// supplied options.
func (r workloadEndpoints) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, libapiv3.KindWorkloadEndpoint, nil)
}

// assignOrValidateName either assigns the name calculated from the Spec fields, or validates
// the name against the spec fields.
func (r workloadEndpoints) assignOrValidateName(res *libapiv3.WorkloadEndpoint) error {
	// Validate the workload endpoint indices and the name match.
	wepids := names.IdentifiersForV3WorkloadEndpoint(res)
	expectedName, err := wepids.CalculateWorkloadEndpointName(false)
	if err != nil {
		return err
	}
	if len(res.Name) == 0 {
		// If a name was not specified then we will calculate it on behalf of the caller.
		res.Name = expectedName
		return nil
	}
	if res.Name != expectedName {
		return errors.ErrorValidation{
			ErroredFields: []errors.ErroredField{{
				Name:   "Name",
				Value:  res.Name,
				Reason: fmt.Sprintf("the WorkloadEndpoint name does not match the primary identifiers assigned in the Spec: expected name %s", expectedName),
			}},
		}
	}
	return nil
}

// updateLabelsForStorage updates the set of labels that we persist.  It adds/overrides
// the Namespace and Orchestrator labels which must be set to the correct values and are
// not user configurable.
func (r workloadEndpoints) updateLabelsForStorage(res *libapiv3.WorkloadEndpoint) {
	labelsCopy := make(map[string]string, len(res.GetLabels())+2)
	maps.Copy(labelsCopy, res.GetLabels())
	labelsCopy[apiv3.LabelNamespace] = res.Namespace
	labelsCopy[apiv3.LabelOrchestrator] = res.Spec.Orchestrator
	res.SetLabels(labelsCopy)
}
