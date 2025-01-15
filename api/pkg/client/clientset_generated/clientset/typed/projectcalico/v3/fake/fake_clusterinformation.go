// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeClusterInformations implements ClusterInformationInterface
type FakeClusterInformations struct {
	Fake *FakeProjectcalicoV3
}

var clusterinformationsResource = v3.SchemeGroupVersion.WithResource("clusterinformations")

var clusterinformationsKind = v3.SchemeGroupVersion.WithKind("ClusterInformation")

// Get takes name of the clusterInformation, and returns the corresponding clusterInformation object, and an error if there is any.
func (c *FakeClusterInformations) Get(ctx context.Context, name string, options v1.GetOptions) (result *v3.ClusterInformation, err error) {
	emptyResult := &v3.ClusterInformation{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(clusterinformationsResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.ClusterInformation), err
}

// List takes label and field selectors, and returns the list of ClusterInformations that match those selectors.
func (c *FakeClusterInformations) List(ctx context.Context, opts v1.ListOptions) (result *v3.ClusterInformationList, err error) {
	emptyResult := &v3.ClusterInformationList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(clusterinformationsResource, clusterinformationsKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v3.ClusterInformationList{ListMeta: obj.(*v3.ClusterInformationList).ListMeta}
	for _, item := range obj.(*v3.ClusterInformationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested clusterInformations.
func (c *FakeClusterInformations) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(clusterinformationsResource, opts))
}

// Create takes the representation of a clusterInformation and creates it.  Returns the server's representation of the clusterInformation, and an error, if there is any.
func (c *FakeClusterInformations) Create(ctx context.Context, clusterInformation *v3.ClusterInformation, opts v1.CreateOptions) (result *v3.ClusterInformation, err error) {
	emptyResult := &v3.ClusterInformation{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(clusterinformationsResource, clusterInformation, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.ClusterInformation), err
}

// Update takes the representation of a clusterInformation and updates it. Returns the server's representation of the clusterInformation, and an error, if there is any.
func (c *FakeClusterInformations) Update(ctx context.Context, clusterInformation *v3.ClusterInformation, opts v1.UpdateOptions) (result *v3.ClusterInformation, err error) {
	emptyResult := &v3.ClusterInformation{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(clusterinformationsResource, clusterInformation, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.ClusterInformation), err
}

// Delete takes name of the clusterInformation and deletes it. Returns an error if one occurs.
func (c *FakeClusterInformations) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(clusterinformationsResource, name, opts), &v3.ClusterInformation{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeClusterInformations) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionActionWithOptions(clusterinformationsResource, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v3.ClusterInformationList{})
	return err
}

// Patch applies the patch and returns the patched clusterInformation.
func (c *FakeClusterInformations) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v3.ClusterInformation, err error) {
	emptyResult := &v3.ClusterInformation{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(clusterinformationsResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.ClusterInformation), err
}
