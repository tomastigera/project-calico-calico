// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package xrefcache

import (
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

var (
	KindsNamespace = []metav1.TypeMeta{
		resources.TypeK8sNamespaces,
	}
)

// VersionedNamespaceResource is an extension of the VersionedResource interface, specific to handling Namespaces.
type VersionedNamespaceResource interface {
	VersionedResource
	GetCalicoV1Profile() *model.Profile
	GetCalicoV3Profile() *apiv3.Profile
}

// CacheEntryNamespace implements the CacheEntry interface, and is what we stored in the Namespaces cache.
type CacheEntryNamespace struct {
	// The versioned policy resource.
	VersionedNamespaceResource

	// --- Internal data ---
	cacheEntryCommon
}

// GetCalicoVersionedResource implements the CacheEntry interface.
func (c *CacheEntryNamespace) getVersionedResource() VersionedResource {
	return c.VersionedNamespaceResource
}

// setVersionedResource implements the CacheEntry interface.
func (c *CacheEntryNamespace) setVersionedResource(r VersionedResource) {
	c.VersionedNamespaceResource = r.(VersionedNamespaceResource)
}

// versionedK8sNamespace implements the VersionedNamespaceResource interface.
type versionedK8sNamespace struct {
	*corev1.Namespace
	v3 *apiv3.Profile
	v1 *model.Profile
}

// GetPrimary implements the VersionedNamespaceResource interface.
func (v *versionedK8sNamespace) GetPrimary() resources.Resource {
	return v.Namespace
}

// GetCalicoV3 implements the VersionedNamespaceResource interface.
func (v *versionedK8sNamespace) GetCalicoV3() resources.Resource {
	return v.v3
}

// getCalicoV1 implements the VersionedNamespaceResource interface.
func (v *versionedK8sNamespace) GetCalicoV1() any {
	return v.v1
}

// GetCalicoV1Profile implements the VersionedNamespaceResource interface.
func (v *versionedK8sNamespace) GetCalicoV1Profile() *model.Profile {
	return v.v1
}

// GetCalicoV3Profile implements the VersionedNamespaceResource interface.
func (v *versionedK8sNamespace) GetCalicoV3Profile() *apiv3.Profile {
	return v.v3
}

// newNamespacesHandler creates a resourceHandler used to handle the Namespaces cache.
func newNamespacesHandler() resourceHandler {
	return &namespaceHandler{
		converter: conversion.NewConverter(),
	}
}

// namespaceHandler implements the resourceHandler.
type namespaceHandler struct {
	CacheAccessor
	converter conversion.Converter
}

// kinds implements the resourceHandler interface.
func (c *namespaceHandler) kinds() []metav1.TypeMeta {
	return KindsNamespace
}

// register implements the resourceHandler interface.
func (c *namespaceHandler) register(cache CacheAccessor) {
	c.CacheAccessor = cache
}

// newCacheEntry implements the resourceHandler interface.
func (c *namespaceHandler) newCacheEntry() CacheEntry {
	return &CacheEntryNamespace{}
}

// convertToVersioned implements the resourceHandler interface.
func (c *namespaceHandler) convertToVersioned(res resources.Resource) (VersionedResource, error) {
	in := res.(*corev1.Namespace)

	kvp, err := c.converter.NamespaceToProfile(in)
	if err != nil {
		return nil, err
	}

	v3 := kvp.Value.(*apiv3.Profile)
	v1, err := updateprocessors.ConvertProfileV3ToV1Value(v3)
	if err != nil {
		return nil, err
	}

	return &versionedK8sNamespace{
		Namespace: in,
		v3:        v3,
		v1:        v1,
	}, nil
}

// resourceAdded implements the resourceHandler interface.
func (c *namespaceHandler) resourceAdded(id apiv3.ResourceID, entry CacheEntry) {
	c.resourceUpdated(id, entry, nil)
}

// resourceUpdated implements the resourceHandler interface.
func (c *namespaceHandler) resourceUpdated(id apiv3.ResourceID, entry CacheEntry, prev VersionedResource) {
	// Kubernetes namespaces are configured as Calico profiles. Use the V3 version of the name and the V1 version of the
	// labels since they will have been modified to match the selector modifications in the pod.
	x := entry.(*CacheEntryNamespace)
	c.EndpointLabelSelector().UpdateParentLabels(x.GetCalicoV3Profile().Name, x.GetCalicoV1Profile().Labels)
}

// resourceDeleted implements the resourceHandler interface.
func (c *namespaceHandler) resourceDeleted(id apiv3.ResourceID, entry CacheEntry) {
	// Kubernetes namespaces are configured as Calico profiles. Use the V3 version of the name since it will have been
	// modified to match the selector modifications in the pod.
	x := entry.(*CacheEntryNamespace)
	c.EndpointLabelSelector().DeleteParentLabels(x.GetCalicoV3Profile().Name)
}

// recalculate implements the resourceHandler interface.
func (c *namespaceHandler) recalculate(id apiv3.ResourceID, res CacheEntry) syncer.UpdateType {
	// We don't store any additional Namespace state at the moment.
	return 0
}
