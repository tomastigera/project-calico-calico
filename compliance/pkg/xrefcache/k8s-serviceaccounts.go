// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package xrefcache

import (
	"github.com/sirupsen/logrus"
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
	KindsServiceAccount = []metav1.TypeMeta{
		resources.TypeK8sServiceAccounts,
	}
)

// VersionedServiceAccountResource is an extension of the VersionedResource interface, specific to handling
// ServiceAccounts.
type VersionedServiceAccountResource interface {
	VersionedResource
	GetCalicoV1Profile() *model.Profile
	GetCalicoV3Profile() *apiv3.Profile
}

// CacheEntryServiceAccount implements the CacheEntry interface, and is what we stored in the ServiceAccounts cache.
type CacheEntryServiceAccount struct {
	// The versioned policy resource.
	VersionedServiceAccountResource

	// --- Internal data ---
	cacheEntryCommon
}

// getVersionedResource implements the CacheEntry interface.
func (c *CacheEntryServiceAccount) getVersionedResource() VersionedResource {
	return c.VersionedServiceAccountResource
}

// setVersionedResource implements the CacheEntry interface.
func (c *CacheEntryServiceAccount) setVersionedResource(r VersionedResource) {
	c.VersionedServiceAccountResource = r.(VersionedServiceAccountResource)
}

// versionedK8sServiceAccount implements the VersionedServiceAccountResource interface.
type versionedK8sServiceAccount struct {
	*corev1.ServiceAccount
	v3 *apiv3.Profile
	v1 *model.Profile
}

// GetPrimary implements the VersionedNetworkSetResource interface.
func (v *versionedK8sServiceAccount) GetPrimary() resources.Resource {
	return v.ServiceAccount
}

// GetCalicoV3 implements the VersionedServiceAccountResource interface.
func (v *versionedK8sServiceAccount) GetCalicoV3() resources.Resource {
	return v.v3
}

// getCalicoV1 implements the VersionedServiceAccountResource interface.
func (v *versionedK8sServiceAccount) GetCalicoV1() any {
	return v.v1
}

// GetCalicoV1Profile implements the VersionedServiceAccountResource interface.
func (v *versionedK8sServiceAccount) GetCalicoV1Profile() *model.Profile {
	return v.v1
}

// GetCalicoV3Profile implements the VersionedServiceAccountResource interface.
func (v *versionedK8sServiceAccount) GetCalicoV3Profile() *apiv3.Profile {
	return v.v3
}

// newServiceAccountHandler creates a resourceHandler used to handle the ServiceAccounts cache.
func newServiceAccountHandler() resourceHandler {
	return &serviceAccountHandler{
		converter: conversion.NewConverter(),
	}
}

// serviceAccountHandler implements the resourceHandler.
type serviceAccountHandler struct {
	CacheAccessor
	converter conversion.Converter
}

// register implements the resourceHandler.
func (c *serviceAccountHandler) register(cache CacheAccessor) {
	c.CacheAccessor = cache
}

// kinds implements the resourceHandler.
func (c *serviceAccountHandler) kinds() []metav1.TypeMeta {
	return KindsServiceAccount
}

// newCacheEntry implements the resourceHandler.
func (c *serviceAccountHandler) newCacheEntry() CacheEntry {
	return &CacheEntryServiceAccount{}
}

// convertToVersioned implements the resourceHandler.
func (c *serviceAccountHandler) convertToVersioned(res resources.Resource) (VersionedResource, error) {
	in := res.(*corev1.ServiceAccount)

	kvp, err := c.converter.ServiceAccountToProfile(in)
	if err != nil {
		return nil, err
	}

	v3 := kvp.Value.(*apiv3.Profile)
	v1, err := updateprocessors.ConvertProfileV3ToV1Value(v3)
	if err != nil {
		return nil, err
	}

	return &versionedK8sServiceAccount{
		ServiceAccount: in,
		v3:             v3,
		v1:             v1,
	}, nil
}

// resourceAdded implements the resourceHandler.
func (c *serviceAccountHandler) resourceAdded(id apiv3.ResourceID, entry CacheEntry) {
	c.resourceUpdated(id, entry, nil)
}

// resourceUpdated implements the resourceHandler.
func (c *serviceAccountHandler) resourceUpdated(id apiv3.ResourceID, entry CacheEntry, prev VersionedResource) {
	// Kubernetes service accounts are configured as Calico profiles. Use the V3 version of the name and the V1 version
	// of the labels since they will have been modified to match the selector modifications in the pod.
	x := entry.(*CacheEntryServiceAccount)
	logrus.Debugf("Configure profile %s with labels %v", x.GetCalicoV3Profile().Name, x.GetCalicoV1Profile().Labels)
	c.EndpointLabelSelector().UpdateParentLabels(x.GetCalicoV3Profile().Name, x.GetCalicoV1Profile().Labels)
}

// resourceDeleted implements the resourceHandler.
func (c *serviceAccountHandler) resourceDeleted(id apiv3.ResourceID, entry CacheEntry) {
	// Kubernetes service accounts are configured as Calico profiles. Use the V3 version of the name since it will have
	// been modified to match the selector modifications in the pod.
	x := entry.(*CacheEntryServiceAccount)
	c.EndpointLabelSelector().DeleteParentLabels(x.GetCalicoV3Profile().Name)
}

// recalculate implements the resourceHandler interface.
func (c *serviceAccountHandler) recalculate(id apiv3.ResourceID, entry CacheEntry) syncer.UpdateType {
	// We don't store any additional ServiceAccount state at the moment.
	return 0
}
