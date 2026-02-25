// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package federatedservices

import (
	"context"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/labelindex"
	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// Federated service controller tests. Note that this is part of the main federatedservices package rather than
// a test package - these tests examine the underlying structures to ensure we are populating and tidying up
// the various interlinkings between services - this would be cumbersome to do as a black-box test.

var (
	fedSvc = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "federated",
			Namespace: "namespace1",
			Annotations: map[string]string{
				FederationServiceSelectorAnnotation: "run == \"nginx\"",
			},
			Labels: map[string]string{
				"run": "nginx",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:     "port1",
					Protocol: v1.ProtocolUDP,
				},
				{
					Name:     "port2",
					Protocol: v1.ProtocolTCP,
				},
			},
		},
	}

	// Matching service on the local cluster. Endpoint ports fully match.
	svc1 = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-local-service",
			Namespace: "namespace1",
			Labels: map[string]string{
				"run": "nginx",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:     "port3",
					Port:     10000,
					Protocol: v1.ProtocolUDP,
				},
			},
		},
	}
	ep1 = &v1.Endpoints{ //nolint:staticcheck
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-local-service",
			Namespace: "namespace1",
		},
		Subsets: []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "1.0.0.1",
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "1.0.0.2",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "2.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1234,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	}

	// Matching service on cluster remote1. Some ports filtered out, and a subset fully
	// filtered out.
	svc2 = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-remote-service",
			Namespace: "namespace1",
			Labels: map[string]string{
				"run": "nginx",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:     "port1",
					Port:     10000,
					Protocol: v1.ProtocolUDP,
				},
			},
		},
	}
	ep2 = &v1.Endpoints{ //nolint:staticcheck
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-remote-service",
			Namespace: "namespace1",
		},
		Subsets: []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.0.1",
						TargetRef: &v1.ObjectReference{
							Name: "remote-pod",
						},
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.100.100",
						TargetRef: &v1.ObjectReference{
							Name: "remote-pod2",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
					{
						Name:     "port2",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
					{
						Name:     "port3",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.0.2",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1090,
						Protocol: v1.ProtocolTCP,
					},
					{
						Name:     "port3",
						Port:     3333,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		},
	}

	// Non-matching service (wrong namespace).
	svc3 = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-non-matching-remote-service",
			Namespace: "namespace2",
			Labels: map[string]string{
				"run": "nginx",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{},
		},
	}
	ep3 = &v1.Endpoints{ //nolint:staticcheck
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-non-matching-remote-service",
			Namespace: "namespace2",
		},
		Subsets: []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "4.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		},
	}

	// Non-matching service (no labels).
	svc4 = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-non-matching-remote-service2",
			Namespace: "namespace1",
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{},
		},
	}
	ep4 = &v1.Endpoints{ //nolint:staticcheck
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-non-matching-remote-service2",
			Namespace: "namespace1",
		},
		Subsets: []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "4.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		},
	}

	fedEpExpected = &v1.Endpoints{ //nolint:staticcheck
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "federated",
			Namespace: "namespace1",
			Annotations: map[string]string{
				FederationServiceSelectorAnnotation: "run == \"nginx\"",
			},
		},
		Subsets: []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "1.0.0.1",
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "1.0.0.2",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "2.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1234,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.0.1",
						TargetRef: &v1.ObjectReference{
							Name: "remote1/remote-pod",
						},
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.100.100",
						TargetRef: &v1.ObjectReference{
							Name: "remote1/remote-pod2",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.0.2",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1090,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	}

	fedEpExpectedNoSvc1 = &v1.Endpoints{ //nolint:staticcheck
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "federated",
			Namespace: "namespace1",
			Annotations: map[string]string{
				FederationServiceSelectorAnnotation: "run == \"nginx\"",
			},
		},
		Subsets: []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.0.1",
						TargetRef: &v1.ObjectReference{
							Name: "remote1/remote-pod",
						},
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.100.100",
						TargetRef: &v1.ObjectReference{
							Name: "remote1/remote-pod2",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.0.2",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1090,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	}

	fedEpExpectedNoSvc2 = &v1.Endpoints{ //nolint:staticcheck
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "federated",
			Namespace: "namespace1",
			Annotations: map[string]string{
				FederationServiceSelectorAnnotation: "run == \"nginx\"",
			},
		},
		Subsets: []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "1.0.0.1",
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "1.0.0.2",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port1",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "2.0.0.1",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port2",
						Port:     1234,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	}

	svc1FedEpExpected = &v1.Endpoints{ //nolint:staticcheck
		TypeMeta: metav1.TypeMeta{
			Kind:       "Endpoints",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-local-service",
			Namespace: "namespace1",
			Annotations: map[string]string{
				FederationServiceSelectorAnnotation: "run == \"nginx\"",
			},
		},
		Subsets: []v1.EndpointSubset{ //nolint:staticcheck
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.0.1",
						TargetRef: &v1.ObjectReference{
							Name: "remote1/remote-pod",
						},
					},
				},
				NotReadyAddresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.100.100",
						TargetRef: &v1.ObjectReference{
							Name: "remote1/remote-pod2",
						},
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port3",
						Port:     1234,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
			{
				Addresses: []v1.EndpointAddress{ //nolint:staticcheck
					{
						IP: "3.0.0.2",
					},
				},
				Ports: []v1.EndpointPort{ //nolint:staticcheck
					{
						Name:     "port3",
						Port:     3333,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		},
	}

	sidFed = serviceID{
		name:      "federated",
		namespace: "namespace1",
	}
	svcKeyFed = model.ResourceKey{
		Kind:      model.KindKubernetesService,
		Name:      "federated",
		Namespace: "namespace1",
	}
	sid1 = serviceID{
		name:      "my-local-service",
		namespace: "namespace1",
	}
	svcKey1 = model.ResourceKey{
		Kind:      model.KindKubernetesService,
		Name:      "my-local-service",
		Namespace: "namespace1",
	}
	epKey1 = model.ResourceKey{
		Kind:      apiv3.KindK8sEndpoints,
		Name:      "my-local-service",
		Namespace: "namespace1",
	}
	sid2 = serviceID{
		cluster:   "remote1",
		name:      "my-remote-service",
		namespace: "namespace1",
	}
	svcKey2 = model.RemoteClusterResourceKey{
		ResourceKey: model.ResourceKey{
			Kind:      model.KindKubernetesService,
			Name:      "my-remote-service",
			Namespace: "namespace1",
		},
		Cluster: "remote1",
	}
	epKey2 = model.RemoteClusterResourceKey{
		ResourceKey: model.ResourceKey{
			Kind:      apiv3.KindK8sEndpoints,
			Name:      "my-remote-service",
			Namespace: "namespace1",
		},
		Cluster: "remote1",
	}
	sid3 = serviceID{
		cluster:   "remote2",
		name:      "my-non-matching-remote-service",
		namespace: "namespace2",
	}
	svcKey3 = model.RemoteClusterResourceKey{
		ResourceKey: model.ResourceKey{
			Kind:      model.KindKubernetesService,
			Name:      "my-non-matching-remote-service",
			Namespace: "namespace2",
		},
		Cluster: "remote2",
	}
	epKey3 = model.RemoteClusterResourceKey{
		ResourceKey: model.ResourceKey{
			Kind:      apiv3.KindK8sEndpoints,
			Name:      "my-non-matching-remote-service",
			Namespace: "namespace2",
		},
		Cluster: "remote2",
	}
	sid4 = serviceID{
		cluster:   "remote2",
		name:      "my-non-matching-remote-service2",
		namespace: "namespace1",
	}
	svcKey4 = model.RemoteClusterResourceKey{
		ResourceKey: model.ResourceKey{
			Kind:      model.KindKubernetesService,
			Name:      "my-non-matching-remote-service2",
			Namespace: "namespace1",
		},
		Cluster: "remote2",
	}
	epKey4 = model.RemoteClusterResourceKey{
		ResourceKey: model.ResourceKey{
			Kind:      apiv3.KindK8sEndpoints,
			Name:      "my-non-matching-remote-service2",
			Namespace: "namespace1",
		},
		Cluster: "remote2",
	}

	rccKey = model.RemoteClusterStatusKey{
		Name: "rcc1",
	}
	rccConnecting = &model.RemoteClusterStatus{
		Status: model.RemoteClusterConnecting,
	}
)

var _ = Describe("Federated Endpoints Controller tests", func() {

	var fsc *federatedServicesController
	var eps map[string]any

	BeforeEach(func() {
		eps = make(map[string]any)
		listFunc := func() (map[string]any, error) {
			return eps, nil
		}

		// Create a Cache to store federated Endpoints in.
		cacheArgs := rcache.ResourceCacheArgs{
			ListFunc:    listFunc,
			ObjectType:  reflect.TypeFor[v1.Endpoints](), //nolint:staticcheck
			LogTypeDesc: "FederatedEndpoints",
		}

		// Create a federataed services controller (we won't actually start it, so our input data will be
		// driven from the tests rather than from the APIs). We give the inSync channel a capacity of 1 so that
		// our in-sync update doesn't block (since the reading of this channel requires starting of the controllers
		// various goroutines which we do not want to do for these tests).
		fsc = &federatedServicesController{
			cache:         rcache.NewResourceCache(cacheArgs),
			ctx:           context.Background(),
			inSync:        make(chan struct{}, 1),
			allServices:   make(map[serviceID]*serviceInfo),
			dirtyServices: set.New[serviceID](),
		}
		fsc.serviceLabelHandler = labelindex.NewInheritIndex(fsc.onServiceMatchStarted, fsc.onServiceMatchStopped)
	})

	It("should process syncer events and create the correct endpoints and events", func() {
		By("Sending syncer status updates up to resync-in-progress")
		fsc.OnStatusUpdated(bapi.WaitForDatastore)
		fsc.OnStatusUpdated(bapi.ResyncInProgress)

		// Add federated service, 2 backing services and s non-backing services. Not yet syncd.
		// Expect internal data structures to contain the correct linkages, but the endpoints to not
		// yet have been calculated.
		By("Sending syncer updates for services and endpoints (not yet synced)")
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   svcKey1,
					Value: svc1.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   epKey1,
					Value: ep1.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   svcKey2,
					Value: svc2.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   svcKeyFed,
					Value: fedSvc.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   epKey2,
					Value: ep2.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   svcKey3,
					Value: svc3.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   epKey3,
					Value: ep3.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   svcKey4,
					Value: svc4.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   epKey4,
					Value: ep4.DeepCopy(),
				},
			},
			// Not actually functionally useful, but gets up additional code coverage
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   rccKey,
					Value: rccConnecting,
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVDeleted,
				KVPair: model.KVPair{
					Key: rccKey,
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVDeleted,
				KVPair: model.KVPair{
					Key: model.PolicyKey{Name: "fakepolicy"},
				},
			},
		})

		By("Validating all the services are cached")
		Expect(fsc.allServices).To(HaveLen(5))
		Expect(fsc.allServices).To(HaveKey(sidFed))
		Expect(fsc.allServices).To(HaveKey(sid1))
		Expect(fsc.allServices).To(HaveKey(sid2))
		Expect(fsc.allServices).To(HaveKey(sid3))
		Expect(fsc.allServices).To(HaveKey(sid4))

		By("Validating the federated service is in the dirty set")
		Expect(fsc.dirtyServices.Len()).To(Equal(1))
		Expect(fsc.dirtyServices.Contains(sidFed)).To(BeTrue())

		By("Validating links between the federated and backing services is correct")
		siFed := fsc.allServices[sidFed]
		Expect(siFed.backingServices.Contains(sid1)).To(BeTrue())
		Expect(siFed.backingServices.Contains(sid2)).To(BeTrue())
		Expect(siFed.backingServices.Contains(sid3)).ToNot(BeTrue())
		Expect(siFed.backingServices.Contains(sid4)).ToNot(BeTrue())
		Expect(siFed.backingServices.Len()).To(Equal(2))
		Expect(siFed.federatedServices.Len()).To(Equal(0))

		si1 := fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(1))
		Expect(si1.federatedServices.Contains(sidFed)).To(BeTrue())
		Expect(si1.backingServices.Len()).To(Equal(0))

		si2 := fsc.allServices[sid2]
		Expect(si2.federatedServices.Len()).To(Equal(1))
		Expect(si2.federatedServices.Contains(sidFed)).To(BeTrue())
		Expect(si2.backingServices.Len()).To(Equal(0))

		si3 := fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 := fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking no updates to our reconciliation cache occur until the in-sync status update")
		Expect(fsc.cache.Get("namespace1/federated")).To(BeNil())

		// Sending a syncer update should process all of the dirty services.
		By("Sending syncer status update of in-sync")
		Expect(fsc.inSync).ShouldNot(Receive())
		fsc.OnStatusUpdated(bapi.InSync)

		// The OnStatusUpdated will send an update synchronously on the inSync channel, so it should be ready
		// to receive immediately.
		Expect(fsc.inSync).Should(Receive())

		By("Validating the federated service is no longer in the dirty set")
		Expect(fsc.dirtyServices.Len()).To(Equal(0))

		By("Checking the federated endpoint has been calculated and stored in the reconciliation cache")
		expected := fedEpExpected.DeepCopy()
		fsc.sanitizeEndpoints(expected)
		val, present := fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeTrue())
		Expect(val).To(Equal(*expected))

		// Update the federation selector to only select entries from the local cache and from a made up remote
		// cache. The effect of this is my-remote-service will not be included in the federated endpoints.
		By("Matching on local cluster and remoteCluster(madeupname)")
		fedSvcFilterCluster := fedSvc.DeepCopy()
		fedSvcFilterCluster.Annotations = map[string]string{
			FederationServiceSelectorAnnotation: "run == \"nginx\" && ( !has(" + LabelClusterName + ") || " + LabelClusterName + " == \"madeupname\" )",
		}
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVUpdated,
				KVPair: model.KVPair{
					Key:   svcKeyFed,
					Value: fedSvcFilterCluster,
				},
			},
		})

		By("Validating the dirty services are handled immediately after sync is complete")
		Expect(fsc.dirtyServices.Len()).To(Equal(0))

		By("Validating links between the federated and backing services is correct")
		siFed = fsc.allServices[sidFed]
		Expect(siFed.federatedServices.Len()).To(Equal(0))
		Expect(siFed.backingServices.Len()).To(Equal(1))
		Expect(siFed.backingServices.Contains(sid1)).To(BeTrue())

		si1 = fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(1))
		Expect(si1.federatedServices.Contains(sidFed)).To(BeTrue())
		Expect(si1.backingServices.Len()).To(Equal(0))

		si2 = fsc.allServices[sid2]
		Expect(si2.federatedServices.Len()).To(Equal(0))
		Expect(si2.backingServices.Len()).To(Equal(0))

		si3 = fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 = fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking the reconciliation cache has been updated with the new endpoints resource")
		expected = fedEpExpectedNoSvc2.DeepCopy()
		expected.Annotations = fedSvcFilterCluster.Annotations
		fsc.sanitizeEndpoints(expected)
		val, present = fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeTrue())
		Expect(val).To(Equal(*expected))

		// Modify the federarion selector to encompass both backing services and then delete one of the
		// backing services.
		By("Resetting the federation annotation then deleting service 2")
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVUpdated,
				KVPair: model.KVPair{
					Key:   svcKeyFed,
					Value: fedSvc.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVDeleted,
				KVPair: model.KVPair{
					Key: svcKey2,
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVDeleted,
				KVPair: model.KVPair{
					Key: epKey2,
				},
			},
		})

		By("Validating the dirty services are handled immediately after sync is complete")
		Expect(fsc.dirtyServices.Len()).To(Equal(0))

		By("Validating links between the federated and backing services is correct")
		siFed = fsc.allServices[sidFed]
		Expect(siFed.federatedServices.Len()).To(Equal(0))
		Expect(siFed.backingServices.Len()).To(Equal(1))
		Expect(siFed.backingServices.Contains(sid1)).To(BeTrue())

		si1 = fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(1))
		Expect(si1.federatedServices.Contains(sidFed)).To(BeTrue())
		Expect(si1.backingServices.Len()).To(Equal(0))

		si2 = fsc.allServices[sid2]
		Expect(si2).To(BeNil())

		si3 = fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 = fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking the reconciliation cache has been updated with the new endpoints resource")
		expected = fedEpExpectedNoSvc2.DeepCopy()
		fsc.sanitizeEndpoints(expected)
		val, present = fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeTrue())
		Expect(val).To(Equal(*expected))

		// Deleting the federated service should leave the reconciliation cache empty.
		By("Deleting federated service")
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVDeleted,
				KVPair: model.KVPair{
					Key: svcKeyFed,
				},
			},
		})

		By("Validating links between the federated and backing services is correct")
		siFed = fsc.allServices[sidFed]
		Expect(siFed).To(BeNil())

		si1 = fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(0))
		Expect(si1.backingServices.Len()).To(Equal(0))

		si2 = fsc.allServices[sid2]
		Expect(si2).To(BeNil())

		si3 = fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 = fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking there is no entry in the reconciliation cache")
		_, present = fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeFalse())
	})

	It("should should handle services switching between non-federated and federated", func() {
		By("Sending syncer status updates to indicate data is now sync'd")
		fsc.OnStatusUpdated(bapi.WaitForDatastore)
		fsc.OnStatusUpdated(bapi.ResyncInProgress)
		fsc.OnStatusUpdated(bapi.InSync)
		Expect(fsc.inSync).Should(Receive())

		// Add federated service, 2 backing services and 2 non-backing services.
		By("Sending syncer updates for services and then for endpoints")
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   svcKey1,
					Value: svc1.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   svcKey2,
					Value: svc2.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   svcKeyFed,
					Value: fedSvc.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   svcKey3,
					Value: svc3.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   svcKey4,
					Value: svc4.DeepCopy(),
				},
			},
		})
		// Send endpoints as a separate update, just to cover more code paths.
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   epKey1,
					Value: ep1.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   epKey2,
					Value: ep2.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   epKey3,
					Value: ep3.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   epKey4,
					Value: ep4.DeepCopy(),
				},
			},
		})

		By("Checking the federated endpoint has been calculated and stored in the reconciliation cache")
		expected := fedEpExpected.DeepCopy()
		fsc.sanitizeEndpoints(expected)
		val, present := fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeTrue())
		Expect(val).To(Equal(*expected))

		// Modify my-remote-service so that it also has a federation annotation. Since this is a remote service
		// it will not be federated by this controller. Since it has a federation annotation it will not be included in
		// the federated endpoints.
		By("Reconfigure my-remote-service as a federated service")
		svc2Fed := svc2.DeepCopy()
		svc2Fed.Annotations = map[string]string{
			FederationServiceSelectorAnnotation: "run == \"nginx\"",
		}
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVUpdated,
				KVPair: model.KVPair{
					Key:   svcKey2,
					Value: svc2Fed,
				},
			},
		})

		By("Validating links between the federated and backing services is correct")
		siFed := fsc.allServices[sidFed]
		Expect(siFed.federatedServices.Len()).To(Equal(0))
		Expect(siFed.backingServices.Len()).To(Equal(1))
		Expect(siFed.backingServices.Contains(sid1)).To(BeTrue())

		si1 := fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(1))
		Expect(si1.federatedServices.Contains(sidFed)).To(BeTrue())
		Expect(si1.backingServices.Len()).To(Equal(0))

		si2 := fsc.allServices[sid2]
		Expect(si2.federatedServices.Len()).To(Equal(0))
		Expect(si2.backingServices.Len()).To(Equal(0))

		si3 := fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 := fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking the reconciliation cache has the correct federated settings")
		Expect(fsc.dirtyServices.Len()).To(Equal(0))
		expected = fedEpExpectedNoSvc2.DeepCopy()
		fsc.sanitizeEndpoints(expected)
		val, present = fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeTrue())
		Expect(val).To(Equal(*expected))

		// Modify my-local-service to have both a federation selector and a normal selector. The federation
		// controller will not federate this service.
		By("Reconfigure my-local-service to have a federation annotation and a selector")
		svc1FedWithSel := svc2.DeepCopy()
		svc1FedWithSel.Annotations = map[string]string{
			FederationServiceSelectorAnnotation: "run == \"nginx\"",
		}
		svc1FedWithSel.Spec.Selector = map[string]string{
			"thing": "thingvalue",
		}
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVUpdated,
				KVPair: model.KVPair{
					Key:   svcKey1,
					Value: svc1FedWithSel,
				},
			},
		})

		By("Validating links between the federated and backing services is correct")
		siFed = fsc.allServices[sidFed]
		Expect(siFed.federatedServices.Len()).To(Equal(0))
		Expect(siFed.backingServices.Len()).To(Equal(0))

		si1 = fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(0))
		Expect(si1.backingServices.Len()).To(Equal(0))

		si2 = fsc.allServices[sid2]
		Expect(si2.federatedServices.Len()).To(Equal(0))
		Expect(si2.backingServices.Len()).To(Equal(0))

		si3 = fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 = fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking the reconciliation cache has federated endpoints with no subsets and there is no entry for my-local-service")
		Expect(fsc.dirtyServices.Len()).To(Equal(0))
		val, present = fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeTrue())
		Expect(val.(v1.Endpoints).Subsets).To(HaveLen(0)) //nolint:staticcheck

		_, present = fsc.cache.Get("namespace1/my-local-service")
		Expect(present).To(BeFalse())

		// Modify my-remote-service so that it is not federated and update my-local-service so that it is
		// federated instead. Both my-local-service and federated should contain the same endpoints which
		// should just be those of my-remote-service.
		By("Reconfigure my-remote-service to be non-federated and my-local-service to be federated")
		svc1Fed := svc1.DeepCopy()
		svc1Fed.Annotations = map[string]string{
			FederationServiceSelectorAnnotation: "run == \"nginx\"",
		}
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVUpdated,
				KVPair: model.KVPair{
					Key:   svcKey1,
					Value: svc1Fed,
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVUpdated,
				KVPair: model.KVPair{
					Key:   svcKey2,
					Value: svc2.DeepCopy(),
				},
			},
		})

		By("Validating links between the federated and backing services is correct")
		siFed = fsc.allServices[sidFed]
		Expect(siFed.federatedServices.Len()).To(Equal(0))
		Expect(siFed.backingServices.Len()).To(Equal(1))
		Expect(siFed.backingServices.Contains(sid2)).To(BeTrue())

		si1 = fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(0))
		Expect(si1.backingServices.Len()).To(Equal(1))
		Expect(si1.backingServices.Contains(sid2)).To(BeTrue())

		si2 = fsc.allServices[sid2]
		Expect(si2.federatedServices.Len()).To(Equal(2))
		Expect(si2.federatedServices.Contains(sidFed)).To(BeTrue())
		Expect(si2.federatedServices.Contains(sid1)).To(BeTrue())
		Expect(si2.backingServices.Len()).To(Equal(0))

		si3 = fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 = fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking the reconciliation cache has the correct federated settings")
		Expect(fsc.dirtyServices.Len()).To(Equal(0))
		expected = fedEpExpectedNoSvc1.DeepCopy()
		fsc.sanitizeEndpoints(expected)
		val, present = fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeTrue())
		Expect(val).To(Equal(*expected))

		expected = svc1FedEpExpected.DeepCopy()
		fsc.sanitizeEndpoints(expected)
		val, present = fsc.cache.Get("namespace1/my-local-service")
		Expect(present).To(BeTrue())
		Expect(val).To(Equal(*expected))

		// Modify the endpoints of my-remote-service and check that the federated endpoints are updated.
		By("Modify the endpoints of my-remote-service and check that the federated endpoints are updated")
		ep2PortUpdate := ep2.DeepCopy()
		// Increment all the ports in the remote cluster.
		for si := range ep2PortUpdate.Subsets {
			for pi := range ep2PortUpdate.Subsets[si].Ports {
				ep2PortUpdate.Subsets[si].Ports[pi].Port++
			}
		}
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVUpdated,
				KVPair: model.KVPair{
					Key:   epKey2,
					Value: ep2PortUpdate,
				},
			},
		})

		By("Validating links between the federated and backing services is correct")
		siFed = fsc.allServices[sidFed]
		Expect(siFed.federatedServices.Len()).To(Equal(0))
		Expect(siFed.backingServices.Len()).To(Equal(1))
		Expect(siFed.backingServices.Contains(sid2)).To(BeTrue())

		si1 = fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(0))
		Expect(si1.backingServices.Len()).To(Equal(1))
		Expect(si1.backingServices.Contains(sid2)).To(BeTrue())

		si2 = fsc.allServices[sid2]
		Expect(si2.federatedServices.Len()).To(Equal(2))
		Expect(si2.federatedServices.Contains(sidFed)).To(BeTrue())
		Expect(si2.federatedServices.Contains(sid1)).To(BeTrue())
		Expect(si2.backingServices.Len()).To(Equal(0))

		si3 = fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 = fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking the reconciliation cache has the correct federated settings")
		// Increment all the ports from the expected sets of data.
		Expect(fsc.dirtyServices.Len()).To(Equal(0))
		expected = fedEpExpectedNoSvc1.DeepCopy()
		for si := range expected.Subsets {
			for pi := range expected.Subsets[si].Ports {
				expected.Subsets[si].Ports[pi].Port++
			}
		}
		fsc.sanitizeEndpoints(expected)
		val, present = fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeTrue())
		Expect(val).To(Equal(*expected))

		expected = svc1FedEpExpected.DeepCopy()
		for si := range expected.Subsets {
			for pi := range expected.Subsets[si].Ports {
				expected.Subsets[si].Ports[pi].Port++
			}
		}
		fsc.sanitizeEndpoints(expected)
		val, present = fsc.cache.Get("namespace1/my-local-service")
		Expect(present).To(BeTrue())
		Expect(val).To(Equal(*expected))

		// Modify my-local-service so that the federation annotation does not parse correctly, and reset the ports
		// in my-remote-service. The endpoints for my-local-service should be removed. The endpoints for federated
		// should remain unchanged - they should not include the endpoints from my-local-service.
		By("configure my-local-service to have an invalid selector")
		svc1FedBad := svc1.DeepCopy()
		svc1FedBad.Annotations = map[string]string{
			FederationServiceSelectorAnnotation: "this selector should not parse correctly!",
		}
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVUpdated,
				KVPair: model.KVPair{
					Key:   epKey2,
					Value: ep2.DeepCopy(),
				},
			},
			{
				UpdateType: bapi.UpdateTypeKVUpdated,
				KVPair: model.KVPair{
					Key:   svcKey1,
					Value: svc1FedBad,
				},
			},
		})

		By("Validating links between the federated and backing services is correct")
		siFed = fsc.allServices[sidFed]
		Expect(siFed.federatedServices.Len()).To(Equal(0))
		Expect(siFed.backingServices.Len()).To(Equal(1))
		Expect(siFed.backingServices.Contains(sid2)).To(BeTrue())

		si1 = fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(0))
		Expect(si1.backingServices.Len()).To(Equal(0))
		Expect(si1.federationConfigErr).ToNot(BeNil())

		si2 = fsc.allServices[sid2]
		Expect(si2.federatedServices.Len()).To(Equal(1))
		Expect(si2.federatedServices.Contains(sidFed)).To(BeTrue())
		Expect(si2.backingServices.Len()).To(Equal(0))

		si3 = fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 = fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking the reconciliation cache has the correct federated settings")
		Expect(fsc.dirtyServices.Len()).To(Equal(0))
		expected = fedEpExpectedNoSvc1.DeepCopy()
		fsc.sanitizeEndpoints(expected)
		val, present = fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeTrue())
		Expect(val).To(Equal(*expected))
		_, present = fsc.cache.Get("namespace1/my-local-service")
		Expect(present).To(BeFalse())

		// Modify my-remote-service so that it has an invalid federation annotation. This will remove the
		// endpoints from the federated service - resulting in empty subsets.
		By("Reconfigure my-remote-service to have an invalid federation annotation")
		svc2FedBad := svc2.DeepCopy()
		svc2FedBad.Annotations = map[string]string{
			FederationServiceSelectorAnnotation: "this selector will also not parse correctly!",
		}
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVUpdated,
				KVPair: model.KVPair{
					Key:   svcKey2,
					Value: svc2FedBad,
				},
			},
		})

		By("Validating links between the federated and backing services is correct")
		siFed = fsc.allServices[sidFed]
		Expect(siFed.federatedServices.Len()).To(Equal(0))
		Expect(siFed.backingServices.Len()).To(Equal(0))

		si1 = fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(0))
		Expect(si1.backingServices.Len()).To(Equal(0))
		Expect(si1.federationConfigErr).ToNot(BeNil())

		si2 = fsc.allServices[sid2]
		Expect(si2.federatedServices.Len()).To(Equal(0))
		Expect(si2.backingServices.Len()).To(Equal(0))
		Expect(si2.federationConfigErr).ToNot(BeNil())

		si3 = fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 = fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking the reconciliation cache has federated endpoints with no subsets")
		Expect(fsc.dirtyServices.Len()).To(Equal(0))
		val, present = fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeTrue())
		Expect(val.(v1.Endpoints).Subsets).To(HaveLen(0)) //nolint:staticcheck

		// Deleting the federated service should leave the reconciliation cache empty.
		By("Deleting federated service")
		fsc.OnUpdates([]bapi.Update{
			{
				UpdateType: bapi.UpdateTypeKVDeleted,
				KVPair: model.KVPair{
					Key: svcKeyFed,
				},
			},
		})

		By("Validating links between the federated and backing services is correct")
		siFed = fsc.allServices[sidFed]
		Expect(siFed).To(BeNil())

		si1 = fsc.allServices[sid1]
		Expect(si1.federatedServices.Len()).To(Equal(0))
		Expect(si1.backingServices.Len()).To(Equal(0))

		si2 = fsc.allServices[sid2]
		Expect(si2.federatedServices.Len()).To(Equal(0))
		Expect(si2.backingServices.Len()).To(Equal(0))
		Expect(si2.federationConfigErr).ToNot(BeNil())

		si3 = fsc.allServices[sid3]
		Expect(si3.federatedServices.Len()).To(Equal(0))
		Expect(si3.backingServices.Len()).To(Equal(0))

		si4 = fsc.allServices[sid4]
		Expect(si4.federatedServices.Len()).To(Equal(0))
		Expect(si4.backingServices.Len()).To(Equal(0))

		By("Checking there is no entry in the reconciliation cache")
		_, present = fsc.cache.Get("namespace1/federated")
		Expect(present).To(BeFalse())
	})
})
