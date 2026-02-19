// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package cache

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/dispatcherv1v3"
)

var _ = Describe("Querycache endpoints cache tests", func() {
	var (
		epc        *endpointsCache
		key1, key2 model.KVPair
	)

	BeforeEach(func() {
		epc = &endpointsCache{
			workloadEndpointsByNamespace: make(map[string]*endpointCache),
			hostEndpoints:                newEndpointCache(),

			converter:    conversion.NewConverter(),
			wepConverter: conversion.NewWorkloadEndpointConverter(),
		}

		key1 = model.KVPair{
			Key: model.KeyFromDefaultPath("/calico/resources/v3/projectcalico.org/workloadendpoints/ns-1/node--1-k8s-name--1-eth0"),
			Value: &libapi.WorkloadEndpoint{
				TypeMeta: metav1.TypeMeta{
					APIVersion: apiv3.GroupVersionCurrent,
					Kind:       libapi.KindWorkloadEndpoint,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "node--1-k8s-name--1-eth0",
					Namespace: "ns-1",
					Labels:    map[string]string{},
				},
				Spec: libapi.WorkloadEndpointSpec{
					Node: "node-1",
				},
				Status: libapi.WorkloadEndpointStatus{
					Phase: string(corev1.PodRunning),
				},
			},
		}

		key2 = model.KVPair{
			Key: model.KeyFromDefaultPath("/calico/resources/v3/projectcalico.org/workloadendpoints/ns-2/node--2-k8s-name--2-eth0"),
			Value: &libapi.WorkloadEndpoint{
				TypeMeta: metav1.TypeMeta{
					APIVersion: apiv3.GroupVersionCurrent,
					Kind:       libapi.KindWorkloadEndpoint,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "node--2-k8s-name--2-eth0",
					Namespace: "ns-2",
					Labels:    map[string]string{},
				},
				Spec: libapi.WorkloadEndpointSpec{
					Node: "node-2",
				},
				Status: libapi.WorkloadEndpointStatus{
					Phase: string(corev1.PodRunning),
				},
			},
		}
	})

	Context("Failed endpoint count tests", func() {
		It("should add failed WEPs to cached when receives v3 update events", func() {
			// create some WEPs in the cache
			newEvent1 := dispatcherv1v3.Update{
				UpdateV3: &bapi.Update{
					KVPair:     key1,
					UpdateType: bapi.UpdateTypeKVNew,
				},
			}
			newEvent2 := dispatcherv1v3.Update{
				UpdateV3: &bapi.Update{
					KVPair:     key2,
					UpdateType: bapi.UpdateTypeKVNew,
				},
			}
			epc.onUpdate(newEvent1)
			epc.onUpdate(newEvent2)

			// update one WEP phase to be failed
			key1.Value.(*libapi.WorkloadEndpoint).Status.Phase = string(corev1.PodFailed)
			updateEvent := dispatcherv1v3.Update{
				UpdateV3: &bapi.Update{
					KVPair:     key1,
					UpdateType: bapi.UpdateTypeKVUpdated,
				},
			}
			epc.onUpdate(updateEvent)

			Expect(epc.TotalWorkloadEndpointsByNamespace()).To(Equal(map[string]api.EndpointSummary{
				"ns-1": {
					Total:             1,
					NumWithNoLabels:   1,
					NumWithNoPolicies: 1,
					NumFailed:         1,
				},
				"ns-2": {
					Total:             1,
					NumWithNoLabels:   1,
					NumWithNoPolicies: 1,
					NumFailed:         0,
				},
			}))
		})

		It("should remove failed Pods from cache when receives an Pod delete event", func() {
			// create some WEPs in the cache
			newEvent1 := dispatcherv1v3.Update{
				UpdateV3: &bapi.Update{
					KVPair:     key1,
					UpdateType: bapi.UpdateTypeKVNew,
				},
			}
			newEvent2 := dispatcherv1v3.Update{
				UpdateV3: &bapi.Update{
					KVPair:     key2,
					UpdateType: bapi.UpdateTypeKVNew,
				},
			}
			epc.onUpdate(newEvent1)
			epc.onUpdate(newEvent2)

			Expect(epc.TotalWorkloadEndpointsByNamespace()).To(Equal(map[string]api.EndpointSummary{
				"ns-1": {
					Total:             1,
					NumWithNoLabels:   1,
					NumWithNoPolicies: 1,
					NumFailed:         0,
				},
				"ns-2": {
					Total:             1,
					NumWithNoLabels:   1,
					NumWithNoPolicies: 1,
					NumFailed:         0,
				},
			}))

			// delete a WEP with phase equals Failed
			key1.Value.(*libapi.WorkloadEndpoint).Status.Phase = string(corev1.PodFailed)
			deleteEvent := dispatcherv1v3.Update{
				UpdateV3: &bapi.Update{
					KVPair:     key1,
					UpdateType: bapi.UpdateTypeKVDeleted,
				},
			}
			epc.onUpdate(deleteEvent)

			Expect(epc.TotalWorkloadEndpointsByNamespace()).To(Equal(map[string]api.EndpointSummary{
				"ns-1": {
					Total:             0,
					NumWithNoLabels:   0,
					NumWithNoPolicies: 0,
					NumFailed:         1,
				},
				"ns-2": {
					Total:             1,
					NumWithNoLabels:   1,
					NumWithNoPolicies: 1,
					NumFailed:         0,
				},
			}))

			// delete the failed Pod
			pod := &corev1.Pod{
				TypeMeta: resources.TypeK8sPods,
				ObjectMeta: metav1.ObjectMeta{
					Name:            "name-1",
					Namespace:       "ns-1",
					ResourceVersion: "1",
				},
				Spec: corev1.PodSpec{
					NodeName: "node-1",
				},
			}
			epc.onPodDelete(pod)

			Expect(epc.TotalWorkloadEndpointsByNamespace()).To(Equal(map[string]api.EndpointSummary{
				"ns-2": {
					Total:             1,
					NumWithNoLabels:   1,
					NumWithNoPolicies: 1,
					NumFailed:         0,
				},
			}))
		})
	})

})
