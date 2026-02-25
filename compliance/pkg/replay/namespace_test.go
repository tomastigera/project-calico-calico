// Copyright (c) 2018 Tigera, Inc. All rights reserved.
package replay_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit"

	"github.com/projectcalico/calico/compliance/pkg/api"
	. "github.com/projectcalico/calico/compliance/pkg/replay"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/list"
)

var (
	now           = time.Now()
	nowMinus24Hrs = now.Add(-24 * time.Hour)
	nowMinus48Hrs = nowMinus24Hrs.Add(-24 * time.Hour)
	namespace1    = "namespace1"
	namespace2    = "namespace2"

	gnp1 = apiv3.GlobalNetworkPolicy{
		TypeMeta: resources.TypeCalicoGlobalNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "gnp1",
			ResourceVersion: "1",
		},
	}
	sgnp1 = apiv3.StagedGlobalNetworkPolicy{
		TypeMeta: resources.TypeCalicoStagedGlobalNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "gnp1",
			ResourceVersion: "1",
		},
	}
	gns1 = apiv3.GlobalNetworkSet{
		TypeMeta: resources.TypeCalicoGlobalNetworkSets,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "gns1",
			ResourceVersion: "1",
		},
	}
	netset1 = apiv3.NetworkSet{
		TypeMeta: resources.TypeCalicoNetworkSets,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "ns1",
			Namespace:       namespace1,
			ResourceVersion: "1",
		},
	}
	hep1 = apiv3.HostEndpoint{
		TypeMeta: resources.TypeCalicoHostEndpoints,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "hep1",
			ResourceVersion: "1",
		},
	}
	np1 = apiv3.NetworkPolicy{
		TypeMeta: resources.TypeCalicoNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "np1",
			Namespace:       namespace1,
			ResourceVersion: "1",
		},
	}
	snp1 = apiv3.StagedNetworkPolicy{
		TypeMeta: resources.TypeCalicoStagedNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "np1",
			Namespace:       namespace1,
			ResourceVersion: "1",
		},
	}
	np2 = apiv3.NetworkPolicy{
		TypeMeta: resources.TypeCalicoNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "np2",
			Namespace:       namespace2,
			ResourceVersion: "1",
		},
	}
	tier1 = apiv3.Tier{
		TypeMeta: resources.TypeCalicoTiers,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "tier1",
			ResourceVersion: "1",
		},
	}
	ep1 = corev1.Endpoints{ //nolint:staticcheck
		TypeMeta: resources.TypeK8sEndpoints,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "svc1",
			Namespace:       namespace1,
			ResourceVersion: "1",
		},
	}
	ep2 = corev1.Endpoints{ //nolint:staticcheck
		TypeMeta: resources.TypeK8sEndpoints,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "svc2",
			Namespace:       namespace2,
			ResourceVersion: "1",
		},
	}
	ns1 = corev1.Namespace{
		TypeMeta: resources.TypeK8sNamespaces,
		ObjectMeta: metav1.ObjectMeta{
			Name:            namespace1,
			ResourceVersion: "1",
		},
	}
	ns2 = corev1.Namespace{
		TypeMeta: resources.TypeK8sNamespaces,
		ObjectMeta: metav1.ObjectMeta{
			Name:            namespace2,
			ResourceVersion: "1",
		},
	}
	knp1 = networkingv1.NetworkPolicy{
		TypeMeta: resources.TypeK8sNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "knp1",
			Namespace:       namespace1,
			ResourceVersion: "1",
		},
	}
	sknp1 = apiv3.StagedKubernetesNetworkPolicy{
		TypeMeta: resources.TypeCalicoStagedKubernetesNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "knp1",
			Namespace:       namespace1,
			ResourceVersion: "1",
		},
	}
	knp2 = networkingv1.NetworkPolicy{
		TypeMeta: resources.TypeK8sNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "knp2",
			Namespace:       namespace2,
			ResourceVersion: "1",
		},
	}
	pod1 = corev1.Pod{
		TypeMeta: resources.TypeK8sPods,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pod1",
			Namespace:       namespace1,
			ResourceVersion: "1",
		},
	}
	pod2 = corev1.Pod{
		TypeMeta: resources.TypeK8sPods,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pod2",
			Namespace:       namespace2,
			ResourceVersion: "1",
		},
	}
	sa1 = corev1.ServiceAccount{
		TypeMeta: resources.TypeK8sServiceAccounts,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "sa1",
			Namespace:       namespace1,
			ResourceVersion: "1",
		},
	}
	sa2 = corev1.ServiceAccount{
		TypeMeta: resources.TypeK8sServiceAccounts,
		ObjectMeta: metav1.ObjectMeta{
			Name:            "sa2",
			Namespace:       namespace2,
			ResourceVersion: "1",
		},
	}
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func resourceListForType(tm metav1.TypeMeta) *list.TimestampedResourceList {
	var l resources.ResourceList
	switch tm {
	case resources.TypeCalicoGlobalNetworkPolicies:
		l = &apiv3.GlobalNetworkPolicyList{
			TypeMeta: resources.TypeCalicoGlobalNetworkPolicies,
			Items:    []apiv3.GlobalNetworkPolicy{gnp1},
		}
	case resources.TypeCalicoStagedGlobalNetworkPolicies:
		l = &apiv3.StagedGlobalNetworkPolicyList{
			TypeMeta: resources.TypeCalicoStagedGlobalNetworkPolicies,
			Items:    []apiv3.StagedGlobalNetworkPolicy{sgnp1},
		}
	case resources.TypeCalicoGlobalNetworkSets:
		l = &apiv3.GlobalNetworkSetList{
			TypeMeta: resources.TypeCalicoGlobalNetworkSets,
			Items:    []apiv3.GlobalNetworkSet{gns1},
		}
	case resources.TypeCalicoNetworkSets:
		l = &apiv3.NetworkSetList{
			TypeMeta: resources.TypeCalicoNetworkSets,
			Items:    []apiv3.NetworkSet{netset1},
		}
	case resources.TypeCalicoHostEndpoints:
		l = &apiv3.HostEndpointList{
			TypeMeta: resources.TypeCalicoHostEndpoints,
			Items:    []apiv3.HostEndpoint{hep1},
		}
	case resources.TypeCalicoNetworkPolicies:
		l = &apiv3.NetworkPolicyList{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			Items:    []apiv3.NetworkPolicy{np1, np2},
		}
	case resources.TypeCalicoStagedNetworkPolicies:
		l = &apiv3.StagedNetworkPolicyList{
			TypeMeta: resources.TypeCalicoStagedNetworkPolicies,
			Items:    []apiv3.StagedNetworkPolicy{snp1},
		}
	case resources.TypeCalicoTiers:
		l = &apiv3.TierList{
			TypeMeta: resources.TypeCalicoTiers,
			Items:    []apiv3.Tier{tier1},
		}
	case resources.TypeK8sEndpoints:
		l = &corev1.EndpointsList{ //nolint:staticcheck
			TypeMeta: resources.TypeK8sEndpoints,
			Items:    []corev1.Endpoints{ep1, ep2}, //nolint:staticcheck
		}
	case resources.TypeK8sNamespaces:
		l = &corev1.NamespaceList{
			TypeMeta: resources.TypeK8sNamespaces,
			Items:    []corev1.Namespace{ns1, ns2},
		}
	case resources.TypeK8sNetworkPolicies:
		l = &networkingv1.NetworkPolicyList{
			TypeMeta: resources.TypeK8sNetworkPolicies,
			Items:    []networkingv1.NetworkPolicy{knp1, knp2},
		}
	case resources.TypeCalicoStagedKubernetesNetworkPolicies:
		l = &apiv3.StagedKubernetesNetworkPolicyList{
			TypeMeta: resources.TypeCalicoStagedKubernetesNetworkPolicies,
			Items:    []apiv3.StagedKubernetesNetworkPolicy{sknp1},
		}
	case resources.TypeK8sPods:
		l = &corev1.PodList{
			TypeMeta: resources.TypeK8sPods,
			Items:    []corev1.Pod{pod1, pod2},
		}
	case resources.TypeK8sServiceAccounts:
		l = &corev1.ServiceAccountList{
			TypeMeta: resources.TypeK8sServiceAccounts,
			Items:    []corev1.ServiceAccount{sa1, sa2},
		}
	default:
		panic(fmt.Errorf("unexpected resource type: %v", tm))
	}

	return &list.TimestampedResourceList{
		ResourceList:              l,
		RequestStartedTimestamp:   metav1.Time{Time: nowMinus48Hrs},
		RequestCompletedTimestamp: metav1.Time{Time: nowMinus48Hrs},
	}
}

var _ = Describe("Replay namespace deletion", func() {
	var (
		mockListDestination *api.MockListDestination
		mockEventFetcher    *api.MockReportEventFetcher
		mockSyncerCallbacks *syncer.MockSyncerCallbacks
		replayer            syncer.Starter
	)

	BeforeEach(func() {
		mockSyncerCallbacks = new(syncer.MockSyncerCallbacks)
		mockListDestination = new(api.MockListDestination)
		mockEventFetcher = new(api.MockReportEventFetcher)
		replayer = New(nowMinus24Hrs, now, mockListDestination, mockEventFetcher, mockSyncerCallbacks)
	})

	AfterEach(func() {
		mockSyncerCallbacks.AssertExpectations(GinkgoT())
	})

	It("should handle namespace deletion before the in-sync", func() {
		By("running the replayed with a namespace deletion in the first event query")
		for _, helper := range resources.GetAllResourceHelpers() {
			resourceList := resourceListForType(helper.TypeMeta())
			mockListDestination.On("RetrieveList", helper.TypeMeta(), mock.Anything, mock.Anything, mock.Anything).Return(resourceList, nil)
		}

		mockEventFetcher.On("GetAuditEvents", mock.Anything, &nowMinus48Hrs, &nowMinus24Hrs).Return(
			createAuditEventChannel(&api.AuditEventResult{
				Event: &auditv1.Event{
					Stage: auditv1.StageResponseComplete,
					Verb:  string(v1.Delete),
					ObjectRef: &auditv1.ObjectReference{
						Resource:        "namespaces",
						Name:            namespace1,
						APIGroup:        "",
						APIVersion:      "v1",
						ResourceVersion: "1",
					},
				},
			})).Once()
		mockEventFetcher.On("GetAuditEvents", mock.Anything, &nowMinus24Hrs, &now).Return(createAuditEventChannel()).Once()

		By("Checking for the expected updates")
		resourceList := []resources.Resource{&gnp1, &sgnp1, &gns1, &tier1, &hep1, &np2, &knp2, &ep2, &pod2, &sa2, &ns2}
		for _, resource := range resourceList {
			mockSyncerCallbacks.On("OnUpdates", []syncer.Update{{Type: syncer.UpdateTypeSet, ResourceID: resources.GetResourceID(resource), Resource: resource}})
		}

		By("Checking for status update complete")
		mockSyncerCallbacks.On("OnStatusUpdate", syncer.NewStatusUpdateInSync()).Return()
		mockSyncerCallbacks.On("OnStatusUpdate", syncer.NewStatusUpdateComplete()).Return()

		replayer.Start(context.Background())
	})

	It("should handle namespace deletion after the in-sync", func() {
		By("running the replayed with a namespace deletion in the second event query")
		for _, helper := range resources.GetAllResourceHelpers() {
			resourceList := resourceListForType(helper.TypeMeta())
			mockListDestination.On("RetrieveList", helper.TypeMeta(), mock.Anything, mock.Anything, mock.Anything).Return(resourceList, nil)
		}

		mockEventFetcher.On("GetAuditEvents", mock.Anything, &nowMinus48Hrs, &nowMinus24Hrs).Return(createAuditEventChannel()).Once()
		mockEventFetcher.On("GetAuditEvents", mock.Anything, &nowMinus24Hrs, &now).Return(
			createAuditEventChannel(&api.AuditEventResult{
				Event: &auditv1.Event{
					Stage: auditv1.StageResponseComplete,
					Verb:  string(v1.Delete),
					ObjectRef: &auditv1.ObjectReference{
						Resource:        "namespaces",
						Name:            namespace1,
						APIGroup:        "",
						APIVersion:      "v1",
						ResourceVersion: "1",
					},
				},
			})).Once()

		By("Checking for the expected updates")
		deletedResourceList := []resources.Resource{&pod1, &sa1, &ep1, &np1, &snp1, &knp1, &sknp1, &netset1, &ns1}

		var deletedResources []resources.Resource
		mockSyncerCallbacks.On("OnUpdates", mock.MatchedBy(func(updates []syncer.Update) bool {
			if len(updates) != len(deletedResourceList) {
				return false
			}

			for _, update := range updates {
				if update.Type != syncer.UpdateTypeDeleted {
					return false
				}
			}

			return true
		})).Run(func(args mock.Arguments) {
			updates := args.Get(0).([]syncer.Update)
			for _, update := range updates {
				deletedResources = append(deletedResources, update.Resource)
			}
		})

		updatedResourceList := []resources.Resource{
			&gnp1, &sgnp1, &gns1, &tier1, &hep1, &netset1, &np1, &snp1, &np2, &knp1, &sknp1,
			&knp2, &ep1, &ep2, &pod1, &pod2, &sa1, &sa2, &ns1, &ns2,
		}
		for _, resource := range updatedResourceList {
			mockSyncerCallbacks.On("OnUpdates", []syncer.Update{{Type: syncer.UpdateTypeSet, ResourceID: resources.GetResourceID(resource), Resource: resource}})
		}

		By("Checking for status update complete")
		mockSyncerCallbacks.On("OnStatusUpdate", syncer.NewStatusUpdateInSync()).Return()
		mockSyncerCallbacks.On("OnStatusUpdate", syncer.NewStatusUpdateComplete()).Return()

		replayer.Start(context.Background())

		Expect(deletedResources).Should(ConsistOf([]resources.Resource{&pod1, &sa1, &ep1, &np1, &snp1, &knp1, &sknp1, &netset1, &ns1}))
	})
})
