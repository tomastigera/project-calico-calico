// Copyright (c) 2019 Tigera, Inc. SelectAll rights reserved.
package testutils

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

// NewXrefCacheTester returns a new XrefCacheTester. This can be used to send in syncer events for the different
// resource types, and to query current state of the cache.
func NewXrefCacheTester() *XrefCacheTester {
	cfg := config.MustLoadConfig()
	cfg.IncludeStagedNetworkPolicies = true
	return &XrefCacheTester{
		XrefCache: xrefcache.NewXrefCache(cfg, func() {
			log.Info("Healthy notification from xref cache")
		}),
	}
}

// ipByteToIPString converts the IP byte value to an IP string.
func ipByteToIPString(ip IP) string {
	switch ip {
	case IP1:
		return "192.168.0.0"
	case IP2:
		return "192.168.0.1"
	case IP3:
		return "192.168.10.0"
	case IP4:
		return "192.168.10.1"
	}
	return ""
}

// ipByteToIPStringSlice converts the IP byte value to an IP string slice. Note that the ip value is actually a bit-mask
// so may encapsulate multiple addresses in one.
func ipByteToIPStringSlice(ip IP) []string {
	var ips []string
	if ip&IP1 != 0 {
		ips = append(ips, ipByteToIPString(IP1))
	}
	if ip&IP2 != 0 {
		ips = append(ips, ipByteToIPString(IP2))
	}
	if ip&IP3 != 0 {
		ips = append(ips, ipByteToIPString(IP3))
	}
	if ip&IP4 != 0 {
		ips = append(ips, ipByteToIPString(IP4))
	}
	return ips
}

// labelByteToLabels converts the label bitmask to a set of labels with keys named label<bit> and an enpty string value.
func labelByteToLabels(l TestLabel) map[string]string {
	labels := make(map[string]string)
	for i := uint(0); i < 8; i++ {
		if l&(1<<i) != 0 {
			labels[fmt.Sprintf("label%d", i+1)] = ""
		}
	}
	return labels
}

// selectorByteToSelector converts the selector bitmask to an ANDed set of has(label<bit>) selector string.
func selectorByteToSelector(s Selector) string {
	if s == SelectAll {
		return "all()"
	}
	if s == NoSelector {
		return ""
	}
	sels := []string{}
	for i := uint(0); i < 8; i++ {
		if s&(1<<i) != 0 {
			sels = append(sels, fmt.Sprintf("has(label%d)", i+1))
		}
	}
	return strings.Join(sels, " && ")
}

// selectorByteToNamespaceSelector converts the selector bitmask to an ANDed set of has(label<bit>) selector string.
// This specific method is used by the rule selector testing, where we need to encode a namespace label.
func selectorByteToNamespaceSelector(s Selector) string {
	if s == SelectAll {
		return "all()"
	}
	if s == NoSelector {
		return ""
	}
	sels := []string{}
	for i := uint(0); i < 8; i++ {
		if s&(1<<i) != 0 {
			sels = append(sels, fmt.Sprintf("has(pcns.label%d)", i+1))
		}
	}
	return strings.Join(sels, " && ")
}

// selectorByteToSelector converts the selector bitmask to a Kubernetes selector containing the set of label<bit>) keys
// with the "Exists" operator. This is effectively the k8s equivalent of the selectorByteToSelector method.
func selectorByteToK8sSelector(s Selector) *metav1.LabelSelector {
	if s == NoSelector {
		return nil
	}
	sel := &metav1.LabelSelector{}
	if s == SelectAll {
		return sel
	}
	for i := uint(0); i < 8; i++ {
		if s&(1<<i) != 0 {
			sel.MatchExpressions = append(sel.MatchExpressions, metav1.LabelSelectorRequirement{
				Key:      fmt.Sprintf("label%d", i+1),
				Operator: metav1.LabelSelectorOpExists,
			})
		}
	}
	return sel
}

// getResourceId converts index values to an actual resource ID.
func getResourceId(tm metav1.TypeMeta, nameIdx Name, namespaceIdx Namespace) apiv3.ResourceID {
	name := "default"
	if nameIdx != NameDefault {
		kind := tm.Kind

		// Staged policy names should be the same as their enforced counterpart.
		switch kind {
		case apiv3.KindStagedNetworkPolicy:
			kind = apiv3.KindNetworkPolicy
		case apiv3.KindStagedGlobalNetworkPolicy:
			kind = apiv3.KindGlobalNetworkPolicy
		case apiv3.KindStagedKubernetesNetworkPolicy:
			kind = apiv3.KindNetworkPolicy
		}

		name = fmt.Sprintf("%s-%d", strings.ToLower(kind), nameIdx)
	}
	var namespace string
	if namespaceIdx > 0 {
		namespace = fmt.Sprintf("namespace-%d", namespaceIdx)
	}
	if tm == resources.TypeK8sNamespaces {
		name = namespace
		namespace = ""
	}
	return apiv3.ResourceID{
		TypeMeta:  tm,
		Name:      name,
		Namespace: namespace,
	}
}

// getPolicyResourceId converts index values to an actual resource ID for a Calico policy resource type.
func getPolicyResourceId(kind metav1.TypeMeta, tierIdx Name, nameIdx Name, namespaceIdx Namespace) (apiv3.ResourceID, string) {
	id := getResourceId(kind, nameIdx, namespaceIdx)
	tier := "default"
	if tierIdx != NameDefault {
		tier = fmt.Sprintf("tier-%d", tierIdx)
	}
	id.Name = tier + "." + id.Name
	return id, tier
}

// getObjectMeta returns a ObjectMeta for a given resource ID and set of labels.
func getObjectMeta(r apiv3.ResourceID, labels TestLabel) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      r.Name,
		Namespace: r.Namespace,
		Labels:    labelByteToLabels(labels),

		// Use a hard-coded UID here, since parsing / conversion logic expects
		// this to be non-nil.
		UID: types.UID("30316465-6365-4463-ad63-3564622d3638"),
	}
}

// XrefCacheTester is the XrefCache tester.
type XrefCacheTester struct {
	xrefcache.XrefCache
	AccumlateUpdates   bool
	accumulatedUpdates []syncer.Update
}

// OnUpdate is a wrapper around OnUpdates to simplify code.
func (t *XrefCacheTester) OnUpdate(u syncer.Update) {
	t.accumulatedUpdates = append(t.accumulatedUpdates, u)
	if !t.AccumlateUpdates {
		t.OnUpdates(t.accumulatedUpdates)
		t.accumulatedUpdates = nil
	}
}

// GetSelector returns the selector for a given selector bitmask value.
func (t *XrefCacheTester) GetSelector(sel Selector) string {
	return selectorByteToSelector(sel)
}

//
// -- HostEndpoint access --
//

func (t *XrefCacheTester) GetHostEndpoint(nameIdx Name) *xrefcache.CacheEntryEndpoint {
	r := getResourceId(resources.TypeCalicoHostEndpoints, nameIdx, 0)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryEndpoint)
}

func (t *XrefCacheTester) SetHostEndpoint(nameIdx Name, labels TestLabel, ips IP) {
	r := getResourceId(resources.TypeCalicoHostEndpoints, nameIdx, 0)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource: &apiv3.HostEndpoint{
			TypeMeta:   r.TypeMeta,
			ObjectMeta: getObjectMeta(r, labels),
			Spec: apiv3.HostEndpointSpec{
				Node:        "node1",
				ExpectedIPs: ipByteToIPStringSlice(ips),
			},
		},
	})
}

func (t *XrefCacheTester) DeleteHostEndpoint(nameIdx Name) {
	r := getResourceId(resources.TypeCalicoHostEndpoints, nameIdx, 0)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- Tier access --
//

func (t *XrefCacheTester) GetTier(nameIdx Name) *xrefcache.CacheEntryTier {
	r := getResourceId(resources.TypeCalicoTiers, nameIdx, 0)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryTier)
}

func (t *XrefCacheTester) SetTier(nameIdx Name, order float64) {
	r := getResourceId(resources.TypeCalicoTiers, nameIdx, 0)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource: &apiv3.Tier{
			TypeMeta:   r.TypeMeta,
			ObjectMeta: getObjectMeta(r, 0),
			Spec: apiv3.TierSpec{
				Order: &order,
			},
		},
	})
}

func (t *XrefCacheTester) DeleteTier(nameIdx Name) {
	r := getResourceId(resources.TypeCalicoTiers, nameIdx, 0)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

func (t *XrefCacheTester) GetDefaultTier() *xrefcache.CacheEntryTier {
	r := apiv3.ResourceID{
		TypeMeta: resources.TypeCalicoTiers,
		Name:     "default",
	}
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryTier)
}

func (t *XrefCacheTester) SetDefaultTier() {
	r := apiv3.ResourceID{
		TypeMeta: resources.TypeCalicoTiers,
		Name:     "default",
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource: &apiv3.Tier{
			TypeMeta:   r.TypeMeta,
			ObjectMeta: getObjectMeta(r, 0),
		},
	})
}

func (t *XrefCacheTester) DeleteDefaultTier() {
	r := apiv3.ResourceID{
		TypeMeta: resources.TypeCalicoTiers,
		Name:     "default",
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- GlobalNetworkSet access --
//

func (t *XrefCacheTester) GetGlobalNetworkSet(nameIdx Name) *xrefcache.CacheEntryNetworkSet {
	r := getResourceId(resources.TypeCalicoGlobalNetworkSets, nameIdx, 0)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryNetworkSet)
}

func (t *XrefCacheTester) SetGlobalNetworkSet(nameIdx Name, labels TestLabel, nets Net) {
	r := getResourceId(resources.TypeCalicoGlobalNetworkSets, nameIdx, 0)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource: &apiv3.GlobalNetworkSet{
			TypeMeta:   r.TypeMeta,
			ObjectMeta: getObjectMeta(r, labels),
			Spec: apiv3.GlobalNetworkSetSpec{
				Nets: getCalicoNets(nets),
			},
		},
	})
}

func (t *XrefCacheTester) DeleteGlobalNetworkSet(nameIdx Name) {
	r := getResourceId(resources.TypeCalicoGlobalNetworkSets, nameIdx, 0)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- NetworkSet access --
//

func (t *XrefCacheTester) GetNetworkSet(nameIdx Name, namespaceIdx Namespace) *xrefcache.CacheEntryNetworkSet {
	r := getResourceId(resources.TypeCalicoNetworkSets, nameIdx, namespaceIdx)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryNetworkSet)
}

func (t *XrefCacheTester) SetNetworkSet(nameIdx Name, namespaceIdx Namespace, labels TestLabel, nets Net) {
	r := getResourceId(resources.TypeCalicoNetworkSets, nameIdx, namespaceIdx)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource: &apiv3.NetworkSet{
			TypeMeta:   r.TypeMeta,
			ObjectMeta: getObjectMeta(r, labels),
			Spec: apiv3.NetworkSetSpec{
				Nets: getCalicoNets(nets),
			},
		},
	})
}

func (t *XrefCacheTester) DeleteNetworkSet(nameIdx Name, namespaceIdx Namespace) {
	r := getResourceId(resources.TypeCalicoNetworkSets, nameIdx, namespaceIdx)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- Calico GlobalNetworkPolicy access --
//

func (t *XrefCacheTester) GetGlobalNetworkPolicy(tierIdx Name, nameIdx Name) *xrefcache.CacheEntryNetworkPolicy {
	r, _ := getPolicyResourceId(resources.TypeCalicoGlobalNetworkPolicies, tierIdx, nameIdx, 0)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryNetworkPolicy)
}

func (t *XrefCacheTester) SetGlobalNetworkPolicy(tierIdx Name, nameIdx Name, s Selector, ingress, egress []apiv3.Rule, order *float64) resources.Resource {
	r, tier := getPolicyResourceId(resources.TypeCalicoGlobalNetworkPolicies, tierIdx, nameIdx, 0)
	types := []apiv3.PolicyType{}
	if ingress != nil {
		types = append(types, apiv3.PolicyTypeIngress)
	}
	if egress != nil {
		types = append(types, apiv3.PolicyTypeEgress)
	}
	res := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   r.TypeMeta,
		ObjectMeta: getObjectMeta(r, NoLabels),
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     tier,
			Order:    order,
			Selector: selectorByteToSelector(s),
			Ingress:  ingress,
			Egress:   egress,
			Types:    types,
		},
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource:   res,
	})
	return res
}

func (t *XrefCacheTester) DeleteGlobalNetworkPolicy(tierIdx Name, nameIdx Name) {
	r, _ := getPolicyResourceId(resources.TypeCalicoGlobalNetworkPolicies, tierIdx, nameIdx, 0)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- Calico StagedGlobalNetworkPolicy access --
//

func (t *XrefCacheTester) GetStagedGlobalNetworkPolicy(tierIdx Name, nameIdx Name) *xrefcache.CacheEntryNetworkPolicy {
	r, _ := getPolicyResourceId(resources.TypeCalicoStagedGlobalNetworkPolicies, tierIdx, nameIdx, 0)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryNetworkPolicy)
}

func (t *XrefCacheTester) SetStagedGlobalNetworkPolicy(
	tierIdx Name, nameIdx Name, s Selector, ingress, egress []apiv3.Rule, order *float64,
	stagedAction apiv3.StagedAction,
) resources.Resource {
	r, tier := getPolicyResourceId(resources.TypeCalicoStagedGlobalNetworkPolicies, tierIdx, nameIdx, 0)
	types := []apiv3.PolicyType{}
	if ingress != nil {
		types = append(types, apiv3.PolicyTypeIngress)
	}
	if egress != nil {
		types = append(types, apiv3.PolicyTypeEgress)
	}
	res := &apiv3.StagedGlobalNetworkPolicy{
		TypeMeta:   r.TypeMeta,
		ObjectMeta: getObjectMeta(r, NoLabels),
		Spec: apiv3.StagedGlobalNetworkPolicySpec{
			StagedAction: stagedAction,
			Tier:         tier,
			Order:        order,
			Selector:     selectorByteToSelector(s),
			Ingress:      ingress,
			Egress:       egress,
			Types:        types,
		},
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource:   res,
	})
	return res
}

func (t *XrefCacheTester) DeleteStagedGlobalNetworkPolicy(tierIdx Name, nameIdx Name) {
	r, _ := getPolicyResourceId(resources.TypeCalicoStagedGlobalNetworkPolicies, tierIdx, nameIdx, 0)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- Calico NetworkPolicy access --
//

func (t *XrefCacheTester) GetNetworkPolicy(tierIdx Name, nameIdx Name, namespaceIdx Namespace) *xrefcache.CacheEntryNetworkPolicy {
	r, _ := getPolicyResourceId(resources.TypeCalicoNetworkPolicies, tierIdx, nameIdx, namespaceIdx)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryNetworkPolicy)
}

func (t *XrefCacheTester) SetNetworkPolicy(tierIdx Name, nameIdx Name, namespaceIdx Namespace, s Selector, ingress, egress []apiv3.Rule, order *float64) resources.Resource {
	r, tier := getPolicyResourceId(resources.TypeCalicoNetworkPolicies, tierIdx, nameIdx, namespaceIdx)
	types := []apiv3.PolicyType{}
	if ingress != nil {
		types = append(types, apiv3.PolicyTypeIngress)
	}
	if egress != nil {
		types = append(types, apiv3.PolicyTypeEgress)
	}
	res := &apiv3.NetworkPolicy{
		TypeMeta:   r.TypeMeta,
		ObjectMeta: getObjectMeta(r, NoLabels),
		Spec: apiv3.NetworkPolicySpec{
			Tier:     tier,
			Order:    order,
			Selector: selectorByteToSelector(s),
			Ingress:  ingress,
			Egress:   egress,
			Types:    types,
		},
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource:   res,
	})
	return res
}

func (t *XrefCacheTester) DeleteNetworkPolicy(tierIdx Name, nameIdx Name, namespaceIdx Namespace) {
	r, _ := getPolicyResourceId(resources.TypeCalicoNetworkPolicies, tierIdx, nameIdx, namespaceIdx)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- Calico StagedNetworkPolicy access --
//

func (t *XrefCacheTester) GetStagedNetworkPolicy(tierIdx Name, nameIdx Name, namespaceIdx Namespace) *xrefcache.CacheEntryNetworkPolicy {
	r, _ := getPolicyResourceId(resources.TypeCalicoStagedNetworkPolicies, tierIdx, nameIdx, namespaceIdx)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryNetworkPolicy)
}

func (t *XrefCacheTester) SetStagedNetworkPolicy(
	tierIdx Name, nameIdx Name, namespaceIdx Namespace, s Selector, ingress, egress []apiv3.Rule, order *float64,
	stagedAction apiv3.StagedAction,
) resources.Resource {
	r, tier := getPolicyResourceId(resources.TypeCalicoStagedNetworkPolicies, tierIdx, nameIdx, namespaceIdx)
	types := []apiv3.PolicyType{}
	if ingress != nil {
		types = append(types, apiv3.PolicyTypeIngress)
	}
	if egress != nil {
		types = append(types, apiv3.PolicyTypeEgress)
	}
	res := &apiv3.StagedNetworkPolicy{
		TypeMeta:   r.TypeMeta,
		ObjectMeta: getObjectMeta(r, NoLabels),
		Spec: apiv3.StagedNetworkPolicySpec{
			StagedAction: stagedAction,
			Tier:         tier,
			Order:        order,
			Selector:     selectorByteToSelector(s),
			Ingress:      ingress,
			Egress:       egress,
			Types:        types,
		},
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource:   res,
	})
	return res
}

func (t *XrefCacheTester) DeleteStagedNetworkPolicy(tierIdx Name, nameIdx Name, namespaceIdx Namespace) {
	r, _ := getPolicyResourceId(resources.TypeCalicoStagedNetworkPolicies, tierIdx, nameIdx, namespaceIdx)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- K8s NetworkPolicy access --
//

func (t *XrefCacheTester) GetK8sNetworkPolicy(nameIdx Name, namespaceIdx Namespace) *xrefcache.CacheEntryNetworkPolicy {
	r := getResourceId(resources.TypeK8sNetworkPolicies, nameIdx, namespaceIdx)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryNetworkPolicy)
}

func (t *XrefCacheTester) SetK8sNetworkPolicy(
	nameIdx Name, namespaceIdx Namespace, s Selector,
	ingress []networkingv1.NetworkPolicyIngressRule,
	egress []networkingv1.NetworkPolicyEgressRule,
) resources.Resource {
	r := getResourceId(resources.TypeK8sNetworkPolicies, nameIdx, namespaceIdx)
	types := []networkingv1.PolicyType{}
	if ingress != nil {
		types = append(types, networkingv1.PolicyTypeIngress)
	}
	if egress != nil {
		types = append(types, networkingv1.PolicyTypeEgress)
	}
	res := &networkingv1.NetworkPolicy{
		TypeMeta:   r.TypeMeta,
		ObjectMeta: getObjectMeta(r, NoLabels),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: *selectorByteToK8sSelector(s),
			PolicyTypes: types,
			Ingress:     ingress,
			Egress:      egress,
		},
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource:   res,
	})
	return res
}

func (t *XrefCacheTester) DeleteK8sNetworkPolicy(nameIdx Name, namespaceIdx Namespace) {
	r := getResourceId(resources.TypeK8sNetworkPolicies, nameIdx, namespaceIdx)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- Calico StagedKubernetesNetworkPolicy access --
//

func (t *XrefCacheTester) GetStagedKubernetesNetworkPolicy(nameIdx Name, namespaceIdx Namespace) *xrefcache.CacheEntryNetworkPolicy {
	r := getResourceId(resources.TypeCalicoStagedKubernetesNetworkPolicies, nameIdx, namespaceIdx)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryNetworkPolicy)
}

func (t *XrefCacheTester) SetStagedKubernetesNetworkPolicy(
	nameIdx Name, namespaceIdx Namespace, s Selector,
	ingress []networkingv1.NetworkPolicyIngressRule,
	egress []networkingv1.NetworkPolicyEgressRule,
	stagedAction apiv3.StagedAction,
) resources.Resource {
	r := getResourceId(resources.TypeCalicoStagedKubernetesNetworkPolicies, nameIdx, namespaceIdx)
	types := []networkingv1.PolicyType{}
	if ingress != nil {
		types = append(types, networkingv1.PolicyTypeIngress)
	}
	if egress != nil {
		types = append(types, networkingv1.PolicyTypeEgress)
	}
	res := &apiv3.StagedKubernetesNetworkPolicy{
		TypeMeta:   r.TypeMeta,
		ObjectMeta: getObjectMeta(r, NoLabels),
		Spec: apiv3.StagedKubernetesNetworkPolicySpec{
			StagedAction: stagedAction,
			PodSelector:  *selectorByteToK8sSelector(s),
			PolicyTypes:  types,
			Ingress:      ingress,
			Egress:       egress,
		},
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource:   res,
	})
	return res
}

func (t *XrefCacheTester) DeleteStagedKubernetesNetworkPolicy(nameIdx Name, namespaceIdx Namespace) {
	r := getResourceId(resources.TypeCalicoStagedKubernetesNetworkPolicies, nameIdx, namespaceIdx)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- K8s Pod access --
//

func (t *XrefCacheTester) GetPod(nameIdx Name, namespaceIdx Namespace) *xrefcache.CacheEntryEndpoint {
	r := getResourceId(resources.TypeK8sPods, nameIdx, namespaceIdx)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryEndpoint)
}

func (t *XrefCacheTester) SetPod(nameIdx Name, namespaceIdx Namespace, labels TestLabel, ip IP, serviceAccount Name, opts PodOpt) resources.Resource {
	r := getResourceId(resources.TypeK8sPods, nameIdx, namespaceIdx)
	var sa string
	if serviceAccount != 0 {
		sr := getResourceId(resources.TypeK8sServiceAccounts, serviceAccount, namespaceIdx)
		sa = sr.Name
	}
	var initContainers, containers []corev1.Container
	meta := getObjectMeta(r, labels)
	if opts&PodOptEnvoyEnabled != 0 {
		// Set annotations for Envoy (this example was from a real system)
		meta.Annotations = map[string]string{
			"sidecar.istio.io/status": "{\"version\":\"99f7794ab7b49c473191a9b99fb394a24a1bd94be1602549ab75085af3fd34a6\"," +
				"\"initContainers\":[\"istio-init\"],\"containers\":[\"istio-proxy\"]," +
				"\"volumes\":[\"istio-envoy\",\"istio-certs\"],\"imagePullSecrets\":null}",
		}
		initContainers = append(initContainers, corev1.Container{
			Image: "docker.io/istio/proxy_init:1.0.7",
		})
		containers = append(containers, corev1.Container{
			Image: "docker.io/istio/proxyv2:1.0.7",
		})
	}
	if opts&PodOptSetGenerateName != 0 {
		meta.GenerateName = "pod-"
	}
	res := &corev1.Pod{
		TypeMeta:   r.TypeMeta,
		ObjectMeta: meta,
		Spec: corev1.PodSpec{
			NodeName:           "node1",
			ServiceAccountName: sa,
			InitContainers:     initContainers,
			Containers:         containers,
		},
		Status: corev1.PodStatus{
			PodIP: ipByteToIPString(ip),
		},
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource:   res,
	})
	return res
}

func (t *XrefCacheTester) DeletePod(nameIdx Name, namespaceIdx Namespace) {
	r := getResourceId(resources.TypeK8sPods, nameIdx, namespaceIdx)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- K8s Endpoints access --
//

func (t *XrefCacheTester) GetEndpoints(nameIdx Name, namespaceIdx Namespace) *xrefcache.CacheEntryServiceEndpoints {
	r := getResourceId(resources.TypeK8sEndpoints, nameIdx, namespaceIdx)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryServiceEndpoints)
}

func (t *XrefCacheTester) SetEndpoints(nameIdx Name, namespaceIdx Namespace, ips IP, pods ...apiv3.ResourceID) resources.Resource {
	r := getResourceId(resources.TypeK8sEndpoints, nameIdx, namespaceIdx)
	ipAddrs := ipByteToIPStringSlice(ips)

	// Convert the IP addresses to endpoint subsets, splitting over multiple if there is more than a single address.
	ss := []corev1.EndpointSubset{} //nolint:staticcheck
	if len(ipAddrs) > 1 {
		ss = append(ss, corev1.EndpointSubset{ //nolint:staticcheck
			Addresses: []corev1.EndpointAddress{{ //nolint:staticcheck
				IP: ipAddrs[0],
			}},
		})
		ipAddrs = ipAddrs[1:]
	}
	addrs := []corev1.EndpointAddress{} //nolint:staticcheck
	for _, ip := range ipAddrs {
		addrs = append(addrs, corev1.EndpointAddress{ //nolint:staticcheck
			IP: ip,
		})
	}
	ss = append(ss, corev1.EndpointSubset{ //nolint:staticcheck
		Addresses: addrs,
	})
	if len(pods) > 0 {
		addrs := []corev1.EndpointAddress{} //nolint:staticcheck
		for _, pod := range pods {
			addrs = append(addrs, corev1.EndpointAddress{ //nolint:staticcheck
				IP: "0.0.0.0",
				TargetRef: &corev1.ObjectReference{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				},
			})
		}
		ss = append(ss, corev1.EndpointSubset{ //nolint:staticcheck
			Addresses: addrs,
		})
	}

	res := &corev1.Endpoints{ //nolint:staticcheck
		TypeMeta:   r.TypeMeta,
		ObjectMeta: getObjectMeta(r, NoLabels),
		Subsets:    ss,
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource:   res,
	})
	return res
}

func (t *XrefCacheTester) DeleteEndpoints(nameIdx Name, namespaceIdx Namespace) {
	r := getResourceId(resources.TypeK8sEndpoints, nameIdx, namespaceIdx)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- K8s ServiceAccounts access --
//

func (t *XrefCacheTester) GetServiceAccount(nameIdx Name, namespaceIdx Namespace) *xrefcache.CacheEntryServiceAccount {
	r := getResourceId(resources.TypeK8sServiceAccounts, nameIdx, namespaceIdx)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryServiceAccount)
}

func (t *XrefCacheTester) SetServiceAccount(nameIdx Name, namespaceIdx Namespace, labels TestLabel) resources.Resource {
	r := getResourceId(resources.TypeK8sServiceAccounts, nameIdx, namespaceIdx)
	res := &corev1.ServiceAccount{
		TypeMeta:   r.TypeMeta,
		ObjectMeta: getObjectMeta(r, labels),
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource:   res,
	})
	return res
}

func (t *XrefCacheTester) DeleteServiceAccount(nameIdx Name, namespaceIdx Namespace) {
	r := getResourceId(resources.TypeK8sServiceAccounts, nameIdx, namespaceIdx)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- K8s Namespaces access --
//

func (t *XrefCacheTester) GetNamespace(namespaceIdx Namespace) *xrefcache.CacheEntryNamespace {
	r := getResourceId(resources.TypeK8sNamespaces, 0, namespaceIdx)
	e := t.Get(r)
	if e == nil {
		return nil
	}
	return e.(*xrefcache.CacheEntryNamespace)
}

func (t *XrefCacheTester) SetNamespace(namespaceIdx Namespace, labels TestLabel) resources.Resource {
	r := getResourceId(resources.TypeK8sNamespaces, 0, namespaceIdx)
	res := &corev1.Namespace{
		TypeMeta:   r.TypeMeta,
		ObjectMeta: getObjectMeta(r, labels),
	}
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: r,
		Resource:   res,
	})
	return res
}

func (t *XrefCacheTester) DeleteNamespace(namespaceIdx Namespace) {
	r := getResourceId(resources.TypeK8sNamespaces, 0, namespaceIdx)
	t.OnUpdate(syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: r,
	})
}

//
// -- K8s rule selector pseudo resource access --
//

func (t *XrefCacheTester) GetCachedRuleSelectors() []string {
	ids := t.GetCachedResourceIDs(xrefcache.KindSelector)
	selectors := make([]string, len(ids))
	for i := range ids {
		selectors[i] = ids[i].Name
	}
	return selectors
}

func (t *XrefCacheTester) GetGNPRuleSelectorCacheEntry(sel Selector, nsSel Selector) *xrefcache.CacheEntryNetworkPolicyRuleSelector {
	s := selectorByteToSelector(sel)
	if nsSel != NoNamespaceSelector {
		s = fmt.Sprintf("(%s) && (%s)", selectorByteToNamespaceSelector(nsSel), s)
	}
	entry := t.Get(apiv3.ResourceID{
		TypeMeta: xrefcache.KindSelector,
		Name:     s,
	})
	if entry == nil {
		return nil
	}
	return entry.(*xrefcache.CacheEntryNetworkPolicyRuleSelector)
}
