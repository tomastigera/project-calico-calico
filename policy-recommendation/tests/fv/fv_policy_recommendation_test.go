// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package fv

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalico "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	"github.com/tigera/api/pkg/lib/numorstring"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeK8s "k8s.io/client-go/kubernetes/fake"

	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	calres "github.com/projectcalico/calico/policy-recommendation/pkg/calico-resources"
	rscontroller "github.com/projectcalico/calico/policy-recommendation/pkg/controllers/recommendation_scope"
	tdata "github.com/projectcalico/calico/policy-recommendation/tests/data"
)

type policy struct {
	namespace string
	isStable  bool
	ingress   []rule
	egress    []rule
}

type rule struct {
	action                v3.Action
	protocol              numorstring.Protocol
	destPorts             []numorstring.Port
	destDomains           []string
	srcNamespaceSelector  string
	destNamespaceSelector string
}

func TestPolicyRecommendationEnable(t *testing.T) {
	// Description:
	// In this case, the recommendation engine will create staged network policies for the
	// namespaces "namespace1" and "namespace2". We have defined mock flows that will be used to
	// generate an egress rule for "namespace1" and an ingress rule for "namespace2".

	RegisterTestingT(t)

	ctx := context.Background()

	// Setup mock resources
	mockClientSet, mockLinseedClient := getMockResources(ctx)

	interval := metav1.Duration{Duration: 1 * time.Second}
	stabilization := metav1.Duration{Duration: 1 * time.Second}
	status := v3.PolicyRecommendationScopeEnabled
	selector := ""

	// Enable policy recommendation
	scope := getPolicyRecommendationScope(status, selector, interval, stabilization)
	Eventually(func() error {
		prs, err := mockClientSet.ProjectcalicoV3().PolicyRecommendationScopes().Create(
			ctx, scope, metav1.CreateOptions{},
		)

		if err != nil &&
			*prs.Spec.Interval != interval &&
			*prs.Spec.StabilizationPeriod != stabilization &&
			prs.Spec.NamespaceSpec.RecStatus != status &&
			prs.Spec.NamespaceSpec.Selector != selector {
			return fmt.Errorf("policy recommendation scope not created")
		}
		return nil
	}, 500*time.Microsecond).Should(Succeed())

	// Create namespaces to recommend policies for
	Eventually(func() error {
		ns, err := mockClientSet.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "namespace1"},
		}, metav1.CreateOptions{})
		if err != nil && ns.Name != "namespace1" {
			return fmt.Errorf("namespace not created")
		}
		return nil
	}, 500*time.Millisecond).Should(Succeed())
	Eventually(func() error {
		ns, err := mockClientSet.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "namespace2"},
		}, metav1.CreateOptions{})
		if err != nil && ns.Name != "namespace2" {
			return fmt.Errorf("namespace not created")
		}
		return nil
	}, 500*time.Millisecond).Should(Succeed())

	// Start policy recommendation
	minPollInterval := metav1.Duration{Duration: 500 * time.Millisecond}
	rctrl, err := rscontroller.NewRecommendationScopeController(ctx, lmak8s.DefaultCluster,
		mockClientSet, mockLinseedClient, minPollInterval, rscontroller.WatcherConfig{WatchScope: true})
	Expect(err).NotTo(HaveOccurred())

	stopChan := make(chan struct{})
	go rctrl.Run(stopChan)

	// Define expected rules for the recommendations (staged network policy)
	expectedPolicies := map[string]policy{
		"namespace1": {
			namespace: "namespace1",
			egress: []rule{
				{
					action:                v3.Allow,
					protocol:              numorstring.ProtocolFromString("tcp"),
					destPorts:             []numorstring.Port{{MinPort: 80, MaxPort: 80}},
					destNamespaceSelector: "projectcalico.org/name == 'namespace2'",
				},
			},
		},
		"namespace2": {

			namespace: "namespace2",
			ingress: []rule{
				{
					action:               v3.Allow,
					protocol:             numorstring.ProtocolFromString("tcp"),
					destPorts:            []numorstring.Port{{MinPort: 80, MaxPort: 80}},
					srcNamespaceSelector: "projectcalico.org/name == 'namespace1'",
				},
			},
		},
	}

	// Verify the recommendations (staged network policies)
	Eventually(func() error {
		items, err := mockClientSet.ProjectcalicoV3().StagedNetworkPolicies(v3.AllNamespaces).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("staged network policy not created")
		}
		if len(items.Items) != len(expectedPolicies) {
			return fmt.Errorf("expected %d staged network policies, got %d", len(expectedPolicies), len(items.Items))
		}
		for _, snp := range items.Items {
			if err := validateStagedNetworkPolicy(snp, snp.Namespace, expectedPolicies[snp.Namespace]); err != nil {
				return err
			}
		}
		// All policies validated successfully
		return nil
	}, 3*time.Second, 50*time.Millisecond).Should(Succeed())

	// Stop the recommendation controller
	close(stopChan)
}

func TestPolicyRecommendationSelector(t *testing.T) {
	// Description:
	// In this case, only namespace1 should have a recommendation since namespace2 is excluded
	// by the selector. The recommendation engine will create staged network policies for the
	// namespaces "namespace1". We have defined mock flows that will be used to generate an egress
	// rule for "namespace1".

	RegisterTestingT(t)

	ctx := context.Background()

	// Setup mock resources
	mockClientSet, mockLinseedClient := getMockResources(ctx)

	interval := metav1.Duration{Duration: 1 * time.Second}
	stabilization := metav1.Duration{Duration: 10 * time.Second}
	status := v3.PolicyRecommendationScopeEnabled
	selector := "!(projectcalico.org/name == 'namespace2')"

	// Enable policy recommendation
	scope := getPolicyRecommendationScope(status, selector, interval, stabilization)
	Eventually(func() error {
		prs, err := mockClientSet.ProjectcalicoV3().PolicyRecommendationScopes().Create(
			ctx, scope, metav1.CreateOptions{},
		)

		if err != nil &&
			*prs.Spec.Interval != interval &&
			*prs.Spec.StabilizationPeriod != stabilization &&
			prs.Spec.NamespaceSpec.RecStatus != status &&
			prs.Spec.NamespaceSpec.Selector != selector {
			return fmt.Errorf("policy recommendation scope not created")
		}
		return nil
	}, 500*time.Microsecond).Should(Succeed())

	// Create namespaces to recommend policies for
	Eventually(func() error {
		ns, err := mockClientSet.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "namespace1"},
		}, metav1.CreateOptions{})
		if err != nil && ns.Name != "namespace1" {
			return fmt.Errorf("namespace not created")
		}
		return nil
	}, 500*time.Millisecond).Should(Succeed())
	Eventually(func() error {
		ns, err := mockClientSet.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "namespace2"},
		}, metav1.CreateOptions{})
		if err != nil && ns.Name != "namespace2" {
			return fmt.Errorf("namespace not created")
		}
		return nil
	}, 500*time.Millisecond).Should(Succeed())

	// Start policy recommendation
	minPollInterval := metav1.Duration{Duration: 500 * time.Millisecond}
	rctrl, err := rscontroller.NewRecommendationScopeController(ctx, lmak8s.DefaultCluster,
		mockClientSet, mockLinseedClient, minPollInterval, rscontroller.WatcherConfig{WatchScope: true})
	Expect(err).NotTo(HaveOccurred())

	stopChan := make(chan struct{})
	go rctrl.Run(stopChan)

	// Define expected rules for the recommendation (staged network policy)
	expectedPolicies := map[string]policy{
		"namespace1": {
			namespace: "namespace1",
			egress: []rule{
				{
					action:                v3.Allow,
					protocol:              numorstring.ProtocolFromString("tcp"),
					destPorts:             []numorstring.Port{{MinPort: 80, MaxPort: 80}},
					destNamespaceSelector: "projectcalico.org/name == 'namespace2'",
				},
			},
		},
	}

	// Verify the recommendations (staged network policies)
	Eventually(func() error {
		items, err := mockClientSet.ProjectcalicoV3().StagedNetworkPolicies(v3.AllNamespaces).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("staged network policy not created")
		}
		if len(items.Items) != len(expectedPolicies) {
			return fmt.Errorf("expected %d staged network policies, got %d", len(expectedPolicies), len(items.Items))
		}
		for _, snp := range items.Items {
			if err := validateStagedNetworkPolicy(snp, snp.Namespace, expectedPolicies[snp.Namespace]); err != nil {
				return err
			}
		}
		// All policies validated successfully
		return nil
	}, 3*time.Second, 50*time.Millisecond).Should(Succeed())

	// Stop the recommendation controller
	close(stopChan)
}

func TestPolicyRecommendationStabilization(t *testing.T) {
	// Description:
	// In this case, the recommendation engine will create staged network policies for the
	// namespaces "namespace1" and "namespace2". We have defined mock flows that will be used to
	// generate an egress rule for "namespace1" and an ingress rule for "namespace2". Both
	// recommendations will be marked as stable within the expected stabilization period.

	RegisterTestingT(t)

	ctx := context.Background()

	// Setup mock resources
	mockClientSet, mockLinseedClient := getMockResources(ctx)

	interval := metav1.Duration{Duration: 1 * time.Second}
	stabilization := metav1.Duration{Duration: 1 * time.Second}
	status := v3.PolicyRecommendationScopeEnabled
	selector := ""

	// Enable policy recommendation
	scope := getPolicyRecommendationScope(status, selector, interval, stabilization)
	Eventually(func() error {
		prs, err := mockClientSet.ProjectcalicoV3().PolicyRecommendationScopes().Create(
			ctx, scope, metav1.CreateOptions{},
		)

		if err != nil &&
			*prs.Spec.Interval != interval &&
			*prs.Spec.StabilizationPeriod != stabilization &&
			prs.Spec.NamespaceSpec.RecStatus != status &&
			prs.Spec.NamespaceSpec.Selector != selector {
			return fmt.Errorf("policy recommendation scope not created")
		}
		return nil
	}, 500*time.Microsecond).Should(Succeed())

	// Create namespaces to recommend policies for
	Eventually(func() error {
		ns, err := mockClientSet.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "namespace1"},
		}, metav1.CreateOptions{})
		if err != nil && ns.Name != "namespace1" {
			return fmt.Errorf("namespace not created")
		}
		return nil
	}, 500*time.Millisecond).Should(Succeed())
	Eventually(func() error {
		ns, err := mockClientSet.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "namespace2"},
		}, metav1.CreateOptions{})
		if err != nil && ns.Name != "namespace2" {
			return fmt.Errorf("namespace not created")
		}
		return nil
	}, 500*time.Millisecond).Should(Succeed())

	// Start policy recommendation
	minPollInterval := metav1.Duration{Duration: 500 * time.Millisecond}
	rctrl, err := rscontroller.NewRecommendationScopeController(ctx, lmak8s.DefaultCluster,
		mockClientSet, mockLinseedClient, minPollInterval, rscontroller.WatcherConfig{WatchScope: true})
	Expect(err).NotTo(HaveOccurred())

	stopChan := make(chan struct{})
	go rctrl.Run(stopChan)

	// Define expected rules for the recommendations (staged network policy)
	expectedPolicies := map[string]policy{
		"namespace1": {
			namespace: "namespace1",
			isStable:  true,
			egress: []rule{
				{
					action:                v3.Allow,
					protocol:              numorstring.ProtocolFromString("tcp"),
					destPorts:             []numorstring.Port{{MinPort: 80, MaxPort: 80}},
					destNamespaceSelector: "projectcalico.org/name == 'namespace2'",
				},
			},
		},
		"namespace2": {

			namespace: "namespace2",
			isStable:  true,
			ingress: []rule{
				{
					action:               v3.Allow,
					protocol:             numorstring.ProtocolFromString("tcp"),
					destPorts:            []numorstring.Port{{MinPort: 80, MaxPort: 80}},
					srcNamespaceSelector: "projectcalico.org/name == 'namespace1'",
				},
			},
		},
	}

	// Verify the recommendations (staged network policies)
	Eventually(func() error {
		items, err := mockClientSet.ProjectcalicoV3().StagedNetworkPolicies(v3.AllNamespaces).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("staged network policy not created")
		}
		if len(items.Items) != len(expectedPolicies) {
			return fmt.Errorf("expected %d staged network policies, got %d", len(expectedPolicies), len(items.Items))
		}
		for _, snp := range items.Items {
			if err := validateStagedNetworkPolicy(snp, snp.Namespace, expectedPolicies[snp.Namespace]); err != nil {
				return err
			}
		}
		// All policies validated successfully
		return nil
	}, 3*time.Second, 50*time.Millisecond).Should(Succeed())

	// Stop the recommendation controller
	close(stopChan)
}

// getPolicyRecommendationScope returns a policy recommendation scope with the given status,
// selector, interval, and stabilization period.
func getPolicyRecommendationScope(
	status v3.PolicyRecommendationNamespaceStatus,
	selector string,
	interval metav1.Duration,
	stabilization metav1.Duration,
) *v3.PolicyRecommendationScope {
	return &v3.PolicyRecommendationScope{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: v3.PolicyRecommendationScopeSpec{
			Interval:            &interval,
			StabilizationPeriod: &stabilization,
			NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
				RecStatus: status,
				Selector:  selector,
			},
		},
	}
}

// getMockResources returns a mock client set and linseed client for testing
func getMockResources(ctx context.Context) (*lmak8s.MockClientSet, lsclient.MockClient) {
	fakeClient := fakecalico.NewSimpleClientset()
	fakeCoreV1 := fakeK8s.NewSimpleClientset().CoreV1()

	// Simplify mock creation with a single mock struct
	mockClientSet := lmak8s.NewMockClientSet(simpleMockT{})
	mockClientSet.On("ProjectcalicoV3").Return(fakeClient.ProjectcalicoV3())
	mockClientSet.On("CoreV1").Return(fakeCoreV1)
	mockClientSet.On("RESTClient").Return(fakeClient.ProjectcalicoV3().RESTClient())

	mockLinseedClient := lsclient.NewMockClient("")
	mockLinseedClient.SetResults(tdata.MockPolicyRecFlows1...)

	return mockClientSet, mockLinseedClient
}

// validateStagedNetworkPolicy performs validation on a staged network policy
func validateStagedNetworkPolicy(policy v3.StagedNetworkPolicy, expectedNamespace string, expectedPolicy policy) error {
	// Validate the policy namespace
	if policy.Namespace != expectedNamespace {
		return fmt.Errorf("expected policy in %s, got %s", expectedNamespace, policy.Namespace)
	}
	if expectedPolicy.isStable && policy.Annotations[calres.StatusKey] != calres.StableStatus {
		return fmt.Errorf("expected policy to be stable, got %s", policy.Annotations[calres.StatusKey])
	}
	// Validate basic egress rule structure and actions
	if err := validateEgressRules(policy, expectedPolicy.egress); err != nil {
		return err
	}
	// Validate basic ingress rule structure and actions
	if err := validateIngressRules(policy, expectedPolicy.ingress); err != nil {
		return err
	}

	return nil
}

// validateEgressRules validates the egress rules of a staged network policy
func validateEgressRules(policy v3.StagedNetworkPolicy, expectedRules []rule) error {
	if len(policy.Spec.Egress) != len(expectedRules) {
		return fmt.Errorf("expected %d egress rules, got %d", len(expectedRules), len(policy.Spec.Egress))
	}

	for i, rule := range policy.Spec.Egress {
		if rule.Action != expectedRules[i].action {
			return fmt.Errorf("expected egress rule %d to have action %v, got %s", i, expectedRules[i].action, rule.Action)
		}
		if rule.Protocol.StrVal != expectedRules[i].protocol.StrVal {
			return fmt.Errorf("expected egress rule %d to have protocol %s, got %s", i, expectedRules[i].protocol.StrVal, rule.Protocol)
		}
		if rule.Destination.NamespaceSelector != expectedRules[i].destNamespaceSelector {
			return fmt.Errorf("expected egress rule %d to have namespace selector %s, got %s", i, expectedRules[i].destNamespaceSelector, rule.Destination.NamespaceSelector)
		}
		if !reflect.DeepEqual(rule.Destination.Ports, expectedRules[i].destPorts) {
			return fmt.Errorf("expected egress rule %d to have ports: %v, got %v", i, expectedRules[i].destPorts, rule.Destination.Ports)
		}
		if len(rule.Destination.Domains) != len(expectedRules[i].destDomains) {
			return fmt.Errorf("expected egress rule %d to have %d domains, got %d", i, len(expectedRules[i].destDomains), len(rule.Destination.Domains))
		}
		for j, domain := range rule.Destination.Domains {
			if domain != expectedRules[i].destDomains[j] {
				return fmt.Errorf("expected egress rule %d to have valid domain: %v, got %s", i, expectedRules[i].destDomains[j], domain)
			}
		}
	}
	return nil
}

// validateIngressRules validates the ingress rules of a staged network policy
func validateIngressRules(policy v3.StagedNetworkPolicy, expectedRules []rule) error {
	if len(policy.Spec.Ingress) != len(expectedRules) {
		return fmt.Errorf("expected %d ingress rules, got %d", len(expectedRules), len(policy.Spec.Ingress))
	}

	for i, rule := range policy.Spec.Ingress {
		if rule.Action != expectedRules[i].action {
			return fmt.Errorf("expected ingress rule %d to have action %v, got %s", i, expectedRules[i].action, rule.Action)
		}
		if rule.Protocol.StrVal != expectedRules[i].protocol.StrVal {
			return fmt.Errorf("expected ingress rule %d to have protocol %s, got %s", i, expectedRules[i].protocol.StrVal, rule.Protocol)
		}
		if rule.Source.NamespaceSelector != expectedRules[i].srcNamespaceSelector {
			return fmt.Errorf("expected ingress rule %d to have namespace selector %s, got %s", i, expectedRules[i].srcNamespaceSelector, rule.Source.NamespaceSelector)
		}
		if !reflect.DeepEqual(rule.Destination.Ports, expectedRules[i].destPorts) {
			return fmt.Errorf("expected ingress rule %d to have ports: %v, got %v", i, expectedRules[i].destPorts, rule.Destination.Ports)
		}
	}
	return nil
}

// Simplified mock interface implementation
type simpleMockT struct{}

func (m simpleMockT) Cleanup(func())                            {}
func (m simpleMockT) Logf(format string, args ...interface{})   {}
func (m simpleMockT) Errorf(format string, args ...interface{}) {}
func (m simpleMockT) FailNow()                                  {}
