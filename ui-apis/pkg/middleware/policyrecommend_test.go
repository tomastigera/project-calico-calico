// Copyright (c) 2019, 2022 Tigera, Inc. All rights reserved.
package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientsetfake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	"github.com/tigera/api/pkg/lib/numorstring"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	fakeK8s "k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/projectcalico/calico/lma/pkg/api"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	lmapolicyrec "github.com/projectcalico/calico/lma/pkg/policyrec"
)

const recommendURLPath = "/recommend"

// Given a source reported flow from deployment app1 to endpoint nginx on port 80,
// the engine should return a policy selecting app1 to nginx, to port 80.
var (
	destPort       = uint16(80)
	destPortInRule = numorstring.SinglePort(destPort)

	protoInRule = numorstring.ProtocolFromString("TCP")

	app1Dep = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app1",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "app1",
			},
		},
	}
	app1Rs = &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			Kind: "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app1-abcdef",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "app1",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "app1",
				},
			},
		},
	}

	app2Dep = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app2",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "app2",
			},
		},
	}
	app2Rs = &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			Kind: "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app2-abcdef",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "app2",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "app2",
				},
			},
		},
	}

	app3Dep = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app3",
			Namespace: "namespace2",
			Labels: map[string]string{
				"app": "app3",
			},
		},
	}
	app3Rs = &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			Kind: "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app3-abcdef",
			Namespace: "namespace2",
			Labels: map[string]string{
				"app": "app3",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "app3",
				},
			},
		},
	}

	nginxDep = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "nginx",
			},
		},
	}
	nginxRs = &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			Kind: "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-12345",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "app1",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "nginx",
				},
			},
		},
	}

	nginx2Dep = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx2",
			Namespace: "namespace2",
			Labels: map[string]string{
				"app": "nginx",
			},
		},
	}
	nginx2Rs = &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			Kind: "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx2-12345",
			Namespace: "namespace2",
			Labels: map[string]string{
				"app": "app3",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "nginx2",
				},
			},
		},
	}

	nginx3Dep = &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx3",
			Namespace: "namespace2",
			Labels: map[string]string{
				"app": "nginx3",
			},
		},
	}
	nginx3Rs = &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			Kind: "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx3-12345",
			Namespace: "namespace2",
			Labels: map[string]string{
				"app": "app3",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "nginx3",
				},
			},
		},
	}
	namespace1Namespace = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
		},
	}
	namespace2Namespace = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
		},
	}

	app1Query = &lmapolicyrec.PolicyRecommendationParams{
		StartTime:    "now-1h",
		EndTime:      "now",
		EndpointName: "app1-abcdef-*",
		Namespace:    "namespace1",
	}

	nginxQuery = &lmapolicyrec.PolicyRecommendationParams{
		StartTime:    "now-1h",
		EndTime:      "now",
		EndpointName: "nginx-12345-*",
		Namespace:    "namespace1",
	}

	namespace1Query = &lmapolicyrec.PolicyRecommendationParams{
		StartTime:    "now-1h",
		EndTime:      "now",
		EndpointName: "",
		Namespace:    "namespace1",
	}

	namespace2Query = &lmapolicyrec.PolicyRecommendationParams{
		StartTime:    "now-1h",
		EndTime:      "now",
		EndpointName: "",
		Namespace:    "namespace2",
	}

	app1Policy = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default.app1",
			Namespace: "namespace1",
		},
		Spec: v3.StagedNetworkPolicySpec{
			StagedAction: v3.StagedActionSet,
			Tier:         "default",
			Types:        []v3.PolicyType{v3.PolicyTypeEgress},
			Selector:     "app == 'app1'",
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoInRule,
					Destination: v3.EntityRule{
						Selector: "app == 'nginx'",
						Ports:    []numorstring.Port{destPortInRule},
					},
				},
			},
		},
	}

	nginxPolicy = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default.nginx",
			Namespace: "namespace1",
		},
		Spec: v3.StagedNetworkPolicySpec{
			StagedAction: v3.StagedActionSet,
			Tier:         "default",
			Types:        []v3.PolicyType{v3.PolicyTypeIngress},
			Selector:     "app == 'nginx'",
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoInRule,
					Source: v3.EntityRule{
						Selector: "app == 'app1'",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{destPortInRule},
					},
				},
			},
		},
	}

	protoIPIP = numorstring.ProtocolFromString("ipip")
	protoTCP  = numorstring.ProtocolFromString("TCP")
	protoUDP  = numorstring.ProtocolFromString("UDP")

	namespace1Policy = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default.namespace1-policy",
			Namespace: "namespace1",
		},
		Spec: v3.StagedNetworkPolicySpec{
			StagedAction: v3.StagedActionSet,
			Tier:         "default",
			Types:        []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Selector:     "projectcalico.org/namespace == 'namespace1'",
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCP,
					Destination: v3.EntityRule{
						NamespaceSelector: "projectcalico.org/name == 'namespace1'",
						Ports:             []numorstring.Port{numorstring.SinglePort(8080)},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &protoTCP,
					Destination: v3.EntityRule{
						NamespaceSelector: "projectcalico.org/name == 'namespace2'",
						Ports:             []numorstring.Port{numorstring.SinglePort(80), numorstring.SinglePort(8091)},
					},
				},
			},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoIPIP,
					Source: v3.EntityRule{
						NamespaceSelector: "projectcalico.org/name == 'namespace2'",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(50)},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &protoUDP,
					Source: v3.EntityRule{
						NamespaceSelector: "projectcalico.org/name == 'namespace2'",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(40)},
					},
				},
			},
		},
	}

	namespace2Policy = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default.namespace2-policy",
			Namespace: "namespace2",
		},
		Spec: v3.StagedNetworkPolicySpec{
			StagedAction: v3.StagedActionSet,
			Tier:         "default",
			Types:        []v3.PolicyType{v3.PolicyTypeEgress},
			Selector:     "projectcalico.org/namespace == 'namespace2'",
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoUDP,
					Source:   v3.EntityRule{},
					Destination: v3.EntityRule{
						NamespaceSelector: "projectcalico.org/name == 'namespace1'",

						Ports: []numorstring.Port{numorstring.SinglePort(40)},
					},
				},
			},
			Ingress: nil,
		},
	}

	app1ToNginxFlows = []rest.MockResult{
		{
			Body: lapi.List[lapi.L3Flow]{
				Items: []lapi.L3Flow{
					// First flow.
					{
						Key: lapi.L3FlowKey{
							Source: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "app1-abcdef-*",
							},
							Destination: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "nginx-12345-*",
								Port:           80,
							},
							Protocol: "6",
							Reporter: lapi.FlowReporterSource,
							Action:   lapi.FlowActionAllow,
						},
						SourceLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "app1", Count: 1},
								},
							},
						},
						DestinationLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx", Count: 1},
								},
							},
						},
						Policies: []lapi.Policy{
							{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
						},
					},

					// Second flow.
					{
						Key: lapi.L3FlowKey{
							Source: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "app1-abcdef-*",
							},
							Destination: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "nginx-12345-*",
								Port:           80,
							},
							Protocol: "6",
							Reporter: lapi.FlowReporterDest,
							Action:   lapi.FlowActionAllow,
						},
						SourceLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "app1", Count: 1},
								},
							},
						},
						DestinationLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx", Count: 1},
								},
							},
						},
						Policies: []lapi.Policy{
							{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
						},
					},
				},
			},
		},
	}

	// Just the flow reported by the source on egress.
	app1ToNginxEgressFlows = []rest.MockResult{
		{
			Body: lapi.List[lapi.L3Flow]{
				Items: []lapi.L3Flow{
					// First flow - this is just the flow as reported by the source.
					{
						Key: lapi.L3FlowKey{
							Source: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "app1-abcdef-*",
							},
							Destination: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "nginx-12345-*",
								Port:           80,
							},
							Protocol: "6",
							Reporter: lapi.FlowReporterSource,
							Action:   lapi.FlowActionAllow,
						},
						SourceLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "app1", Count: 1},
								},
							},
						},
						DestinationLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx", Count: 1},
								},
							},
						},
						Policies: []lapi.Policy{
							{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
						},
					},
				},
			},
		},
	}

	flowsForNamespaceTest = []rest.MockResult{
		{
			Body: lapi.List[lapi.L3Flow]{
				Items: []lapi.L3Flow{
					// Flow-1
					{
						Key: lapi.L3FlowKey{
							Source: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "app1-abcdef-*",
							},
							Destination: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace2",
								AggregatedName: "nginx2-12345-*",
								Port:           80,
							},
							Protocol: "6",
							Reporter: lapi.FlowReporterSource,
							Action:   lapi.FlowActionAllow,
						},
						SourceLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "app1", Count: 1},
								},
							},
						},
						DestinationLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx2", Count: 1},
								},
							},
						},
						Policies: []lapi.Policy{
							{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
						},
					},

					// Flow-2
					{
						Key: lapi.L3FlowKey{
							Source: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "app2-abcdef-*",
							},
							Destination: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "nginx-12345-*",
								Port:           8080,
							},
							Protocol: "6",
							Reporter: lapi.FlowReporterSource,
							Action:   lapi.FlowActionAllow,
						},
						SourceLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "app2", Count: 1},
								},
							},
						},
						DestinationLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx", Count: 1},
								},
							},
						},
						Policies: []lapi.Policy{
							{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
						},
					},

					// Flow-3
					{
						Key: lapi.L3FlowKey{
							Source: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "app2-abcdef-*",
							},
							Destination: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "nginx-12345-*",
								Port:           8080,
							},
							Protocol: "6",
							Reporter: lapi.FlowReporterDest,
							Action:   lapi.FlowActionAllow,
						},
						SourceLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "app2", Count: 1},
								},
							},
						},
						DestinationLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx", Count: 1},
								},
							},
						},
						Policies: []lapi.Policy{
							{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
						},
					},

					// Flow-4
					{
						Key: lapi.L3FlowKey{
							Source: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace2",
								AggregatedName: "nginx3-12345-*",
							},
							Destination: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "nginx-12345-*",
								Port:           50,
							},
							Protocol: "4",
							Reporter: lapi.FlowReporterDest,
							Action:   lapi.FlowActionAllow,
						},
						SourceLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx3", Count: 1},
								},
							},
						},
						DestinationLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx", Count: 1},
								},
							},
						},
						Policies: []lapi.Policy{
							{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
						},
					},

					// Flow-5
					{
						Key: lapi.L3FlowKey{
							Source: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace2",
								AggregatedName: "app3-abcdef-*",
							},
							Destination: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "nginx-12345-*",
								Port:           40,
							},
							Protocol: "17",
							Reporter: lapi.FlowReporterSource,
							Action:   lapi.FlowActionAllow,
						},
						SourceLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "app3", Count: 1},
								},
							},
						},
						DestinationLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx", Count: 1},
								},
							},
						},
						Policies: []lapi.Policy{
							{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
						},
					},

					// Flow-6
					{
						Key: lapi.L3FlowKey{
							Source: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace2",
								AggregatedName: "app3-abcdef-*",
							},
							Destination: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "nginx-12345-*",
								Port:           40,
							},
							Protocol: "17",
							Reporter: lapi.FlowReporterDest,
							Action:   lapi.FlowActionAllow,
						},
						SourceLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "app3", Count: 1},
								},
							},
						},
						DestinationLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx", Count: 1},
								},
							},
						},
						Policies: []lapi.Policy{
							{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
						},
					},

					// Flow-7
					{
						Key: lapi.L3FlowKey{
							Source: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace1",
								AggregatedName: "nginx-12345-*",
							},
							Destination: lapi.Endpoint{
								Type:           lapi.WEP,
								Namespace:      "namespace2",
								AggregatedName: "nginx2-12345-*",
								Port:           8091,
							},
							Protocol: "6",
							Reporter: lapi.FlowReporterSource,
							Action:   lapi.FlowActionAllow,
						},
						SourceLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "app3", Count: 1},
								},
							},
						},
						DestinationLabels: []lapi.FlowLabels{
							{
								Key: "app",
								Values: []lapi.FlowLabelValue{
									{Value: "nginx", Count: 1},
								},
							},
						},
						Policies: []lapi.Policy{
							{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
						},
					},
				},
			},
		},
	}
)

var _ = Describe("Policy Recommendation", func() {
	var (
		lsc                client.MockClient
		mockRBACAuthorizer *lmaauth.MockRBACAuthorizer
	)

	BeforeEach(func() {
		lsc = client.NewMockClient("")
		mockRBACAuthorizer = new(lmaauth.MockRBACAuthorizer)
	})

	DescribeTable("Recommend policies for matching flows and endpoint",
		func(linseedResponses []rest.MockResult,
			query *lmapolicyrec.PolicyRecommendationParams,
			expectedResponse *PolicyRecommendationResponse,
			statusCode int,
		) {
			// Set the results in the client.
			lsc.SetResults(linseedResponses...)

			jsonQuery, err := json.Marshal(query)
			Expect(err).To(BeNil())
			req, err := http.NewRequest(http.MethodPost, recommendURLPath, bytes.NewBuffer(jsonQuery))
			Expect(err).To(BeNil())

			// The mock k8s client set, with test data.
			mockLmaK8sClientSet := lmak8s.MockClientSet{}
			mockLmaK8sClientSet.On("ProjectcalicoV3").Return(
				clientsetfake.NewClientset().ProjectcalicoV3(),
			)
			coreV1 := fakeK8s.NewClientset().CoreV1()
			_, err = coreV1.Namespaces().Create(req.Context(), namespace1Namespace, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = coreV1.Namespaces().Create(req.Context(), namespace2Namespace, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			appV1 := fakeK8s.NewClientset().AppsV1()
			_, err = appV1.Deployments(app1Dep.Namespace).Create(req.Context(), app1Dep, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = appV1.Deployments(app2Dep.Namespace).Create(req.Context(), app2Dep, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = appV1.Deployments(app3Dep.Namespace).Create(req.Context(), app3Dep, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = appV1.ReplicaSets(app1Rs.Namespace).Create(req.Context(), app1Rs, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = appV1.ReplicaSets(app2Rs.Namespace).Create(req.Context(), app2Rs, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = appV1.ReplicaSets(app3Rs.Namespace).Create(req.Context(), app3Rs, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			_, err = appV1.Deployments(nginxDep.Namespace).Create(req.Context(), nginxDep, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = appV1.Deployments(nginx2Dep.Namespace).Create(req.Context(), nginx2Dep, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = appV1.Deployments(nginx3Dep.Namespace).Create(req.Context(), nginx3Dep, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = appV1.ReplicaSets(nginxRs.Namespace).Create(req.Context(), nginxRs, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = appV1.ReplicaSets(nginx2Rs.Namespace).Create(req.Context(), nginx2Rs, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = appV1.ReplicaSets(nginx3Rs.Namespace).Create(req.Context(), nginx3Rs, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			batchV1 := fakeK8s.NewClientset().BatchV1()

			batchV1Beta1 := fakeK8s.NewClientset().BatchV1beta1()

			// Define the return methods called by this test.
			mockLmaK8sClientSet.On("CoreV1").Return(coreV1)
			mockLmaK8sClientSet.On("AppsV1").Return(appV1)
			mockLmaK8sClientSet.On("BatchV1").Return(batchV1)
			mockLmaK8sClientSet.On("BatchV1beta1").Return(batchV1Beta1)

			mockLmaK8sClientFactory := &lmak8s.MockClientSetFactory{}
			mockLmaK8sClientFactory.On("NewClientSetForApplication", "cluster").Return(&mockLmaK8sClientSet, nil)

			mockK8sClientFactory := new(datastore.MockClusterCtxK8sClientFactory)
			mockK8sClientFactory.On("RBACAuthorizerForCluster", mock.Anything).Return(mockRBACAuthorizer, nil)

			By("Initializing the engine") // Tempted to say "Start your engines!"
			hdlr := PolicyRecommendationHandler(mockLmaK8sClientFactory, mockK8sClientFactory, lsc)

			mockRBACAuthorizer.On("Authorize", mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

			// add a bogus user
			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{}))

			w := httptest.NewRecorder()
			hdlr.ServeHTTP(w, req)
			Expect(err).To(BeNil())

			if statusCode != http.StatusOK {
				Expect(w.Code).To(Equal(statusCode))
				recResponse, err := io.ReadAll(w.Body)
				Expect(err).NotTo(HaveOccurred())
				errorBody := &api.Error{}
				err = json.Unmarshal(recResponse, errorBody)
				Expect(err).To(BeNil())
				Expect(errorBody.Code).To(Equal(statusCode))
				Expect(errorBody.Feature).To(Equal(api.PolicyRec))
				return
			}

			recResponse, err := io.ReadAll(w.Body)
			Expect(err).NotTo(HaveOccurred())

			if len(expectedResponse.NetworkPolicies) == 0 && len(expectedResponse.GlobalNetworkPolicies) == 0 {
				Expect(len(recResponse)).To(Equal(0))
			} else {
				actualRec := &PolicyRecommendationResponse{}
				err = json.Unmarshal(recResponse, actualRec)
				Expect(err).To(BeNil())

				if expectedResponse == nil {
					Expect(actualRec).To(BeNil())
				} else {
					Expect(actualRec).ToNot(BeNil())
					Expect(actualRec).To(Equal(expectedResponse))
				}
			}
		},

		Entry("for source endpoint",
			app1ToNginxFlows,
			app1Query,
			&PolicyRecommendationResponse{
				Recommendation: &lmapolicyrec.Recommendation{
					NetworkPolicies: []*v3.StagedNetworkPolicy{
						app1Policy,
					},
					GlobalNetworkPolicies: []*v3.StagedGlobalNetworkPolicy{},
				},
			},
			http.StatusOK,
		),

		Entry("for destination endpoint",
			app1ToNginxFlows,
			nginxQuery,
			&PolicyRecommendationResponse{
				Recommendation: &lmapolicyrec.Recommendation{
					NetworkPolicies: []*v3.StagedNetworkPolicy{
						nginxPolicy,
					},
					GlobalNetworkPolicies: []*v3.StagedGlobalNetworkPolicy{},
				},
			},
			http.StatusOK,
		),

		Entry("for destination endpoint with egress only flows - no rules will be computed",
			app1ToNginxEgressFlows,
			nginxQuery,
			nil,
			http.StatusInternalServerError,
		),

		Entry("for unknown endpoint - no results from linseed",
			[]rest.MockResult{{Body: lapi.List[lapi.L3Flow]{}}},
			&lmapolicyrec.PolicyRecommendationParams{
				StartTime:    "now-1h",
				EndTime:      "now",
				EndpointName: "idontexist-*",
				Namespace:    "default",
			},
			&PolicyRecommendationResponse{
				Recommendation: &lmapolicyrec.Recommendation{
					NetworkPolicies:       []*v3.StagedNetworkPolicy{},
					GlobalNetworkPolicies: []*v3.StagedGlobalNetworkPolicy{},
				},
			},
			http.StatusOK,
		),

		Entry("for query that errors out - invalid time parameters",
			[]rest.MockResult{{Err: fmt.Errorf("mock error from Linseed")}},
			&lmapolicyrec.PolicyRecommendationParams{
				StartTime:    "now",
				EndTime:      "now-1h",
				EndpointName: "someendpoint-*",
				Namespace:    "default",
			}, nil, http.StatusInternalServerError,
		),
	)

	DescribeTable("Namespace policy - recommend policies for matching flows and namespace",
		func(linseedResponses []rest.MockResult,
			query *lmapolicyrec.PolicyRecommendationParams,
			expectedResponse *PolicyRecommendationResponse,
			statusCode int,
		) {
			lsc.SetResults(linseedResponses...)

			jsonQuery, err := json.Marshal(query)
			Expect(err).To(BeNil())

			req, err := http.NewRequest(http.MethodPost, recommendURLPath, bytes.NewBuffer(jsonQuery))
			Expect(err).To(BeNil())

			// The mock k8s client set, with test data.
			mockLmaK8sClientSet := lmak8s.MockClientSet{}
			mockLmaK8sClientSet.On("ProjectcalicoV3").Return(
				clientsetfake.NewClientset().ProjectcalicoV3(),
			)
			coreV1 := fakeK8s.NewClientset().CoreV1()
			_, err = coreV1.Namespaces().Create(req.Context(), namespace1Namespace, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = coreV1.Namespaces().Create(req.Context(), namespace2Namespace, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			mockLmaK8sClientSet.On("CoreV1").Return(coreV1)

			mockLmaK8sClientFactory := &lmak8s.MockClientSetFactory{}
			mockLmaK8sClientFactory.On("NewClientSetForApplication", "cluster").Return(&mockLmaK8sClientSet, nil)

			mockK8sClientFactory := new(datastore.MockClusterCtxK8sClientFactory)
			mockK8sClientFactory.On("RBACAuthorizerForCluster", mock.Anything).Return(mockRBACAuthorizer, nil)

			By("Initializing the engine") // Tempted to say "Start your engines!"
			hdlr := PolicyRecommendationHandler(mockLmaK8sClientFactory, mockK8sClientFactory, lsc)

			mockRBACAuthorizer.On("Authorize", mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

			// add a bogus user
			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{}))

			w := httptest.NewRecorder()
			hdlr.ServeHTTP(w, req)
			Expect(err).To(BeNil())

			if statusCode != http.StatusOK {
				Expect(w.Code).To(Equal(http.StatusNotFound))
				recResponse, err := io.ReadAll(w.Body)
				Expect(err).NotTo(HaveOccurred())
				errorBody := &api.Error{}
				err = json.Unmarshal(recResponse, errorBody)
				Expect(err).To(BeNil())
				Expect(errorBody.Code).To(Equal(statusCode))
				Expect(errorBody.Feature).To(Equal(api.PolicyRec))
				return
			}

			recResponse, err := io.ReadAll(w.Body)
			Expect(err).NotTo(HaveOccurred())

			actualRec := &PolicyRecommendationResponse{}
			err = json.Unmarshal(recResponse, actualRec)
			Expect(err).To(BeNil())

			if expectedResponse == nil {
				Expect(actualRec).To(BeNil())
			} else {
				Expect(actualRec).ToNot(BeNil())
				for i, gnp := range actualRec.GlobalNetworkPolicies {
					Expect(gnp).To(lmapolicyrec.MatchPolicy(expectedResponse.GlobalNetworkPolicies[i]))
				}
				for i, np := range actualRec.NetworkPolicies {
					Expect(np).To(lmapolicyrec.MatchPolicy(expectedResponse.NetworkPolicies[i]))
				}
			}
		},

		Entry("policy for namespace1",
			flowsForNamespaceTest,
			namespace1Query,
			&PolicyRecommendationResponse{
				Recommendation: &lmapolicyrec.Recommendation{
					NetworkPolicies: []*v3.StagedNetworkPolicy{
						namespace1Policy,
					},
					GlobalNetworkPolicies: []*v3.StagedGlobalNetworkPolicy{},
				},
			},
			http.StatusOK,
		),

		Entry("policy for namespace2",
			flowsForNamespaceTest,
			namespace2Query,
			&PolicyRecommendationResponse{
				Recommendation: &lmapolicyrec.Recommendation{
					NetworkPolicies: []*v3.StagedNetworkPolicy{
						namespace2Policy,
					},
					GlobalNetworkPolicies: []*v3.StagedGlobalNetworkPolicy{},
				},
			},
			http.StatusOK,
		),
	)
})
