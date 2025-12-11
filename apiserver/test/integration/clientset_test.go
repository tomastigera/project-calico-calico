// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
//
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
// limitations under the License.package util

package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	"github.com/tigera/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/apiserver/pkg/apiserver"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authenticationreview"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizationreview"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	libclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	licclient "github.com/projectcalico/calico/licensing/client"
	"github.com/projectcalico/calico/licensing/utils"
)

// TestGroupVersion is trivial.
func TestGroupVersion(t *testing.T) {
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.NetworkPolicy{}
			}, true)
			defer shutdownServer()
			if err := testGroupVersion(client); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run("group version", rootTestFunc()) {
		t.Error("test failed")
	}
}

func testGroupVersion(client calicoclient.Interface) error {
	gv := client.ProjectcalicoV3().RESTClient().APIVersion()
	if gv.Group != v3.GroupName {
		return fmt.Errorf("we should be testing the servicecatalog group, not %s", gv.Group)
	}
	return nil
}

func TestEtcdHealthCheckerSuccess(t *testing.T) {
	serverConfig := NewTestServerConfig()
	_, _, clientconfig, shutdownServer := withConfigGetFreshApiserverServerAndClient(t, serverConfig)
	t.Log(clientconfig.Host)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := &http.Client{Transport: tr}
	var success bool
	var resp *http.Response
	var err error
	retryInterval := 500 * time.Millisecond
	for i := 0; i < 5; i++ {
		resp, err = c.Get(clientconfig.Host + "/healthz")
		if err != nil || http.StatusOK != resp.StatusCode {
			success = false
			time.Sleep(retryInterval)
		} else {
			success = true
			break
		}
	}

	if !success {
		t.Fatal("health check endpoint should not have failed")
	}

	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("couldn't read response body", err)
	}
	if strings.Contains(string(body), "healthz check failed") {
		t.Fatal("health check endpoint should not have failed")
	}

	defer shutdownServer()
}

// TestNoName checks that all creates fail for objects that have no
// name given.
func TestNoName(t *testing.T) {
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.NetworkPolicy{}
			}, true)
			defer shutdownServer()
			if err := testNoName(client); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run("no-name", rootTestFunc()) {
		t.Errorf("NoName test failed")
	}
}

func testNoName(client calicoclient.Interface) error {
	cClient := client.ProjectcalicoV3()

	ns := "default"

	if p, e := cClient.NetworkPolicies(ns).Create(context.Background(), &v3.NetworkPolicy{}, metav1.CreateOptions{}); nil == e {
		return fmt.Errorf("needs a name (%s)", p.Name)
	}

	return nil
}

// TestNetworkPolicyClient exercises the NetworkPolicy client.
func TestNetworkPolicyClient(t *testing.T) {
	const name = "test-networkpolicy"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.NetworkPolicy{}
			}, true)
			defer shutdownServer()
			if err := testNetworkPolicyClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-networkpolicy test failed")
	}
}

func testNetworkPolicyClient(client calicoclient.Interface, name string) error {
	ns := "default"
	defaultTierPolicyName := "default" + "." + name
	policyClient := client.ProjectcalicoV3().NetworkPolicies(ns)
	policy := &v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: defaultTierPolicyName}}
	ctx := context.Background()

	// start from scratch
	policies, err := policyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing policies (%s)", err)
	}
	if policies.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}
	if len(policies.Items) > 0 {
		return fmt.Errorf("policies should not exist on start, had %v policies", len(policies.Items))
	}

	// Create a policy without the "default" prefix. It should be returned back without the prefix.
	policy2 := &v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name}}
	policyServer, err := policyClient.Create(ctx, policy2, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the policy '%v' (%v)", policy2, err)
	}
	if name != policyServer.Name {
		return fmt.Errorf("policy name prefix was defaulted by the apiserver on create: %v", policyServer)
	}

	// Update that policy. We should be able to use the same name that we used to create it (i.e., without the "default" prefix).
	policyServer.Name = name
	policyServer.Labels = map[string]string{"foo": "bar"}
	policyServer, err = policyClient.Update(ctx, policyServer, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating the policy '%v' (%v)", policyServer, err)
	}
	if defaultTierPolicyName == policyServer.Name {
		return fmt.Errorf("policy name prefix was defaulted by the apiserver on update: %v", policyServer)
	}

	// Delete that policy. We should be able to use the same name that we used to create it (i.e., without the "default" prefix).
	err = policyClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("error deleting the policy '%v' (%v)", name, err)
	}

	// Now create a policy with the "default" prefix. It should be created as-is.
	policyServer, err = policyClient.Create(ctx, policy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the policy '%v' (%v)", policy, err)
	}
	if defaultTierPolicyName != policyServer.Name {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}

	updatedPolicy := policyServer
	updatedPolicy.Labels = map[string]string{"foo": "bar"}
	policyServer, err = policyClient.Update(ctx, updatedPolicy, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the policy '%v' (%v)", policy, err)
	}
	if defaultTierPolicyName != policyServer.Name {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}

	// For testing out Tiered Policy
	tierClient := client.ProjectcalicoV3().Tiers()
	order := float64(100.0)
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "net-sec"},
		Spec: v3.TierSpec{
			Order: &order,
		},
	}

	if _, err := tierClient.Create(ctx, tier, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error creating tier '%v' (%v)", tier, err)
	}
	defer func() {
		_ = tierClient.Delete(ctx, "net-sec", metav1.DeleteOptions{})
	}()

	netSecPolicyName := "net-sec" + "." + name
	netSecPolicy := &v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: netSecPolicyName}, Spec: v3.NetworkPolicySpec{Tier: "net-sec"}}
	policyServer, err = policyClient.Create(ctx, netSecPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the policy '%v' (%v)", netSecPolicy, err)
	}
	if netSecPolicyName != policyServer.Name {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}

	// Should be listing the policy under default tier.
	policies, err = policyClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.tier=default"})
	if err != nil {
		return fmt.Errorf("error listing policies (%s)", err)
	}
	if len(policies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(policies.Items))
	}

	// Should be listing the policy under "net-sec" tier
	policies, err = policyClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.tier=net-sec"})
	if err != nil {
		return fmt.Errorf("error listing policies (%s)", err)
	}
	if len(policies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(policies.Items))
	}

	// Should be listing all policy
	policies, err = policyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing policies (%s)", err)
	}
	if len(policies.Items) != 2 {
		return fmt.Errorf("should have exactly two policies, had %v policies", len(policies.Items))
	}

	// Should be listing the policy under "net-sec" tier
	policies, err = policyClient.List(ctx, metav1.ListOptions{LabelSelector: "projectcalico.org/tier in (net-sec)"})
	if err != nil {
		return fmt.Errorf("error listing NetworkPolicies (%s)", err)
	}
	if len(policies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(policies.Items))
	}
	if policies.Items[0].Spec.Tier != "net-sec" {
		return fmt.Errorf("should have list policy from net-sec tier, had %s tier", policies.Items[0].Spec.Tier)
	}

	// Should be listing the policy under "net-sec" and "default tier
	policies, err = policyClient.List(ctx, metav1.ListOptions{LabelSelector: "projectcalico.org/tier in (default, net-sec)"})
	if err != nil {
		return fmt.Errorf("error listing NetworkPolicies (%s)", err)
	}
	if len(policies.Items) != 2 {
		return fmt.Errorf("should have exactly two policies, had %v policies", len(policies.Items))
	}

	policyServer, err = policyClient.Get(ctx, defaultTierPolicyName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting policy %s (%s)", name, err)
	}
	if name != policyServer.Name &&
		policy.ResourceVersion == policyServer.ResourceVersion {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}

	// check that the policy is the same from get and list
	/*policyListed := &policies.Items[0]
	if !reflect.DeepEqual(policyServer, policyListed) {
		fmt.Printf("Policy through Get: %v\n", policyServer)
		fmt.Printf("Policy through list: %v\n", policyListed)
		return fmt.Errorf(
			"Didn't get the same instance from list and get: diff: %v",
			diff.ObjectReflectDiff(policyServer, policyListed),
		)
	}*/
	// Watch Test:
	opts := metav1.ListOptions{Watch: true}
	wIface, err := policyClient.Watch(ctx, opts)
	if err != nil {
		return fmt.Errorf("Error on watch")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range wIface.ResultChan() {
			fmt.Println("Watch object: ", e)
			break
		}
	}()

	err = policyClient.Delete(ctx, defaultTierPolicyName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("policy should be deleted (%s)", err)
	}

	err = policyClient.Delete(ctx, netSecPolicyName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("policy should be deleted (%s)", err)
	}

	wg.Wait()
	return nil
}

// TestStagedgNetworkPolicyClient exercises the StagedNetworkPolicy client.
func TestStagedNetworkPolicyClient(t *testing.T) {
	const name = "test-networkpolicy"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.NetworkPolicy{}
			}, true)
			defer shutdownServer()
			if err := testStagedNetworkPolicyClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-stagednetworkpolicy test failed")
	}
}

func testStagedNetworkPolicyClient(client calicoclient.Interface, name string) error {
	ns := "default"
	defaultTierPolicyName := "default" + "." + name
	policyClient := client.ProjectcalicoV3().StagedNetworkPolicies(ns)
	policy := &v3.StagedNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: defaultTierPolicyName},
		Spec:       v3.StagedNetworkPolicySpec{StagedAction: "Set", Selector: "foo == \"bar\""},
	}
	ctx := context.Background()

	// start from scratch
	policies, err := policyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing policies (%s)", err)
	}
	if policies.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}
	if len(policies.Items) > 0 {
		return fmt.Errorf("policies should not exist on start, had %v policies", len(policies.Items))
	}

	// Test that we can create / update / delete policies using the non-tier prefixed name.
	stagedNetworkPolicy2 := &v3.StagedNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name}}
	stagedNetworkPolicyServer, err := policyClient.Create(ctx, stagedNetworkPolicy2, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the staged network policy '%v' (%v)", stagedNetworkPolicy2, err)
	}
	if name != stagedNetworkPolicyServer.Name {
		return fmt.Errorf("policy name prefix was defaulted by the apiserver on create: %v", stagedNetworkPolicyServer)
	}
	stagedNetworkPolicyServer.Name = name
	stagedNetworkPolicyServer.Labels = map[string]string{"foo": "bar"}
	stagedNetworkPolicyServer, err = policyClient.Update(ctx, stagedNetworkPolicyServer, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating the policy '%v' (%v)", stagedNetworkPolicyServer, err)
	}
	if name != stagedNetworkPolicyServer.Name {
		return fmt.Errorf("policy name prefix was defaulted by the apiserver on update: %v", stagedNetworkPolicyServer)
	}
	err = policyClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("error deleting the policy '%v' (%v)", name, err)
	}

	policyServer, err := policyClient.Create(ctx, policy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the policy '%v' (%v)", policy, err)
	}
	if defaultTierPolicyName != policyServer.Name {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}

	updatedPolicy := policyServer
	updatedPolicy.Labels = map[string]string{"foo": "bar"}
	policyServer, err = policyClient.Update(ctx, updatedPolicy, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the policy '%v' (%v)", policy, err)
	}
	if defaultTierPolicyName != policyServer.Name {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}

	// For testing out Tiered Policy
	tierClient := client.ProjectcalicoV3().Tiers()
	order := float64(100.0)
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "net-sec"},
		Spec: v3.TierSpec{
			Order: &order,
		},
	}

	if _, err := tierClient.Create(ctx, tier, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error creating tier '%v' (%v)", tier, err)
	}
	defer func() {
		_ = tierClient.Delete(ctx, "net-sec", metav1.DeleteOptions{})
	}()

	netSecPolicyName := "net-sec" + "." + name
	netSecPolicy := &v3.StagedNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: netSecPolicyName}, Spec: v3.StagedNetworkPolicySpec{StagedAction: "Set", Selector: "foo == \"bar\"", Tier: "net-sec"}}
	policyServer, err = policyClient.Create(ctx, netSecPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the policy '%v' (%v)", netSecPolicy, err)
	}
	if netSecPolicyName != policyServer.Name {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}

	// Should be listing the policy under default tier.
	policies, err = policyClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.tier=default"})
	if err != nil {
		return fmt.Errorf("error listing policies (%s)", err)
	}
	if len(policies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(policies.Items))
	}

	// Should be listing the policy under "net-sec" tier
	policies, err = policyClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.tier=net-sec"})
	if err != nil {
		return fmt.Errorf("error listing policies (%s)", err)
	}
	if len(policies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(policies.Items))
	}

	// Should be listing all policies
	policies, err = policyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing policies (%s)", err)
	}
	if len(policies.Items) != 2 {
		return fmt.Errorf("should have exactly two policies, had %v policies", len(policies.Items))
	}

	// Should be listing the policy under "net-sec" tier
	policies, err = policyClient.List(ctx, metav1.ListOptions{LabelSelector: "projectcalico.org/tier in (net-sec)"})
	if err != nil {
		return fmt.Errorf("error listing stagedGlobalNetworkPolicies (%s)", err)
	}
	if len(policies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(policies.Items))
	}
	if policies.Items[0].Spec.Tier != "net-sec" {
		return fmt.Errorf("should have list policy from net-sec tier, had %s tier", policies.Items[0].Spec.Tier)
	}

	// Should be listing the policy under "net-sec" and "default tier
	policies, err = policyClient.List(ctx, metav1.ListOptions{LabelSelector: "projectcalico.org/tier in (default, net-sec)"})
	if err != nil {
		return fmt.Errorf("error listing stagedGlobalNetworkPolicies (%s)", err)
	}
	if len(policies.Items) != 2 {
		return fmt.Errorf("should have exactly two policies, had %v policies", len(policies.Items))
	}

	policyServer, err = policyClient.Get(ctx, defaultTierPolicyName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting policy %s (%s)", name, err)
	}
	if defaultTierPolicyName != policyServer.Name &&
		policy.ResourceVersion == policyServer.ResourceVersion {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}

	// Watch Test:
	opts := metav1.ListOptions{Watch: true}
	wIface, err := policyClient.Watch(ctx, opts)
	if err != nil {
		return fmt.Errorf("Error on watch")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range wIface.ResultChan() {
			fmt.Println("Watch object: ", e)
			break
		}
	}()

	err = policyClient.Delete(ctx, defaultTierPolicyName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("policy should be deleted (%s)", err)
	}

	err = policyClient.Delete(ctx, netSecPolicyName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("policy should be deleted (%s)", err)
	}

	wg.Wait()
	return nil
}

func TestPolicyRecommendationScopeClient(t *testing.T) {
	name := "test-policy-recommendation-scope"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.Tier{}
			}, true)
			defer shutdownServer()
			if err := testPolicyRecommendationScopeClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("%s failed", name)
	}
}

func testPolicyRecommendationScopeClient(client calicoclient.Interface, name string) error {
	policyrecommendationscopeClient := client.ProjectcalicoV3().PolicyRecommendationScopes()
	defaultValue := 20

	policyrecommendationscope := &v3.PolicyRecommendationScope{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v3.PolicyRecommendationScopeSpec{
			MaxRules:               &defaultValue,
			PoliciesLearningCutOff: &defaultValue,
			NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
				RecStatus: v3.PolicyRecommendationScopeEnabled,
				Selector:  "foo == \"bar\"",
			},
		},
		Status: v3.PolicyRecommendationScopeStatus{
			Conditions: []v3.PolicyRecommendationScopeStatusCondition{
				{
					Message: "0",
					Reason:  "0",
					Status:  "0",
					Type:    "0",
				},
			},
		},
	}

	ctx := context.Background()

	// empty resources
	policyrecommendationscopes, err := policyrecommendationscopeClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing policyrecommendationscopes (%s)", err)
	}
	if policyrecommendationscopes.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	policyrecommendationscopeOnServer, err := policyrecommendationscopeClient.Create(ctx, policyrecommendationscope, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the policyrecommendationscope '%v' (%v)", policyrecommendationscopeOnServer, err)
	}
	if name != policyrecommendationscopeOnServer.Name {
		return fmt.Errorf("didn't get the same policyrecommendationscope back from the server \n%+v\n%+v", policyrecommendationscopes, policyrecommendationscopeOnServer)
	}
	if !reflect.DeepEqual(policyrecommendationscopeOnServer.Status, v3.PolicyRecommendationScopeStatus{}) {
		return fmt.Errorf("status was set on create to %#v", policyrecommendationscopeOnServer.Status)
	}

	policyrecommendationscopeOnServer, err = policyrecommendationscopeClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting policyrecommendationscope %s (%s)", name, err)
	}
	if name != policyrecommendationscopeOnServer.Name &&
		policyrecommendationscopeOnServer.ResourceVersion == policyrecommendationscope.ResourceVersion {
		return fmt.Errorf("didn't get the same policyrecommendationscope back from the server \n%+v\n%+v", policyrecommendationscope, policyrecommendationscopeOnServer)
	}
	updatedValue := 30

	policyrecommendationscopeUpdated := policyrecommendationscopeOnServer.DeepCopy()
	policyrecommendationscopeUpdated.Labels = map[string]string{"foo": "bar"}
	policyrecommendationscopeUpdated.Spec.MaxRules = &updatedValue
	policyrecommendationscopeUpdated.Spec.PoliciesLearningCutOff = &updatedValue

	policyrecommendationscopeUpdated.Status.Conditions = append(policyrecommendationscopeUpdated.Status.Conditions,
		v3.PolicyRecommendationScopeStatusCondition{
			Message: "1",
			Reason:  "1",
			Status:  "1",
			Type:    "1",
		})

	policyrecommendationscopeOnServer, err = policyrecommendationscopeClient.UpdateStatus(ctx, policyrecommendationscopeUpdated, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating status policyrecommendationscope %s (%s)", name, err)
	}

	if len(policyrecommendationscopeOnServer.Status.Conditions) < 1 {
		return fmt.Errorf("didn't update status. %v != %v", policyrecommendationscopeOnServer.Status, policyrecommendationscopeUpdated.Status)
	}

	if _, ok := policyrecommendationscopeOnServer.Labels["foo"]; ok {
		return fmt.Errorf("labels were not updated")
	}

	if *policyrecommendationscopeOnServer.Spec.MaxRules != defaultValue {
		return fmt.Errorf("Specs MaxRules were updated in update status %+v != %+v", policyrecommendationscopeOnServer.Spec, policyrecommendationscope.Spec)
	}

	if *policyrecommendationscopeOnServer.Spec.PoliciesLearningCutOff != defaultValue {
		return fmt.Errorf("Specs PoliciesLearningCutOff were updated in update status %+v != %+v", policyrecommendationscopeOnServer.Spec, policyrecommendationscope.Spec)
	}

	policyrecommendationscopeUpdated = policyrecommendationscopeOnServer.DeepCopy()
	policyrecommendationscopeUpdated.Labels = map[string]string{"foo": "bar"}
	policyrecommendationscopeUpdated.Spec.MaxRules = &updatedValue
	policyrecommendationscopeUpdated.Spec.PoliciesLearningCutOff = &updatedValue

	policyrecommendationscopeUpdated.Status.Conditions = append(policyrecommendationscopeUpdated.Status.Conditions,
		v3.PolicyRecommendationScopeStatusCondition{
			Message: "1",
			Reason:  "1",
			Status:  "1",
			Type:    "1",
		})

	policyrecommendationscopeOnServer, err = policyrecommendationscopeClient.Update(ctx, policyrecommendationscopeUpdated, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating policyrecommendationscope %s (%s)", name, err)
	}

	if *policyrecommendationscopeOnServer.Spec.MaxRules != updatedValue {
		return fmt.Errorf("Specs were not updated")
	}

	if *policyrecommendationscopeOnServer.Spec.PoliciesLearningCutOff != updatedValue {
		return fmt.Errorf("Specs were not updated")
	}

	if len(policyrecommendationscopeOnServer.Status.Conditions) < 1 {
		return fmt.Errorf("didn't update status. %v != %v", policyrecommendationscopeOnServer.Status, policyrecommendationscopeUpdated.Status)
	}

	err = policyrecommendationscopeClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("policyrecommendationscope should be deleted (%s)", err)
	}

	// Test watch
	w, err := client.ProjectcalicoV3().PolicyRecommendationScopes().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching PolicyRecommendationScope (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out wating for events")
				return
			}
		}
	}()

	// Create two PolicyRecScopes
	for i := 0; i < 2; i++ {
		ga := &v3.PolicyRecommendationScope{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("ga%d", i)},
			Spec: v3.PolicyRecommendationScopeSpec{
				MaxRules:               &defaultValue,
				PoliciesLearningCutOff: &defaultValue,
				NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
					RecStatus: v3.PolicyRecommendationScopeEnabled,
					Selector:  "foo == \"bar\"",
				},
			},
		}
		_, err = policyrecommendationscopeClient.Create(ctx, ga, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating the PolicyRecommendationScope '%v' (%v)", ga, err)
		}
	}
	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestTierClient exercises the Tier client.
func TestTierClient(t *testing.T) {
	const name = "test-tier"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.Tier{}
			}, true)
			defer shutdownServer()
			if err := testTierClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-tier test failed")
	}
}

func testTierClient(client calicoclient.Interface, name string) error {
	tierClient := client.ProjectcalicoV3().Tiers()
	order := float64(100.0)
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.TierSpec{
			Order: &order,
		},
	}
	ctx := context.Background()

	err := createEnterprise(client, ctx)
	if err == nil {
		return fmt.Errorf("Could not create a license")
	}

	// start from scratch
	tiers, err := tierClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing tiers (%s)", err)
	}
	if tiers.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	tierServer, err := tierClient.Create(ctx, tier, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the tier '%v' (%v)", tier, err)
	}
	if name != tierServer.Name {
		return fmt.Errorf("didn't get the same tier back from the server \n%+v\n%+v", tier, tierServer)
	}

	_, err = tierClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing tiers (%s)", err)
	}

	tierServer, err = tierClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting tier %s (%s)", name, err)
	}
	if name != tierServer.Name &&
		tier.ResourceVersion == tierServer.ResourceVersion {
		return fmt.Errorf("didn't get the same tier back from the server \n%+v\n%+v", tier, tierServer)
	}

	err = tierClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("tier should be deleted (%s)", err)
	}

	return nil
}

// TestGlobalNetworkPolicyClient exercises the GlobalNetworkPolicy client.
func TestGlobalNetworkPolicyClient(t *testing.T) {
	const name = "test-globalnetworkpolicy"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.GlobalNetworkPolicy{}
			}, true)
			defer shutdownServer()
			if err := testGlobalNetworkPolicyClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-globalnetworkpolicy test failed")
	}
}

func testGlobalNetworkPolicyClient(client calicoclient.Interface, name string) error {
	globalNetworkPolicyClient := client.ProjectcalicoV3().GlobalNetworkPolicies()
	defaultTierPolicyName := "default" + "." + name
	globalNetworkPolicy := &v3.GlobalNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: defaultTierPolicyName}}
	ctx := context.Background()

	// start from scratch
	globalNetworkPolicies, err := globalNetworkPolicyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalNetworkPolicies (%s)", err)
	}
	if globalNetworkPolicies.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	// Test that we can create / update / delete policies using the non-tier prefixed name.
	globalNetworkPolicy2 := &v3.GlobalNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name}}
	globalNetworkPolicyServer, err := globalNetworkPolicyClient.Create(ctx, globalNetworkPolicy2, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the globalNetworkPolicy '%v' (%v)", globalNetworkPolicy2, err)
	}
	if defaultTierPolicyName == globalNetworkPolicyServer.Name {
		return fmt.Errorf("policy name prefix was defaulted by the apiserver on create: %v", globalNetworkPolicyServer)
	}
	globalNetworkPolicyServer.Name = name
	globalNetworkPolicyServer.Labels = map[string]string{"foo": "bar"}
	globalNetworkPolicyServer, err = globalNetworkPolicyClient.Update(ctx, globalNetworkPolicyServer, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating the policy '%v' (%v)", globalNetworkPolicyServer, err)
	}
	if defaultTierPolicyName == globalNetworkPolicyServer.Name {
		return fmt.Errorf("policy name prefix was defaulted by the apiserver on update: %v", globalNetworkPolicyServer)
	}
	err = globalNetworkPolicyClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("error deleting the policy '%v' (%v)", name, err)
	}

	// Now use the tier prefixed name.
	globalNetworkPolicyServer, err = globalNetworkPolicyClient.Create(ctx, globalNetworkPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the globalNetworkPolicy '%v' (%v)", globalNetworkPolicy, err)
	}
	if defaultTierPolicyName != globalNetworkPolicyServer.Name {
		return fmt.Errorf("didn't get the same globalNetworkPolicy back from the server \n%+v\n%+v", globalNetworkPolicy, globalNetworkPolicyServer)
	}

	// For testing out Tiered Policy
	tierClient := client.ProjectcalicoV3().Tiers()
	order := float64(100.0)
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "net-sec"},
		Spec: v3.TierSpec{
			Order: &order,
		},
	}

	if _, err := tierClient.Create(ctx, tier, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error creating tier '%v' (%v)", tier, err)
	}
	defer func() {
		_ = tierClient.Delete(ctx, "net-sec", metav1.DeleteOptions{})
	}()

	netSecPolicyName := "net-sec" + "." + name
	netSecPolicy := &v3.GlobalNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: netSecPolicyName}, Spec: v3.GlobalNetworkPolicySpec{Tier: "net-sec"}}
	globalNetworkPolicyServer, err = globalNetworkPolicyClient.Create(ctx, netSecPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the policy '%v' (%v)", netSecPolicy, err)
	}
	if netSecPolicyName != globalNetworkPolicyServer.Name {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", netSecPolicy, globalNetworkPolicyServer)
	}

	// Should be listing the policy under "default" tier
	globalNetworkPolicies, err = globalNetworkPolicyClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.tier=default"})
	if err != nil {
		return fmt.Errorf("error listing globalNetworkPolicies (%s)", err)
	}
	if len(globalNetworkPolicies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(globalNetworkPolicies.Items))
	}

	// Should be listing the policy under "net-sec" tier
	globalNetworkPolicies, err = globalNetworkPolicyClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.tier=net-sec"})
	if err != nil {
		return fmt.Errorf("error listing globalNetworkPolicies (%s)", err)
	}
	if len(globalNetworkPolicies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(globalNetworkPolicies.Items))
	}

	// Should be listing all policies
	globalNetworkPolicies, err = globalNetworkPolicyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalNetworkPolicies (%s)", err)
	}
	if len(globalNetworkPolicies.Items) != 2 {
		return fmt.Errorf("should have exactly two policies, had %v policies", len(globalNetworkPolicies.Items))
	}

	// Should be listing the policy under "net-sec" tier
	globalNetworkPolicies, err = globalNetworkPolicyClient.List(ctx, metav1.ListOptions{LabelSelector: "projectcalico.org/tier in (net-sec)"})
	if err != nil {
		return fmt.Errorf("error listing stagedGlobalNetworkPolicies (%s)", err)
	}
	if len(globalNetworkPolicies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(globalNetworkPolicies.Items))
	}
	if globalNetworkPolicies.Items[0].Spec.Tier != "net-sec" {
		return fmt.Errorf("should have list policy from net-sec tier, had %s tier", globalNetworkPolicies.Items[0].Spec.Tier)
	}

	// Should be listing the policy under "net-sec" and "default tier
	globalNetworkPolicies, err = globalNetworkPolicyClient.List(ctx, metav1.ListOptions{LabelSelector: "projectcalico.org/tier in (default, net-sec)"})
	if err != nil {
		return fmt.Errorf("error listing stagedGlobalNetworkPolicies (%s)", err)
	}
	if len(globalNetworkPolicies.Items) != 2 {
		return fmt.Errorf("should have exactly two policies, had %v policies", len(globalNetworkPolicies.Items))
	}

	globalNetworkPolicyServer, err = globalNetworkPolicyClient.Get(ctx, defaultTierPolicyName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting globalNetworkPolicy %s (%s)", name, err)
	}
	if name != globalNetworkPolicyServer.Name &&
		globalNetworkPolicy.ResourceVersion == globalNetworkPolicyServer.ResourceVersion {
		return fmt.Errorf("didn't get the same globalNetworkPolicy back from the server \n%+v\n%+v", globalNetworkPolicy, globalNetworkPolicyServer)
	}

	err = globalNetworkPolicyClient.Delete(ctx, defaultTierPolicyName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("globalNetworkPolicy should be deleted (%s)", err)
	}

	err = globalNetworkPolicyClient.Delete(ctx, netSecPolicyName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("policy should be deleted (%s)", err)
	}

	return nil
}

// TestStagedGlobalNetworkPolicyClient exercises the StagedGlobalNetworkPolicy client.
func TestStagedGlobalNetworkPolicyClient(t *testing.T) {
	const name = "test-stagedglobalnetworkpolicy"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.StagedGlobalNetworkPolicy{}
			}, true)
			defer shutdownServer()
			if err := testStagedGlobalNetworkPolicyClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-Stagedglobalnetworkpolicy test failed")
	}
}

func testStagedGlobalNetworkPolicyClient(client calicoclient.Interface, name string) error {
	stagedGlobalNetworkPolicyClient := client.ProjectcalicoV3().StagedGlobalNetworkPolicies()
	defaultTierPolicyName := name
	stagedGlobalNetworkPolicy := &v3.StagedGlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v3.StagedGlobalNetworkPolicySpec{StagedAction: "Set", Selector: "foo == \"bar\""},
	}
	ctx := context.Background()

	// start from scratch
	stagedGlobalNetworkPolicies, err := stagedGlobalNetworkPolicyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing stagedglobalNetworkPolicies (%s)", err)
	}
	if stagedGlobalNetworkPolicies.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	// Test that we can create / update / delete policies using the non-tier prefixed name.
	stagedGlobalNetworkPolicy2 := &v3.StagedGlobalNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name}}
	stagedGlobalNetworkPolicyServer, err := stagedGlobalNetworkPolicyClient.Create(ctx, stagedGlobalNetworkPolicy2, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the staged globalNetworkPolicy '%v' (%v)", stagedGlobalNetworkPolicy2, err)
	}
	if defaultTierPolicyName != stagedGlobalNetworkPolicyServer.Name {
		return fmt.Errorf("policy name prefix wasn't defaulted by the apiserver on create: %v", stagedGlobalNetworkPolicyServer)
	}
	stagedGlobalNetworkPolicyServer.Name = name
	stagedGlobalNetworkPolicyServer.Labels = map[string]string{"foo": "bar"}
	stagedGlobalNetworkPolicyServer, err = stagedGlobalNetworkPolicyClient.Update(ctx, stagedGlobalNetworkPolicyServer, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating the policy '%v' (%v)", stagedGlobalNetworkPolicyServer, err)
	}
	if defaultTierPolicyName != stagedGlobalNetworkPolicyServer.Name {
		return fmt.Errorf("policy name prefix wasn't defaulted by the apiserver on update: %v", stagedGlobalNetworkPolicyServer)
	}
	err = stagedGlobalNetworkPolicyClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("error deleting the policy '%v' (%v)", name, err)
	}

	stagedGlobalNetworkPolicyServer, err = stagedGlobalNetworkPolicyClient.Create(ctx, stagedGlobalNetworkPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the stagedGlobalNetworkPolicy '%v' (%v)", stagedGlobalNetworkPolicy, err)
	}
	if defaultTierPolicyName != stagedGlobalNetworkPolicyServer.Name {
		return fmt.Errorf("didn't get the same stagedGlobalNetworkPolicy back from the server \n%+v\n%+v", stagedGlobalNetworkPolicy, stagedGlobalNetworkPolicyServer)
	}

	// For testing out Tiered Policy
	tierClient := client.ProjectcalicoV3().Tiers()
	order := float64(100.0)
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "net-sec"},
		Spec: v3.TierSpec{
			Order: &order,
		},
	}

	if _, err := tierClient.Create(ctx, tier, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error creating tier '%v' (%v)", tier, err)
	}
	defer func() {
		_ = tierClient.Delete(ctx, "net-sec", metav1.DeleteOptions{})
	}()

	netSecPolicyName := "net-sec" + "." + name
	netSecPolicy := &v3.StagedGlobalNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: netSecPolicyName}, Spec: v3.StagedGlobalNetworkPolicySpec{StagedAction: "Set", Selector: "foo == \"bar\"", Tier: "net-sec"}}
	stagedGlobalNetworkPolicyServer, err = stagedGlobalNetworkPolicyClient.Create(ctx, netSecPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the policy '%v' (%v)", netSecPolicy, err)
	}
	if netSecPolicyName != stagedGlobalNetworkPolicyServer.Name {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", netSecPolicy, stagedGlobalNetworkPolicyServer)
	}

	// Should be listing the policy under "default" tier
	stagedGlobalNetworkPolicies, err = stagedGlobalNetworkPolicyClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.tier=default"})
	if err != nil {
		return fmt.Errorf("error listing stagedGlobalNetworkPolicies (%s)", err)
	}
	if len(stagedGlobalNetworkPolicies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(stagedGlobalNetworkPolicies.Items))
	}

	// Should be listing the policy under "net-sec" tier
	stagedGlobalNetworkPolicies, err = stagedGlobalNetworkPolicyClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.tier=net-sec"})
	if err != nil {
		return fmt.Errorf("error listing stagedGlobalNetworkPolicies (%s)", err)
	}
	if len(stagedGlobalNetworkPolicies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(stagedGlobalNetworkPolicies.Items))
	}

	// Should be listing all policies
	stagedGlobalNetworkPolicies, err = stagedGlobalNetworkPolicyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing stagedGlobalNetworkPolicies (%s)", err)
	}
	if len(stagedGlobalNetworkPolicies.Items) != 2 {
		return fmt.Errorf("should have exactly two policies, had %v policies", len(stagedGlobalNetworkPolicies.Items))
	}

	// Should be listing the policy under "net-sec" tier
	stagedGlobalNetworkPolicies, err = stagedGlobalNetworkPolicyClient.List(ctx, metav1.ListOptions{LabelSelector: "projectcalico.org/tier in (net-sec)"})
	if err != nil {
		return fmt.Errorf("error listing stagedGlobalNetworkPolicies (%s)", err)
	}
	if len(stagedGlobalNetworkPolicies.Items) != 1 {
		return fmt.Errorf("should have exactly one policy, had %v policies", len(stagedGlobalNetworkPolicies.Items))
	}
	if stagedGlobalNetworkPolicies.Items[0].Spec.Tier != "net-sec" {
		return fmt.Errorf("should have list policy from net-sec tier, had %s tier", stagedGlobalNetworkPolicies.Items[0].Spec.Tier)
	}

	// Should be listing the policy under "net-sec" and "default tier
	stagedGlobalNetworkPolicies, err = stagedGlobalNetworkPolicyClient.List(ctx, metav1.ListOptions{LabelSelector: "projectcalico.org/tier in (default, net-sec)"})
	if err != nil {
		return fmt.Errorf("error listing stagedGlobalNetworkPolicies (%s)", err)
	}
	if len(stagedGlobalNetworkPolicies.Items) != 2 {
		return fmt.Errorf("should have exactly two policies, had %v policies", len(stagedGlobalNetworkPolicies.Items))
	}

	stagedGlobalNetworkPolicyServer, err = stagedGlobalNetworkPolicyClient.Get(ctx, defaultTierPolicyName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting stagedGlobalNetworkPolicy %s (%s)", name, err)
	}
	if name != stagedGlobalNetworkPolicyServer.Name &&
		stagedGlobalNetworkPolicy.ResourceVersion == stagedGlobalNetworkPolicyServer.ResourceVersion {
		return fmt.Errorf("didn't get the same stagedGlobalNetworkPolicy back from the server \n%+v\n%+v", stagedGlobalNetworkPolicy, stagedGlobalNetworkPolicyServer)
	}

	err = stagedGlobalNetworkPolicyClient.Delete(ctx, defaultTierPolicyName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("stagedGlobalNetworkPolicy should be deleted (%s)", err)
	}

	err = stagedGlobalNetworkPolicyClient.Delete(ctx, netSecPolicyName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("policy should be deleted (%s)", err)
	}

	return nil
}

// TestGlobalNetworkSetClient exercises the GlobalNetworkSet client.
func TestGlobalNetworkSetClient(t *testing.T) {
	const name = "test-globalnetworkset"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.GlobalNetworkSet{}
			}, true)
			defer shutdownServer()
			if err := testGlobalNetworkSetClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-globalnetworkset test failed")
	}
}

func testGlobalNetworkSetClient(client calicoclient.Interface, name string) error {
	globalNetworkSetClient := client.ProjectcalicoV3().GlobalNetworkSets()
	globalNetworkSet := &v3.GlobalNetworkSet{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	ctx := context.Background()

	// start from scratch
	globalNetworkSets, err := globalNetworkSetClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalNetworkSets (%s)", err)
	}
	if globalNetworkSets.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	globalNetworkSetServer, err := globalNetworkSetClient.Create(ctx, globalNetworkSet, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the globalNetworkSet '%v' (%v)", globalNetworkSet, err)
	}
	if name != globalNetworkSetServer.Name {
		return fmt.Errorf("didn't get the same globalNetworkSet back from the server \n%+v\n%+v", globalNetworkSet, globalNetworkSetServer)
	}

	_, err = globalNetworkSetClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalNetworkSets (%s)", err)
	}

	globalNetworkSetServer, err = globalNetworkSetClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting globalNetworkSet %s (%s)", name, err)
	}
	if name != globalNetworkSetServer.Name &&
		globalNetworkSet.ResourceVersion == globalNetworkSetServer.ResourceVersion {
		return fmt.Errorf("didn't get the same globalNetworkSet back from the server \n%+v\n%+v", globalNetworkSet, globalNetworkSetServer)
	}

	err = globalNetworkSetClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("globalNetworkSet should be deleted (%s)", err)
	}

	return nil
}

// TestNetworkSetClient exercises the NetworkSet client.
func TestNetworkSetClient(t *testing.T) {
	const name = "test-networkset"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.NetworkSet{}
			}, true)
			defer shutdownServer()
			if err := testNetworkSetClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-networkset test failed")
	}
}

func testNetworkSetClient(client calicoclient.Interface, name string) error {
	ns := "default"
	networkSetClient := client.ProjectcalicoV3().NetworkSets(ns)
	networkSet := &v3.NetworkSet{ObjectMeta: metav1.ObjectMeta{Name: name}}
	ctx := context.Background()

	// start from scratch
	networkSets, err := networkSetClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing networkSets (%s)", err)
	}
	if networkSets.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}
	if len(networkSets.Items) > 0 {
		return fmt.Errorf("networkSets should not exist on start, had %v networkSets", len(networkSets.Items))
	}

	networkSetServer, err := networkSetClient.Create(ctx, networkSet, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the networkSet '%v' (%v)", networkSet, err)
	}

	updatedNetworkSet := networkSetServer
	updatedNetworkSet.Labels = map[string]string{"foo": "bar"}
	_, err = networkSetClient.Update(ctx, updatedNetworkSet, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating the networkSet '%v' (%v)", networkSet, err)
	}

	// Should be listing the networkSet.
	networkSets, err = networkSetClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing networkSets (%s)", err)
	}
	if len(networkSets.Items) != 1 {
		return fmt.Errorf("should have exactly one networkSet, had %v networkSets", len(networkSets.Items))
	}

	networkSetServer, err = networkSetClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting networkSet %s (%s)", name, err)
	}
	if name != networkSetServer.Name &&
		networkSet.ResourceVersion == networkSetServer.ResourceVersion {
		return fmt.Errorf("didn't get the same networkSet back from the server \n%+v\n%+v", networkSet, networkSetServer)
	}

	// Watch Test:
	opts := metav1.ListOptions{Watch: true}
	wIface, err := networkSetClient.Watch(ctx, opts)
	if err != nil {
		return fmt.Errorf("Error on watch")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range wIface.ResultChan() {
			fmt.Println("Watch object: ", e)
			break
		}
	}()

	err = networkSetClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("networkSet should be deleted (%s)", err)
	}

	wg.Wait()
	return nil
}

// TestLicenseKeyClient exercises the LicenseKey client.
func TestLicenseKeyClient(t *testing.T) {
	const name = "default"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.LicenseKey{}
			}, false)
			defer shutdownServer()
			if err := testLicenseKeyClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-licensekey test failed")
	}
}

func testLicenseKeyClient(client calicoclient.Interface, name string) error {
	licenseKeyClient := client.ProjectcalicoV3().LicenseKeys()
	ctx := context.Background()

	licenseKeys, err := licenseKeyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing licenseKeys (%s)", err)
	}
	if licenseKeys.Items == nil {
		return fmt.Errorf("items field should not be set to nil")
	}

	// Validate that a license not encrypted with production key is rejected
	corruptLicenseKey := &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: name}}

	_, err = licenseKeyClient.Create(ctx, corruptLicenseKey, metav1.CreateOptions{})
	if err == nil {
		return fmt.Errorf("expected creating the emptyLicenseKey")
	}

	// Confirm that valid, but expired licenses, are rejected
	expiredLicenseKey := utils.ExpiredTestLicense()
	_, err = licenseKeyClient.Create(ctx, expiredLicenseKey, metav1.CreateOptions{})
	if err == nil {
		return fmt.Errorf("expected creating the expiredLicenseKey")
	} else if err.Error() != "LicenseKey.projectcalico.org \"default\" is invalid: LicenseKeySpec.token: Internal error: the license you're trying to create expired on 2019-02-08 07:59:59 +0000 UTC" {
		fmt.Printf("Incorrect error: %+v\n", err)
	}
	// Valid Enterprise License with Maximum supported Nodes 100
	enterpriseValidLicenseKey := utils.ValidEnterpriseTestLicense()
	claims, err := licclient.Decode(*enterpriseValidLicenseKey)
	if err != nil {
		fmt.Printf("Failed to decode 'valid' license  %v\n", err)
		return err
	}

	lic, err := licenseKeyClient.Create(ctx, enterpriseValidLicenseKey, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf("Check for License Expiry date %v\n", err)
		return err
	}

	// Check for maximum nodes.
	if lic.Status.MaxNodes != *claims.Nodes {
		fmt.Printf("Valid License's Maximum Node doesn't match :%d\n", lic.Status.MaxNodes)
		return fmt.Errorf("Incorrect Maximum Nodes in LicenseKey")
	}

	// Check for Certificate Expiry date exists.  Since hte cert is provided to us as configuration, we can't check
	// the exact date.
	if !lic.Status.Expiry.After(time.Now()) {
		fmt.Printf("Valid License's Expiry date missing/in past:%v\n", lic.Status.Expiry)
		return fmt.Errorf("License Expiry date don't match")
	}

	if lic.Status.Package != "Enterprise" {
		fmt.Printf("License's package type does not match :%v\n", lic.Status.Package)
		return fmt.Errorf("License Package Type does not match")
	}

	// Check that required features (cnx and all) are present in the license
	requiredFeatures := []string{"cnx", "all"}

	for _, requiredFeature := range requiredFeatures {
		if !slices.Contains(lic.Status.Features, requiredFeature) {
			err := fmt.Errorf("License is missing required feature '%s'. Actual features: %v\n", requiredFeature, lic.Status.Features)
			fmt.Print(err)
			return err
		}
	}

	return nil
}

// TestAlertExceptionClient exercises the AlertException client.
func TestAlertExceptionClient(t *testing.T) {
	const name = "test-alertexception"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.AlertException{}
			}, true)
			defer shutdownServer()
			if err := testAlertExceptionClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-alertexception test failed")
	}
}

func testAlertExceptionClient(client calicoclient.Interface, name string) error {
	alertExceptionClient := client.ProjectcalicoV3().AlertExceptions()
	alertException := &v3.AlertException{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.AlertExceptionSpec{
			Description: "alert exception description",
			Selector:    "origin=someorigin",
			StartTime:   metav1.Time{Time: time.Now()},
		},
		Status: v3.AlertExceptionStatus{},
	}
	ctx := context.Background()

	// start from scratch
	alertExceptions, err := alertExceptionClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing alertException (%s)", err)
	}
	if alertExceptions.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	alertExceptionServer, err := alertExceptionClient.Create(ctx, alertException, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the alertException '%v' (%v)", alertException, err)
	}
	if name != alertExceptionServer.Name {
		return fmt.Errorf("didn't get the same alertException back from the server \n%+v\n%+v", alertException, alertExceptionServer)
	}
	if !reflect.DeepEqual(alertExceptionServer.Status, v3.AlertExceptionStatus{}) {
		return fmt.Errorf("status was set on create to %#v", alertException.Status)
	}

	alertExceptions, err = alertExceptionClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing alertExceptions (%s)", err)
	}
	if len(alertExceptions.Items) != 1 {
		return fmt.Errorf("expected 1 alertException got %d", len(alertExceptions.Items))
	}

	alertExceptionServer, err = alertExceptionClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting alertException %s (%s)", name, err)
	}
	if name != alertExceptionServer.Name &&
		alertException.ResourceVersion == alertExceptionServer.ResourceVersion {
		return fmt.Errorf("didn't get the same alertException back from the server \n%+v\n%+v", alertException, alertExceptionServer)
	}

	alertExceptionUpdate := alertExceptionServer.DeepCopy()
	alertExceptionUpdate.Spec.Description += "-updated"
	alertExceptionServer, err = alertExceptionClient.Update(ctx, alertExceptionUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating alertException %s (%s)", name, err)
	}
	if alertExceptionServer.Spec.Description != alertExceptionUpdate.Spec.Description {
		return errors.New("didn't update spec.description")
	}

	alertExceptionUpdate = alertExceptionServer.DeepCopy()
	alertExceptionUpdate.Labels = map[string]string{"foo": "bar"}
	statusDescription := "status"
	alertExceptionUpdate.Spec.Description = statusDescription
	alertExceptionServer, err = alertExceptionClient.UpdateStatus(ctx, alertExceptionUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating alertException %s (%s)", name, err)
	}
	if _, ok := alertExceptionServer.Labels["foo"]; ok {
		return fmt.Errorf("updatestatus updated labels")
	}
	if alertExceptionServer.Spec.Description == statusDescription {
		return fmt.Errorf("updatestatus updated spec")
	}

	err = alertExceptionClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("alertException should be deleted (%s)", err)
	}

	// Test watch
	w, err := client.ProjectcalicoV3().AlertExceptions().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching AlertExceptions (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out waiting for events")
				return
			}
		}
	}()

	// Create two AlertExceptions
	for i := 0; i < 2; i++ {
		ae := &v3.AlertException{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("ae%d", i)},
			Spec: v3.AlertExceptionSpec{
				Description: "test",
				Selector:    "origin=someorigin",
				StartTime:   metav1.Time{Time: time.Now()},
			},
		}
		_, err = alertExceptionClient.Create(ctx, ae, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating the alertException '%v' (%v)", ae, err)
		}
	}
	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestSecurityEventWebhookClient exercises the SecurityEventWebhook client.
func TestSecurityEventWebhookClient(t *testing.T) {
	const name = "test-securityeventwebhook"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.SecurityEventWebhook{}
			}, true)
			defer shutdownServer()
			if err := testSecurityEventWebhookClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-securityeventwebhook test failed")
	}
}

func testSecurityEventWebhookClient(client calicoclient.Interface, name string) error {
	SEWClient := client.ProjectcalicoV3().SecurityEventWebhooks()
	securityEventWebhook := &v3.SecurityEventWebhook{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.SecurityEventWebhookSpec{
			Consumer: "Slack",
			State:    "Enabled",
			Query:    "selector-1",
			Config:   []v3.SecurityEventWebhookConfigVar{},
		},
	}
	ctx := context.Background()

	// start from scratch
	securityEventWebhooks, err := SEWClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing SecurityEventWebhooks (%s)", err)
	}
	if securityEventWebhooks.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	securityEventWebhookServer, err := SEWClient.Create(ctx, securityEventWebhook, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the SecurityEventWebhook '%v' (%v)", securityEventWebhook, err)
	}
	if name != securityEventWebhookServer.Name {
		return fmt.Errorf("didn't get the same SecurityEventWebhook back from the server \n%+v\n%+v", securityEventWebhook, securityEventWebhookServer)
	}

	securityEventWebhooks, err = SEWClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing SecurityEventWebhooks (%s)", err)
	}
	if len(securityEventWebhooks.Items) != 1 {
		return fmt.Errorf("expected 1 SecurityEventWebhooks got %d", len(securityEventWebhooks.Items))
	}

	securityEventWebhookServer, err = SEWClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting SecurityEventWebhook %s (%s)", name, err)
	}
	if name != securityEventWebhookServer.Name && securityEventWebhook.ResourceVersion == securityEventWebhookServer.ResourceVersion {
		return fmt.Errorf("didn't get the same SecurityEventWebhook back from the server \n%+v\n%+v", securityEventWebhook, securityEventWebhookServer)
	}

	err = SEWClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("SecurityEventWebhook should be deleted (%s)", err)
	}

	// Test SecurityEventWebhooks watch
	w, err := client.ProjectcalicoV3().SecurityEventWebhooks().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching SecurityEventWebhooks (%s)", err)
	}

	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error

	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out wating for events")
				return
			}
		}
	}()

	// Create two SecurityEventWebhooks
	for i := 0; i < 2; i++ {
		ga := &v3.SecurityEventWebhook{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("ga%d", i)},
			Spec: v3.SecurityEventWebhookSpec{
				Consumer: "Jira",
				State:    "Debug",
				Query:    "selector-2",
				Config:   []v3.SecurityEventWebhookConfigVar{},
			},
		}
		_, err = SEWClient.Create(ctx, ga, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating the SecurityEventWebhook '%v' (%v)", ga, err)
		}
	}

	done.Wait()

	if timeoutErr != nil {
		return timeoutErr
	}

	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestGlobalAlertClient exercises the GlobalAlert client.
func TestGlobalAlertClient(t *testing.T) {
	const name = "test-globalalert"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.GlobalAlert{}
			}, true)
			defer shutdownServer()
			if err := testGlobalAlertClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-globalalert test failed")
	}
}

func testGlobalAlertClient(client calicoclient.Interface, name string) error {
	globalAlertClient := client.ProjectcalicoV3().GlobalAlerts()
	globalAlert := &v3.GlobalAlert{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.GlobalAlertSpec{
			DataSet:     "dns",
			Description: "test",
			Severity:    100,
		},
		Status: v3.GlobalAlertStatus{
			LastUpdate:   &metav1.Time{Time: time.Now()},
			Active:       false,
			Healthy:      false,
			LastExecuted: &metav1.Time{Time: time.Now()},
			LastEvent:    &metav1.Time{Time: time.Now()},
			ErrorConditions: []v3.ErrorCondition{
				{Type: "foo", Message: "bar"},
			},
		},
	}
	ctx := context.Background()

	// start from scratch
	globalAlerts, err := globalAlertClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalAlerts (%s)", err)
	}
	if globalAlerts.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	globalAlertServer, err := globalAlertClient.Create(ctx, globalAlert, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the globalAlert '%v' (%v)", globalAlert, err)
	}
	if name != globalAlertServer.Name {
		return fmt.Errorf("didn't get the same globalAlert back from the server \n%+v\n%+v", globalAlert, globalAlertServer)
	}
	if !reflect.DeepEqual(globalAlertServer.Status, v3.GlobalAlertStatus{}) {
		return fmt.Errorf("status was set on create to %#v", globalAlertServer.Status)
	}

	globalAlerts, err = globalAlertClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalAlerts (%s)", err)
	}
	if len(globalAlerts.Items) != 1 {
		return fmt.Errorf("expected 1 globalAlert got %d", len(globalAlerts.Items))
	}

	globalAlertServer, err = globalAlertClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting globalAlert %s (%s)", name, err)
	}
	if name != globalAlertServer.Name &&
		globalAlert.ResourceVersion == globalAlertServer.ResourceVersion {
		return fmt.Errorf("didn't get the same globalAlert back from the server \n%+v\n%+v", globalAlert, globalAlertServer)
	}

	globalAlertUpdate := globalAlertServer.DeepCopy()
	globalAlertUpdate.Spec.Description += "-updated"
	globalAlertUpdate.Status.LastUpdate = &metav1.Time{Time: time.Now()}
	globalAlertServer, err = globalAlertClient.Update(ctx, globalAlertUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating globalAlert %s (%s)", name, err)
	}
	if globalAlertServer.Spec.Description != globalAlertUpdate.Spec.Description {
		return errors.New("didn't update spec.content")
	}
	if globalAlertServer.Status.LastUpdate != nil {
		return errors.New("status was updated by Update()")
	}

	globalAlertUpdate = globalAlertServer.DeepCopy()
	globalAlertUpdate.Status.LastUpdate = &metav1.Time{Time: time.Now()}
	globalAlertUpdate.Labels = map[string]string{"foo": "bar"}
	statusDescription := "status"
	globalAlertUpdate.Spec.Description = statusDescription
	globalAlertServer, err = globalAlertClient.UpdateStatus(ctx, globalAlertUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating globalAlert %s (%s)", name, err)
	}
	if globalAlertServer.Status.LastUpdate == nil {
		return fmt.Errorf("didn't update status. %v != %v", globalAlertUpdate.Status, globalAlertServer.Status)
	}
	if _, ok := globalAlertServer.Labels["foo"]; ok {
		return fmt.Errorf("updatestatus updated labels")
	}
	if globalAlertServer.Spec.Description == statusDescription {
		return fmt.Errorf("updatestatus updated spec")
	}

	err = globalAlertClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("globalAlert should be deleted (%s)", err)
	}

	// Test watch
	w, err := client.ProjectcalicoV3().GlobalAlerts().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching GlobalAlerts (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out wating for events")
				return
			}
		}
	}()

	// Create two GlobalAlerts
	for i := 0; i < 2; i++ {
		ga := &v3.GlobalAlert{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("ga%d", i)},
			Spec: v3.GlobalAlertSpec{
				Description: "test",
				Severity:    100,
				DataSet:     "dns",
			},
		}
		_, err = globalAlertClient.Create(ctx, ga, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating the globalAlert '%v' (%v)", ga, err)
		}
	}
	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestGlobalAlertTemplateClient exercises the GlobalAlertTemplate client.
func TestGlobalAlertTemplateClient(t *testing.T) {
	const name = "test-globalalert"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.GlobalAlertTemplate{}
			}, true)
			defer shutdownServer()
			if err := testGlobalAlertTemplateClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-globalalert test failed")
	}
}

func testGlobalAlertTemplateClient(client calicoclient.Interface, name string) error {
	globalAlertClient := client.ProjectcalicoV3().GlobalAlertTemplates()
	globalAlert := &v3.GlobalAlertTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.GlobalAlertSpec{
			Summary:     "foo",
			DataSet:     "dns",
			Description: "test",
			Severity:    100,
		},
	}
	ctx := context.Background()

	// start from scratch
	globalAlerts, err := globalAlertClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalAlertTemplates (%s)", err)
	}
	if globalAlerts.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	globalAlertServer, err := globalAlertClient.Create(ctx, globalAlert, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the globalAlertTemplate '%v' (%v)", globalAlert, err)
	}
	if name != globalAlertServer.Name {
		return fmt.Errorf("didn't get the same globalAlertTemplate back from the server \n%+v\n%+v", globalAlert, globalAlertServer)
	}

	globalAlerts, err = globalAlertClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalAlertTemplates (%s)", err)
	}
	if len(globalAlerts.Items) != 1 {
		return fmt.Errorf("expected 1 globalAlertTemplate got %d", len(globalAlerts.Items))
	}

	globalAlertServer, err = globalAlertClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting globalAlertTemplate %s (%s)", name, err)
	}
	if name != globalAlertServer.Name &&
		globalAlert.ResourceVersion == globalAlertServer.ResourceVersion {
		return fmt.Errorf("didn't get the same globalAlertTemplate back from the server \n%+v\n%+v", globalAlert, globalAlertServer)
	}

	globalAlertUpdate := globalAlertServer.DeepCopy()
	globalAlertUpdate.Spec.Description += "-update"
	globalAlertServer, err = globalAlertClient.Update(ctx, globalAlertUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating globalAlertTemplate %s (%s)", name, err)
	}
	if globalAlertServer.Spec.Description != globalAlertUpdate.Spec.Description {
		return errors.New("didn't update spec.content")
	}

	err = globalAlertClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("globalAlertTemplate should be deleted (%s)", err)
	}

	// Test watch
	w, err := client.ProjectcalicoV3().GlobalAlertTemplates().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching GlobalAlertTemplates (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out wating for events")
				return
			}
		}
	}()

	// Create two GlobalAlertTemplates
	for i := 0; i < 2; i++ {
		ga := &v3.GlobalAlertTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("ga%d", i)},
			Spec: v3.GlobalAlertSpec{
				Summary:     "bar",
				Description: "test",
				Severity:    100,
				DataSet:     "dns",
			},
		}
		_, err = globalAlertClient.Create(ctx, ga, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating the globalAlertTemplate '%v' (%v)", ga, err)
		}
	}
	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestGlobalThreatFeedClient exercises the GlobalThreatFeed client.
func TestGlobalThreatFeedClient(t *testing.T) {
	const name = "test-globalthreatfeed"
	mode := v3.ThreatFeedModeEnabled

	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.GlobalThreatFeed{
					Spec: v3.GlobalThreatFeedSpec{
						Mode:        &mode,
						Description: "test",
					},
				}
			}, true)
			defer shutdownServer()
			if err := testGlobalThreatFeedClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-globalthreatfeed test failed")
	}
}

// TestIPReservationClient exercises the IPReservation client.
func TestIPReservationClient(t *testing.T) {
	const name = "test-ipreservation"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.IPReservation{}
			}, true)
			defer shutdownServer()
			if err := testIPReservationClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-ipreservation test failed")
	}
}

func testIPReservationClient(client calicoclient.Interface, name string) error {
	ipreservationClient := client.ProjectcalicoV3().IPReservations()
	ipreservation := &v3.IPReservation{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.IPReservationSpec{
			ReservedCIDRs: []string{"192.168.0.0/16"},
		},
	}
	ctx := context.Background()

	// start from scratch
	ipreservations, err := ipreservationClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ipreservations (%s)", err)
	}
	if ipreservations.Items == nil {
		return fmt.Errorf("items field should not be set to nil")
	}

	ipreservationServer, err := ipreservationClient.Create(ctx, ipreservation, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the ipreservation '%v' (%v)", ipreservation, err)
	}
	if name != ipreservationServer.Name {
		return fmt.Errorf("didn't get the same ipreservation back from the server \n%+v\n%+v", ipreservation, ipreservationServer)
	}

	_, err = ipreservationClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ipreservations (%s)", err)
	}

	ipreservationServer, err = ipreservationClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting ipreservation %s (%s)", name, err)
	}
	if name != ipreservationServer.Name &&
		ipreservation.ResourceVersion == ipreservationServer.ResourceVersion {
		return fmt.Errorf("didn't get the same ipreservation back from the server \n%+v\n%+v", ipreservation, ipreservationServer)
	}

	err = ipreservationClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("ipreservation should be deleted (%s)", err)
	}

	return nil
}

func testGlobalThreatFeedClient(client calicoclient.Interface, name string) error {
	mode := v3.ThreatFeedModeEnabled

	globalThreatFeedClient := client.ProjectcalicoV3().GlobalThreatFeeds()
	globalThreatFeed := &v3.GlobalThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.GlobalThreatFeedSpec{
			Mode:        &mode,
			Description: "test",
		},
		Status: v3.GlobalThreatFeedStatus{
			LastSuccessfulSync:   &metav1.Time{Time: time.Now()},
			LastSuccessfulSearch: &metav1.Time{Time: time.Now()},
			ErrorConditions: []v3.ErrorCondition{
				{
					Type:    "foo",
					Message: "bar",
				},
			},
		},
	}
	ctx := context.Background()

	// start from scratch
	globalThreatFeeds, err := globalThreatFeedClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalThreatFeeds (%s)", err)
	}
	if globalThreatFeeds.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	globalThreatFeedServer, err := globalThreatFeedClient.Create(ctx, globalThreatFeed, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the globalThreatFeed '%v' (%v)", globalThreatFeed, err)
	}
	if name != globalThreatFeedServer.Name {
		return fmt.Errorf("didn't get the same globalThreatFeed back from the server \n%+v\n%+v", globalThreatFeed, globalThreatFeedServer)
	}
	if !reflect.DeepEqual(globalThreatFeedServer.Status, v3.GlobalThreatFeedStatus{}) {
		return fmt.Errorf("status was set on create to %#v", globalThreatFeedServer.Status)
	}

	globalThreatFeeds, err = globalThreatFeedClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalThreatFeeds (%s)", err)
	}
	if len(globalThreatFeeds.Items) != 1 {
		return fmt.Errorf("expected 1 globalThreatFeed got %d", len(globalThreatFeeds.Items))
	}

	globalThreatFeedServer, err = globalThreatFeedClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting globalThreatFeed %s (%s)", name, err)
	}
	if name != globalThreatFeedServer.Name &&
		globalThreatFeed.ResourceVersion == globalThreatFeedServer.ResourceVersion {
		return fmt.Errorf("didn't get the same globalThreatFeed back from the server \n%+v\n%+v", globalThreatFeed, globalThreatFeedServer)
	}

	globalThreatFeedUpdate := globalThreatFeedServer.DeepCopy()
	globalThreatFeedUpdate.Spec.Content = "IPSet"
	globalThreatFeedUpdate.Spec.Mode = &mode
	globalThreatFeedUpdate.Spec.Description = "test"
	globalThreatFeedUpdate.Status.LastSuccessfulSync = &metav1.Time{Time: time.Now()}
	globalThreatFeedServer, err = globalThreatFeedClient.Update(ctx, globalThreatFeedUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating globalThreatFeed %s (%s)", name, err)
	}
	if globalThreatFeedServer.Spec.Content != globalThreatFeedUpdate.Spec.Content {
		return errors.New("didn't update spec.content")
	}
	if globalThreatFeedServer.Status.LastSuccessfulSync != nil {
		return errors.New("status was updated by Update()")
	}

	// NOTE: The update status test currently doesn't work because the GlobalThreatFeed's crd.projectcalico.org status
	// is set as a subresource and the apiserver doesn't handle subresource yet. Uncomment this when this is dealt with.

	globalThreatFeedUpdate = globalThreatFeedServer.DeepCopy()
	globalThreatFeedUpdate.Status.LastSuccessfulSync = &metav1.Time{Time: time.Now()}
	globalThreatFeedUpdate.Labels = map[string]string{"foo": "bar"}
	globalThreatFeedUpdate.Spec.Content = ""
	globalThreatFeedServer, err = globalThreatFeedClient.UpdateStatus(ctx, globalThreatFeedUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating globalThreatFeed %s (%s)", name, err)
	}
	if globalThreatFeedServer.Status.LastSuccessfulSync == nil {
		return fmt.Errorf("didn't update status. %v != %v", globalThreatFeedUpdate.Status, globalThreatFeedServer.Status)
	}
	if _, ok := globalThreatFeedServer.Labels["foo"]; ok {
		return fmt.Errorf("updatestatus updated labels")
	}
	if globalThreatFeedServer.Spec.Content == "" {
		return fmt.Errorf("updatestatus updated spec")
	}

	err = globalThreatFeedClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("globalThreatFeed should be deleted (%s)", err)
	}

	// Test watch
	w, err := client.ProjectcalicoV3().GlobalThreatFeeds().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching GlobalThreatFeeds (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out wating for events")
				return
			}
		}
	}()

	// Create two GlobalThreatFeeds
	for i := 0; i < 2; i++ {
		gtf := &v3.GlobalThreatFeed{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("gtf%d", i)},
			Spec: v3.GlobalThreatFeedSpec{
				Mode:        &mode,
				Description: "test",
			},
		}
		_, err = globalThreatFeedClient.Create(ctx, gtf, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating the globalThreatFeed '%v' (%v)", gtf, err)
		}
	}
	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	// Delete two GlobalThreatFeeds
	for i := 0; i < 2; i++ {
		gtf := fmt.Sprintf("gtf%d", i)
		err = globalThreatFeedClient.Delete(ctx, gtf, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("error creating the globalThreatFeed '%v' (%v)", gtf, err)
		}
	}

	return nil
}

// TestHostEndpointClient exercises the HostEndpoint client.
func TestHostEndpointClient(t *testing.T) {
	const name = "test-hostendpoint"
	client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
		return &v3.HostEndpoint{}
	}, true)
	defer shutdownServer()
	defer func() {
		_ = deleteHostEndpointClient(client, name)
	}()
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.HostEndpoint{}
			}, true)
			defer shutdownServer()
			if err := testHostEndpointClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-hostendpoint test failed")
	}
}

func createTestHostEndpoint(name string, ip string, node string) *v3.HostEndpoint {
	hostEndpoint := &v3.HostEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	hostEndpoint.Spec.ExpectedIPs = []string{ip}
	hostEndpoint.Spec.Node = node

	return hostEndpoint
}

func deleteHostEndpointClient(client calicoclient.Interface, name string) error {
	hostEndpointClient := client.ProjectcalicoV3().HostEndpoints()
	ctx := context.Background()

	return hostEndpointClient.Delete(ctx, name, metav1.DeleteOptions{})
}

func testHostEndpointClient(client calicoclient.Interface, name string) error {
	hostEndpointClient := client.ProjectcalicoV3().HostEndpoints()

	hostEndpoint := createTestHostEndpoint(name, "192.168.0.1", "test-node")
	ctx := context.Background()

	// start from scratch
	hostEndpoints, err := hostEndpointClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing hostEndpoints (%s)", err)
	}
	if hostEndpoints.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	hostEndpointServer, err := hostEndpointClient.Create(ctx, hostEndpoint, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the hostEndpoint '%v' (%v)", hostEndpoint, err)
	}
	if name != hostEndpointServer.Name {
		return fmt.Errorf("didn't get the same hostEndpoint back from the server \n%+v\n%+v", hostEndpoint, hostEndpointServer)
	}

	hostEndpoints, err = hostEndpointClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing hostEndpoints (%s)", err)
	}
	if len(hostEndpoints.Items) != 1 {
		return fmt.Errorf("expected 1 hostEndpoint entry, got %d", len(hostEndpoints.Items))
	}

	hostEndpointServer, err = hostEndpointClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting hostEndpoint %s (%s)", name, err)
	}
	if name != hostEndpointServer.Name &&
		hostEndpoint.ResourceVersion == hostEndpointServer.ResourceVersion {
		return fmt.Errorf("didn't get the same hostEndpoint back from the server \n%+v\n%+v", hostEndpoint, hostEndpointServer)
	}

	err = hostEndpointClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("hostEndpoint should be deleted (%s)", err)
	}

	// Test watch
	w, err := client.ProjectcalicoV3().HostEndpoints().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching HostEndpoints (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out wating for events")
				return
			}
		}
	}()

	// Create two HostEndpoints
	for i := 0; i < 2; i++ {
		hep := createTestHostEndpoint(fmt.Sprintf("hep%d", i), "192.168.0.1", "test-node")
		_, err = hostEndpointClient.Create(ctx, hep, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating hostEndpoint '%v' (%v)", hep, err)
		}
	}

	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestGlobalReportClient exercises the GlobalReport client.
func TestGlobalReportClient(t *testing.T) {
	const name = "test-global-report"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.GlobalReport{}
			}, true)
			defer shutdownServer()
			if err := testGlobalReportClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("GlobalReport test failed")
	}
}

func testGlobalReportClient(client calicoclient.Interface, name string) error {
	globalReportTypeName := "inventory"
	globalReportClient := client.ProjectcalicoV3().GlobalReports()
	globalReport := &v3.GlobalReport{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.ReportSpec{
			ReportType: globalReportTypeName,
		},
		Status: v3.ReportStatus{
			LastSuccessfulReportJobs: []v3.CompletedReportJob{
				{
					ReportJob: v3.ReportJob{
						Start: metav1.Time{Time: time.Now()},
						End:   metav1.Time{Time: time.Now()},
						Job: &corev1.ObjectReference{
							Kind:      "NetworkPolicy",
							Name:      "fbar-srj",
							Namespace: "fbar-ns-srj",
						},
					},
					JobCompletionTime: &metav1.Time{Time: time.Now()},
				},
			},
			LastFailedReportJobs: []v3.CompletedReportJob{
				{
					ReportJob: v3.ReportJob{
						Start: metav1.Time{Time: time.Now()},
						End:   metav1.Time{Time: time.Now()},
						Job: &corev1.ObjectReference{
							Kind:      "NetworkPolicy",
							Name:      "fbar-frj",
							Namespace: "fbar-ns-frj",
						},
					},
					JobCompletionTime: &metav1.Time{Time: time.Now()},
				},
			},
			ActiveReportJobs: []v3.ReportJob{
				{
					Start: metav1.Time{Time: time.Now()},
					End:   metav1.Time{Time: time.Now()},
					Job: &corev1.ObjectReference{
						Kind:      "NetworkPolicy",
						Name:      "fbar-arj",
						Namespace: "fbar-ns-arj",
					},
				},
			},
			LastScheduledReportJob: &v3.ReportJob{
				Start: metav1.Time{Time: time.Now()},
				End:   metav1.Time{Time: time.Now()},
				Job: &corev1.ObjectReference{
					Kind:      "NetworkPolicy",
					Name:      "fbar-lsj",
					Namespace: "fbar-ns-lsj",
				},
			},
		},
	}
	ctx := context.Background()

	// Make sure there is no GlobalReport configured.
	globalReports, err := globalReportClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalReports (%s)", err)
	}
	if globalReports.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	// Create/List/Get/Delete tests.

	// We now need a GlobalReportType resource before GlobalReport can be created.
	globalReportTypeClient := client.ProjectcalicoV3().GlobalReportTypes()
	globalReportType := &v3.GlobalReportType{
		ObjectMeta: metav1.ObjectMeta{Name: globalReportTypeName},
		Spec: v3.ReportTypeSpec{
			UISummaryTemplate: v3.ReportTemplate{
				Name:     "uist",
				Template: "Report Name: {{ .ReportName }}",
			},
		},
	}
	_, err = globalReportTypeClient.Create(ctx, globalReportType, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the pre-requisite globalReportType '%v' (%v)", globalReportType, err)
	}

	globalReportServer, err := globalReportClient.Create(ctx, globalReport, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the globalReport '%v' (%v)", globalReport, err)
	}
	if name != globalReportServer.Name {
		return fmt.Errorf("didn't get the same globalReport back from the server \n%+v\n%+v", globalReport, globalReportServer)
	}
	if !reflect.DeepEqual(globalReportServer.Status, v3.ReportStatus{}) {
		return fmt.Errorf("status was set on create to %#v", globalReportServer.Status)
	}

	globalReports, err = globalReportClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalReports (%s)", err)
	}
	if len(globalReports.Items) != 1 {
		return fmt.Errorf("expected 1 globalReport entry, got %d", len(globalReports.Items))
	}

	globalReportServer, err = globalReportClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting globalReport %s (%s)", name, err)
	}
	if name != globalReportServer.Name &&
		globalReport.ResourceVersion == globalReportServer.ResourceVersion {
		return fmt.Errorf("didn't get the same globalReport back from the server \n%+v\n%+v", globalReport, globalReportServer)
	}

	// Pupulate both GlobalReport and ReportStatus.
	// Verify that Update() modifies GlobalReport only.
	globalReportUpdate := globalReportServer.DeepCopy()
	globalReportUpdate.Spec.Schedule = "1 * * * *"
	globalReportUpdate.Status.LastSuccessfulReportJobs = []v3.CompletedReportJob{
		{JobCompletionTime: &metav1.Time{Time: time.Now()}},
	}

	globalReportServer, err = globalReportClient.Update(ctx, globalReportUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating globalReport %s (%s)", name, err)
	}
	if globalReportServer.Spec.Schedule != globalReportUpdate.Spec.Schedule {
		return errors.New("GlobalReport Update() didn't update Spec.Schedule")
	}
	if len(globalReportServer.Status.LastSuccessfulReportJobs) != 0 {
		return errors.New("GlobalReport status was updated by Update()")
	}

	// Pupulate both GlobalReport and ReportStatus.
	// Verify that UpdateStatus() modifies ReportStatus only.
	globalReportUpdate = globalReportServer.DeepCopy()
	globalReportUpdate.Status.LastSuccessfulReportJobs = []v3.CompletedReportJob{
		{ReportJob: v3.ReportJob{
			Start: metav1.Time{Time: time.Now()},
			End:   metav1.Time{Time: time.Now()},
			Job:   &corev1.ObjectReference{},
		}, JobCompletionTime: &metav1.Time{Time: time.Now()}},
	}
	globalReportUpdate.Labels = map[string]string{"foo": "bar"}
	globalReportServer, err = globalReportClient.UpdateStatus(ctx, globalReportUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating globalReport status %s (%s)", name, err)
	}
	if len(globalReportServer.Status.LastSuccessfulReportJobs) == 0 ||
		globalReportServer.Status.LastSuccessfulReportJobs[0].JobCompletionTime == nil ||
		globalReportServer.Status.LastSuccessfulReportJobs[0].JobCompletionTime.Time.Equal(time.Time{}) {
		return fmt.Errorf("didn't update GlobalReport status. %v != %v", globalReportUpdate.Status, globalReportServer.Status)
	}
	if _, ok := globalReportServer.Labels["foo"]; ok {
		return fmt.Errorf("updatestatus updated labels")
	}

	err = globalReportClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("globalReport should be deleted (%s)", err)
	}

	// Check list-ing GlobalReport resource works with watch option.
	w, err := client.ProjectcalicoV3().GlobalReports().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching GlobalReports (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out wating for events")
				return
			}
		}
	}()

	// Create two GlobalReports
	for i := 0; i < 2; i++ {
		gr := &v3.GlobalReport{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("gr%d", i)},
			Spec:       v3.ReportSpec{ReportType: "inventory"},
		}
		_, err = globalReportClient.Create(ctx, gr, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating globalReport '%v' (%v)", gr, err)
		}
	}

	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	// Undo pre-requisite creating GlobalReportType.
	err = globalReportTypeClient.Delete(ctx, globalReportTypeName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("error deleting the pre-requisite globalReportType '%v' (%v)", globalReportType, err)
	}

	return nil
}

// TestGlobalReportTypeClient exercises the GlobalReportType client.
func TestGlobalReportTypeClient(t *testing.T) {
	const name = "test-global-report-type"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.GlobalReportType{}
			}, true)
			defer shutdownServer()
			if err := testGlobalReportTypeClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("GlobalReportType test failed")
	}
}

func testGlobalReportTypeClient(client calicoclient.Interface, name string) error {
	globalReportTypeClient := client.ProjectcalicoV3().GlobalReportTypes()
	globalReportType := &v3.GlobalReportType{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.ReportTypeSpec{
			UISummaryTemplate: v3.ReportTemplate{
				Name:     "uist",
				Template: "Report Name: {{ .ReportName }}",
			},
		},
	}
	ctx := context.Background()

	// Make sure there is no GlobalReportType configured.
	globalReportTypes, err := globalReportTypeClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalReportTypes (%s)", err)
	}
	if globalReportTypes.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	// Create/List/Get/Delete tests.
	globalReportTypeServer, err := globalReportTypeClient.Create(ctx, globalReportType, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the globalReportType '%v' (%v)", globalReportType, err)
	}
	if name != globalReportTypeServer.Name {
		return fmt.Errorf("didn't get the same globalReportType back from the server \n%+v\n%+v", globalReportType, globalReportTypeServer)
	}

	globalReportTypes, err = globalReportTypeClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalReportTypes (%s)", err)
	}
	if len(globalReportTypes.Items) != 1 {
		return fmt.Errorf("expected 1 globalReportType entry, got %d", len(globalReportTypes.Items))
	}

	globalReportTypeServer, err = globalReportTypeClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting globalReportType %s (%s)", name, err)
	}
	if name != globalReportTypeServer.Name &&
		globalReportType.ResourceVersion == globalReportTypeServer.ResourceVersion {
		return fmt.Errorf("didn't get the same globalReportType back from the server \n%+v\n%+v", globalReportType, globalReportTypeServer)
	}

	err = globalReportTypeClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("globalReportType should be deleted (%s)", err)
	}

	// Check list-ing GlobalReportType resource works with watch option.
	w, err := client.ProjectcalicoV3().GlobalReportTypes().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching GlobalReportTypes (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out wating for events")
				return
			}
		}
	}()

	// Create two GlobalReports
	for i := 0; i < 2; i++ {
		grt := &v3.GlobalReportType{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("grt%d", i)},
			Spec: v3.ReportTypeSpec{
				UISummaryTemplate: v3.ReportTemplate{
					Name:     fmt.Sprintf("uist%d", i),
					Template: "Report Name: {{ .ReportName }}",
				},
			},
		}
		_, err = globalReportTypeClient.Create(ctx, grt, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating globalReportType '%v' (%v)", grt, err)
		}
	}

	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestIPPoolClient exercises the IPPool client.
func TestIPPoolClient(t *testing.T) {
	const name = "test-ippool"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.IPPool{}
			}, true)
			defer shutdownServer()
			if err := testIPPoolClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-ippool test failed")
	}
}

func testIPPoolClient(client calicoclient.Interface, name string) error {
	ippoolClient := client.ProjectcalicoV3().IPPools()
	ippool := &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.IPPoolSpec{
			CIDR: "192.168.0.0/16",
		},
	}
	ctx := context.Background()

	// start from scratch
	ippools, err := ippoolClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ippools (%s)", err)
	}
	if ippools.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	ippoolServer, err := ippoolClient.Create(ctx, ippool, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the ippool '%v' (%v)", ippool, err)
	}
	if name != ippoolServer.Name {
		return fmt.Errorf("didn't get the same ippool back from the server \n%+v\n%+v", ippool, ippoolServer)
	}

	_, err = ippoolClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ippools (%s)", err)
	}

	ippoolServer, err = ippoolClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting ippool %s (%s)", name, err)
	}
	if name != ippoolServer.Name &&
		ippool.ResourceVersion == ippoolServer.ResourceVersion {
		return fmt.Errorf("didn't get the same ippool back from the server \n%+v\n%+v", ippool, ippoolServer)
	}

	err = ippoolClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("ippool should be deleted (%s)", err)
	}

	return nil
}

// TestBGPConfigurationClient exercises the BGPConfiguration client.
func TestBGPConfigurationClient(t *testing.T) {
	const name = "test-bgpconfig"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.BGPConfiguration{}
			}, true)
			defer shutdownServer()
			if err := testBGPConfigurationClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-bgpconfig test failed")
	}
}

func testBGPConfigurationClient(client calicoclient.Interface, name string) error {
	bgpConfigClient := client.ProjectcalicoV3().BGPConfigurations()
	resName := "bgpconfig-test"
	bgpConfig := &v3.BGPConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: resName},
		Spec: v3.BGPConfigurationSpec{
			LogSeverityScreen: "Info",
		},
	}
	ctx := context.Background()

	// start from scratch
	bgpConfigList, err := bgpConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing bgpConfiguration (%s)", err)
	}
	if bgpConfigList.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	bgpRes, err := bgpConfigClient.Create(ctx, bgpConfig, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the bgpConfiguration '%v' (%v)", bgpConfig, err)
	}
	if resName != bgpRes.Name {
		return fmt.Errorf("didn't get the same bgpConfig back from server\n%+v\n%+v", bgpConfig, bgpRes)
	}

	_, err = bgpConfigClient.Get(ctx, resName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting bgpConfiguration %s (%s)", resName, err)
	}

	err = bgpConfigClient.Delete(ctx, resName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("BGPConfiguration should be deleted (%s)", err)
	}

	return nil
}

// TestBGPPeerClient exercises the BGPPeer client.
func TestBGPPeerClient(t *testing.T) {
	const name = "test-bgppeer"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.BGPPeer{}
			}, true)
			defer shutdownServer()
			if err := testBGPPeerClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-bgppeer test failed")
	}
}

func testBGPPeerClient(client calicoclient.Interface, name string) error {
	bgpPeerClient := client.ProjectcalicoV3().BGPPeers()
	resName := "bgppeer-test"
	bgpPeer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: resName},
		Spec: v3.BGPPeerSpec{
			Node:     "node1",
			PeerIP:   "10.0.0.1",
			ASNumber: numorstring.ASNumber(6512),
		},
	}
	ctx := context.Background()

	// start from scratch
	bgpPeerList, err := bgpPeerClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing bgpPeer (%s)", err)
	}
	if bgpPeerList.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	bgpRes, err := bgpPeerClient.Create(ctx, bgpPeer, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the bgpPeer '%v' (%v)", bgpPeer, err)
	}
	if resName != bgpRes.Name {
		return fmt.Errorf("didn't get the same bgpPeer back from server\n%+v\n%+v", bgpPeer, bgpRes)
	}

	_, err = bgpPeerClient.Get(ctx, resName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting bgpPeer %s (%s)", resName, err)
	}

	err = bgpPeerClient.Delete(ctx, resName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("BGPPeer should be deleted (%s)", err)
	}

	return nil
}

// TestProfileClient exercises the Profile client.
func TestProfileClient(t *testing.T) {
	// This matches the namespace that is created at test setup time in the Makefile.
	// TODO(doublek): Note that this currently only works for KDD mode.
	const name = "kns.namespace-1"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.Profile{}
			}, true)
			defer shutdownServer()
			if err := testProfileClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-profile test failed")
	}
}

func testProfileClient(client calicoclient.Interface, name string) error {
	profileClient := client.ProjectcalicoV3().Profiles()
	profile := &v3.Profile{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.ProfileSpec{
			LabelsToApply: map[string]string{
				"aa": "bb",
			},
		},
	}
	ctx := context.Background()

	// start from scratch
	profileList, err := profileClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing profile (%s)", err)
	}
	if profileList.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	// Profile creation is not supported.
	_, err = profileClient.Create(ctx, profile, metav1.CreateOptions{})
	if err == nil {
		return fmt.Errorf("profile should not be allowed to be created'%v' (%v)", profile, err)
	}

	profileRes, err := profileClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting profile %s (%s)", name, err)
	}

	if name != profileRes.Name {
		return fmt.Errorf("didn't get the same profile back from server\n%+v\n%+v", profile, profileRes)
	}

	// Profile deletion is not supported.
	err = profileClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err == nil {
		return fmt.Errorf("Profile cannot be deleted (%s)", err)
	}

	return nil
}

// TestRemoteClusterConfigurationClient exercises the RemoteClusterConfiguration client.
func TestRemoteClusterConfigurationClient(t *testing.T) {
	const name = "test-remoteclusterconfig"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.RemoteClusterConfiguration{}
			}, true)
			defer shutdownServer()
			if err := testRemoteClusterConfigurationClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-remoteclusterconfig test failed")
	}
}

func testRemoteClusterConfigurationClient(client calicoclient.Interface, name string) error {
	rccClient := client.ProjectcalicoV3().RemoteClusterConfigurations()
	resName := "rcc-test"
	rcc := &v3.RemoteClusterConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: resName},
		Spec: v3.RemoteClusterConfigurationSpec{
			DatastoreType: "etcdv3",
			EtcdConfig: v3.EtcdConfig{
				EtcdEndpoints: "https://127.0.0.1:999",
				EtcdUsername:  "user",
				EtcdPassword:  "abc123",
			},
		},
	}
	ctx := context.Background()

	// start from scratch
	rccList, err := rccClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing remoteClusterConfiguration (%s)", err)
	}
	if rccList.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	rccRes, err := rccClient.Create(ctx, rcc, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the remoteClusterConfiguration '%v' (%v)", rcc, err)
	}
	if resName != rccRes.Name {
		return fmt.Errorf("didn't get the same remoteClusterConfiguration back from server\n%+v\n%+v", rcc, rccRes)
	}

	_, err = rccClient.Get(ctx, resName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting remoteClusterConfiguration %s (%s)", resName, err)
	}

	err = rccClient.Delete(ctx, resName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("RemoteClusterConfiguration should be deleted (%s)", err)
	}

	return nil
}

// TestFelixConfigurationClient exercises the FelixConfiguration client.
func TestFelixConfigurationClient(t *testing.T) {
	const name = "test-felixconfig"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.FelixConfiguration{}
			}, true)
			defer shutdownServer()
			if err := testFelixConfigurationClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-felixConfig test failed")
	}
}

func testFelixConfigurationClient(client calicoclient.Interface, name string) error {
	felixConfigClient := client.ProjectcalicoV3().FelixConfigurations()
	ptrTrue := true
	ptrInt := 1432
	felixConfig := &v3.FelixConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.FelixConfigurationSpec{
			UseInternalDataplaneDriver: &ptrTrue,
			DataplaneDriver:            "test-dataplane-driver",
			MetadataPort:               &ptrInt,
		},
	}
	ctx := context.Background()

	// start from scratch
	felixConfigs, err := felixConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing felixConfigs (%s)", err)
	}
	if felixConfigs.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	felixConfigServer, err := felixConfigClient.Create(ctx, felixConfig, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the felixConfig '%v' (%v)", felixConfig, err)
	}
	if name != felixConfigServer.Name {
		return fmt.Errorf("didn't get the same felixConfig back from the server \n%+v\n%+v", felixConfig, felixConfigServer)
	}

	_, err = felixConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing felixConfigs (%s)", err)
	}

	felixConfigServer, err = felixConfigClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting felixConfig %s (%s)", name, err)
	}
	if name != felixConfigServer.Name &&
		felixConfig.ResourceVersion == felixConfigServer.ResourceVersion {
		return fmt.Errorf("didn't get the same felixConfig back from the server \n%+v\n%+v", felixConfig, felixConfigServer)
	}

	err = felixConfigClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("felixConfig should be deleted (%s)", err)
	}

	return nil
}

// TestKubeControllersConfigurationClient exercises the KubeControllersConfiguration client.
func TestKubeControllersConfigurationClient(t *testing.T) {
	const name = "test-kubecontrollersconfig"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.KubeControllersConfiguration{}
			}, true)
			defer shutdownServer()
			if err := testKubeControllersConfigurationClient(client); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-kubecontrollersconfig test failed")
	}
}

func testKubeControllersConfigurationClient(client calicoclient.Interface) error {
	kubeControllersConfigClient := client.ProjectcalicoV3().KubeControllersConfigurations()
	kubeControllersConfig := &v3.KubeControllersConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Status: v3.KubeControllersConfigurationStatus{
			RunningConfig: v3.KubeControllersConfigurationSpec{
				Controllers: v3.ControllersConfig{
					Node: &v3.NodeControllerConfig{
						SyncLabels: v3.Enabled,
					},
				},
			},
		},
	}
	ctx := context.Background()

	// start from scratch
	kubeControllersConfigs, err := kubeControllersConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing kubeControllersConfigs (%s)", err)
	}
	if kubeControllersConfigs.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	kubeControllersConfigServer, err := kubeControllersConfigClient.Create(ctx, kubeControllersConfig, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the kubeControllersConfig '%v' (%v)", kubeControllersConfig, err)
	}
	if kubeControllersConfigServer.Name != "default" {
		return fmt.Errorf("didn't get the same kubeControllersConfig back from the server \n%+v\n%+v", kubeControllersConfig, kubeControllersConfigServer)
	}
	if !reflect.DeepEqual(kubeControllersConfigServer.Status, v3.KubeControllersConfigurationStatus{}) {
		return fmt.Errorf("status was set on create to %#v", kubeControllersConfigServer.Status)
	}

	kubeControllersConfigs, err = kubeControllersConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing kubeControllersConfigs (%s)", err)
	}
	if len(kubeControllersConfigs.Items) != 1 {
		return fmt.Errorf("expected 1 kubeControllersConfig got %d", len(kubeControllersConfigs.Items))
	}

	kubeControllersConfigServer, err = kubeControllersConfigClient.Get(ctx, "default", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting kubeControllersConfig default (%s)", err)
	}
	if kubeControllersConfigServer.Name != "default" &&
		kubeControllersConfig.ResourceVersion == kubeControllersConfigServer.ResourceVersion {
		return fmt.Errorf("didn't get the same kubeControllersConfig back from the server \n%+v\n%+v", kubeControllersConfig, kubeControllersConfigServer)
	}

	kubeControllersConfigUpdate := kubeControllersConfigServer.DeepCopy()
	kubeControllersConfigUpdate.Spec.HealthChecks = v3.Enabled
	kubeControllersConfigUpdate.Status.EnvironmentVars = map[string]string{"FOO": "bar"}
	kubeControllersConfigServer, err = kubeControllersConfigClient.Update(ctx, kubeControllersConfigUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating kubeControllersConfig default (%s)", err)
	}
	if kubeControllersConfigServer.Spec.HealthChecks != kubeControllersConfigUpdate.Spec.HealthChecks {
		return errors.New("didn't update spec.content")
	}
	if kubeControllersConfigServer.Status.EnvironmentVars != nil {
		return errors.New("status was updated by Update()")
	}

	kubeControllersConfigUpdate = kubeControllersConfigServer.DeepCopy()
	kubeControllersConfigUpdate.Status.EnvironmentVars = map[string]string{"FIZZ": "buzz"}
	kubeControllersConfigUpdate.Labels = map[string]string{"foo": "bar"}
	kubeControllersConfigUpdate.Spec.HealthChecks = ""
	kubeControllersConfigServer, err = kubeControllersConfigClient.UpdateStatus(ctx, kubeControllersConfigUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating kubeControllersConfig default (%s)", err)
	}
	if !reflect.DeepEqual(kubeControllersConfigServer.Status, kubeControllersConfigUpdate.Status) {
		return fmt.Errorf("didn't update status. %v != %v", kubeControllersConfigUpdate.Status, kubeControllersConfigServer.Status)
	}
	if _, ok := kubeControllersConfigServer.Labels["foo"]; ok {
		return fmt.Errorf("updatestatus updated labels")
	}
	if kubeControllersConfigServer.Spec.HealthChecks == "" {
		return fmt.Errorf("updatestatus updated spec")
	}

	err = kubeControllersConfigClient.Delete(ctx, "default", metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("kubeControllersConfig should be deleted (%s)", err)
	}

	// Test watch
	w, err := client.ProjectcalicoV3().KubeControllersConfigurations().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching KubeControllersConfigurations (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out wating for events")
				return
			}
		}
	}()

	// Create, then delete KubeControllersConfigurations
	_, err = kubeControllersConfigClient.Create(ctx, kubeControllersConfig, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the kubeControllersConfig '%v' (%v)", kubeControllersConfig, err)
	}
	err = kubeControllersConfigClient.Delete(ctx, "default", metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("kubeControllersConfig should be deleted (%s)", err)
	}

	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestManagedClusterClient exercises the ManagedCluster client.
func TestManagedClusterClient(t *testing.T) {
	const name = "test-managedcluster"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			serverConfig := &TestServerConfig{
				etcdServerList: []string{"http://localhost:2379"},
				emptyObjFunc: func() runtime.Object {
					return &v3.ManagedCluster{}
				},
				enableManagedClusterCreateAPI: true,
				managementClusterAddr:         "example.org:1234",
				tunnelSecretName:              "tigera-management-cluster-connection",
				applyTigeraLicense:            true,
			}

			client, _, shutdownServer := customizeFreshApiserverAndClient(t, serverConfig)

			createCASecret(t)

			defer shutdownServer()
			if err := testManagedClusterClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx := context.Background()

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-managedcluster test failed")
	}

	t.Run(fmt.Sprintf("%s-Create API is disabled", name), func(t *testing.T) {
		serverConfig := &TestServerConfig{
			etcdServerList: []string{"http://localhost:2379"},
			emptyObjFunc: func() runtime.Object {
				return &v3.ManagedCluster{}
			},
			enableManagedClusterCreateAPI: false,
			tunnelSecretName:              "tigera-management-cluster-connection",
			applyTigeraLicense:            true,
		}

		client, _, shutdownServer := customizeFreshApiserverAndClient(t, serverConfig)
		defer shutdownServer()

		managedClusterClient := client.ProjectcalicoV3().ManagedClusters()
		managedCluster := &v3.ManagedCluster{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       v3.ManagedClusterSpec{},
		}
		_, err := managedClusterClient.Create(ctx, managedCluster, metav1.CreateOptions{})

		if err == nil {
			t.Fatal("Expected API to be disabled")
		}
		if !strings.Contains(err.Error(), "ManagementCluster must be configured before adding ManagedClusters") {
			t.Fatalf("Expected API err to indicate that API is disabled. Received: %v", err)
		}
	})
}

func createCASecret(t *testing.T) {
	kubeconfig := os.Getenv("KUBECONFIG")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Errorf("Failed to build K8S client configuration %s", err)
		t.Fail()
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Errorf("Cannot create k8s client due to %s", err)
		t.Fail()
	}

	_, err = SetupManagedClusterCreateRequirements(k8sClient)
	if err != nil {
		t.Errorf("failed to setup managed cluster create requirements %s", err.Error())
		t.Fail()
	}
}

func testManagedClusterClient(client calicoclient.Interface, name string) error {
	managedClusterClient := client.ProjectcalicoV3().ManagedClusters()
	managedCluster := &v3.ManagedCluster{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v3.ManagedClusterSpec{},
	}

	expectedInitialStatus := v3.ManagedClusterStatus{
		Conditions: []v3.ManagedClusterStatusCondition{
			{
				Status: v3.ManagedClusterStatusValueUnknown,
				Type:   v3.ManagedClusterStatusTypeConnected,
			},
		},
	}
	ctx := context.Background()

	// start from scratch
	managedClusters, err := managedClusterClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing managedClusters (%s)", err)
	}
	if managedClusters.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	// ------------------------------------------------------------------------------------------
	managedClusterServer, err := managedClusterClient.Create(ctx, managedCluster, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the managedCluster '%v' (%v)", managedCluster, err)
	}
	if name != managedClusterServer.Name {
		return fmt.Errorf("didn't get the same managedCluster back from the server \n%+v\n%+v", managedCluster, managedClusterServer)
	}
	endpoint := regexp.MustCompile("managementClusterAddr:\\s\"example.org:1234\"")
	ca := regexp.MustCompile(`management-cluster\.crt:\s\w+`)
	cert := regexp.MustCompile(`managed-cluster\.crt:\s\w+`)
	key := regexp.MustCompile(`managed-cluster\.key:\s\w+`)

	if len(managedClusterServer.Spec.InstallationManifest) == 0 {
		return fmt.Errorf("expected installationManifest to be populated when creating "+
			"%s \n%+v", managedCluster.Name, managedClusterServer)
	}

	if endpoint.FindStringIndex(managedClusterServer.Spec.InstallationManifest) == nil {
		return fmt.Errorf("expected installationManifest to contain %s when creating "+
			"%s \n%+v", "managementClusterAddr", managedCluster.Name, managedClusterServer)
	}

	if ca.FindStringIndex(managedClusterServer.Spec.InstallationManifest) == nil {
		return fmt.Errorf("expected installationManifest to contain %s when creating "+
			"%s \n%+v", "management-cluster.crt", managedCluster.Name, managedClusterServer)
	}

	if cert.FindStringIndex(managedClusterServer.Spec.InstallationManifest) == nil {
		return fmt.Errorf("expected installationManifest to contain %s when creating "+
			"%s \n%+v", "managed-cluster.crt", managedCluster.Name, managedClusterServer)
	}

	if key.FindStringIndex(managedClusterServer.Spec.InstallationManifest) == nil {
		return fmt.Errorf("expected installationManifest to contain %s when creating "+
			"%s \n%+v", "managed-cluster.key", managedCluster.Name, managedClusterServer)
	}

	fingerprint := managedClusterServer.Annotations["certs.tigera.io/active-fingerprint"]
	if len(fingerprint) == 0 {
		return fmt.Errorf("expected fingerprint when creating %s instead of \n%+v",
			managedCluster.Name, managedClusterServer)
	}

	// ------------------------------------------------------------------------------------------
	managedClusters, err = managedClusterClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing managedClusters (%s)", err)
	}
	if len(managedClusters.Items) != 1 {
		return fmt.Errorf("expected 1 managedCluster got %d", len(managedClusters.Items))
	}

	// ------------------------------------------------------------------------------------------
	managedClusterServer, err = managedClusterClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting managedCluster %s (%s)", name, err)
	}
	if name != managedClusterServer.Name &&
		managedCluster.ResourceVersion == managedClusterServer.ResourceVersion {
		return fmt.Errorf("didn't get the same managedCluster back from the server \n%+v\n%+v", managedCluster, managedClusterServer)
	}
	if !reflect.DeepEqual(managedClusterServer.Status, expectedInitialStatus) {
		return fmt.Errorf("status was set on create to %#v", managedClusterServer.Status)
	}
	if len(managedClusterServer.Spec.InstallationManifest) != 0 {
		return fmt.Errorf("expected installation manifest to be empty after creation instead of \n%+v", managedCluster)
	}
	// ------------------------------------------------------------------------------------------
	managedClusterUpdate := managedClusterServer.DeepCopy()
	managedClusterUpdate.Status.Conditions = []v3.ManagedClusterStatusCondition{
		{
			Message: "Connected to Managed Cluster",
			Reason:  "ConnectionSuccessful",
			Status:  v3.ManagedClusterStatusValueTrue,
			Type:    v3.ManagedClusterStatusTypeConnected,
		},
	}
	managedClusterServer, err = managedClusterClient.Update(ctx, managedClusterUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating managedCluster %s (%s)", name, err)
	}
	if !reflect.DeepEqual(managedClusterServer.Status, managedClusterUpdate.Status) {
		return fmt.Errorf("didn't update status %#v", managedClusterServer.Status)
	}
	// ------------------------------------------------------------------------------------------
	err = managedClusterClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("managedCluster should be deleted (%s)", err)
	}

	// Test watch
	w, err := client.ProjectcalicoV3().ManagedClusters().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching ManagedClusters (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(1000 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out wating for events")
				return
			}
		}
	}()

	// Create two ManagedClusters
	for i := 0; i < 2; i++ {
		mc := &v3.ManagedCluster{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("mc%d", i)},
		}
		_, err = managedClusterClient.Create(ctx, mc, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating the managedCluster '%v' (%v)", mc, err)
		}
	}
	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestClusterInformationClient exercises the ClusterInformation client.
func TestClusterInformationClient(t *testing.T) {
	const name = "default"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.ClusterInformation{}
			}, true)
			defer shutdownServer()
			if err := testClusterInformationClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-clusterinformation test failed")
	}
}

func testClusterInformationClient(client calicoclient.Interface, name string) error {
	clusterInformationClient := client.ProjectcalicoV3().ClusterInformations()
	ctx := context.Background()

	ci, err := clusterInformationClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ClusterInformation (%s)", err)
	}
	if ci.Items == nil {
		return fmt.Errorf("items field should not be set to nil")
	}

	// Confirm it's not possible to edit the default cluster information.
	info := ci.Items[0]
	info.Spec.CalicoVersion = "fakeVersion"
	_, err = clusterInformationClient.Update(ctx, &info, metav1.UpdateOptions{})
	if err == nil {
		return fmt.Errorf("expected error updating default clusterinformation")
	}

	// Should also not be able to delete it.
	err = clusterInformationClient.Delete(ctx, "default", metav1.DeleteOptions{})
	if err == nil {
		return fmt.Errorf("expected error updating default clusterinformation")
	}

	// Confirm it's not possible to create a clusterInformation obj with name other than "default"
	invalidClusterInfo := &v3.ClusterInformation{ObjectMeta: metav1.ObjectMeta{Name: "test-clusterinformation"}}

	_, err = clusterInformationClient.Create(ctx, invalidClusterInfo, metav1.CreateOptions{})
	if err == nil {
		return fmt.Errorf("expected error creating invalidClusterInfo with name other than \"default\"")
	}

	return nil
}

// TestAuthenticationReviewsClient exercises the AuthenticationReviews client.
func TestAuthenticationReviewsClient(t *testing.T) {
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.AuthenticationReview{}
			}, true)
			defer shutdownServer()
			if err := testAuthenticationReviewsClient(client); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run("test-authentication-reviews", rootTestFunc()) {
		t.Errorf("test-authentication-reviews failed")
	}
}

func testAuthenticationReviewsClient(client calicoclient.Interface) error {
	ar := v3.AuthenticationReview{}
	_, err := client.ProjectcalicoV3().AuthenticationReviews().Create(context.Background(), &ar, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	name := "name"
	groups := []string{name}
	extra := map[string][]string{name: groups}
	uid := "uid"

	ctx := request.NewContext()
	ctx = request.WithUser(ctx, &user.DefaultInfo{
		Name:   name,
		Groups: groups,
		Extra:  extra,
		UID:    uid,
	})

	auth := authenticationreview.NewREST()
	obj, err := auth.Create(ctx, auth.New(), nil, nil)
	if err != nil {
		return err
	}

	if obj == nil {
		return errors.New("expected an authentication review")
	}

	status := obj.(*v3.AuthenticationReview).Status
	if status.Name != name || status.Groups[0] != name || status.UID != uid || status.Extra[name][0] != name {
		return errors.New("unexpected user info from authentication review")
	}
	return nil
}

// TestAuthorizationReviewsClient exercises the AuthorizationReviews client.
func TestAuthorizationReviewsClient(t *testing.T) {
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			pcs, client, shutdownServer := getFreshApiserverServerAndClient(t, func() runtime.Object {
				return &v3.AuthorizationReview{}
			})
			defer shutdownServer()
			if err := testAuthorizationReviewsClient(pcs, client); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !t.Run("test-authorization-reviews", rootTestFunc()) {
		t.Errorf("test-authorization-reviews failed")
	}
}

func testAuthorizationReviewsClient(pcs *apiserver.ProjectCalicoServer, client calicoclient.Interface) error {
	// Check we are able to create the authorization review.
	ar := v3.AuthorizationReview{}
	_, err := client.ProjectcalicoV3().AuthorizationReviews().Create(context.Background(), &ar, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	// Create a user context.
	name := "name"
	groups := []string{name}
	extra := map[string][]string{name: groups}
	uid := "uid"

	ctx := request.NewContext()
	ctx = request.WithUser(ctx, &user.DefaultInfo{
		Name:   name,
		Groups: groups,
		Extra:  extra,
		UID:    uid,
	})

	// Create the authorization review REST backend using the instantiated RBAC helper.
	if pcs.RBACCalculator == nil {
		return fmt.Errorf("No RBAC calc")
	}
	auth := authorizationreview.NewREST(pcs.RBACCalculator)

	// For testing tier permissions.
	tierClient := client.ProjectcalicoV3().Tiers()
	order := float64(100.0)
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "net-sec"},
		Spec: v3.TierSpec{
			Order: &order,
		},
	}

	_, err = tierClient.Create(ctx, tier, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("Failed to create tier: %v", err)
	}
	defer func() {
		_ = tierClient.Delete(ctx, "net-sec", metav1.DeleteOptions{})
	}()

	// Get the users permissions.
	req := &v3.AuthorizationReview{
		Spec: v3.AuthorizationReviewSpec{
			ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
				{
					APIGroup:  "",
					Resources: []string{"namespaces"},
					Verbs:     []string{"create", "get"},
				},
				{
					APIGroup:  "",
					Resources: []string{"pods"},
					// Try some duplicates to make sure they are contracted.
					Verbs: []string{"patch", "create", "delete", "patch", "delete"},
				},
			},
		},
	}

	// The user will currently have no permissions, so the returned status should contain an entry for each resource
	// type and verb combination, but contain no match entries for each.
	obj, err := auth.Create(ctx, req, nil, nil)
	if err != nil {
		return fmt.Errorf("Failed to create AuthorizationReview: %v", err)
	}

	if obj == nil {
		return errors.New("expected an AuthorizationReview")
	}

	status := obj.(*v3.AuthorizationReview).Status

	if err := checkAuthorizationReviewStatus(status, v3.AuthorizationReviewStatus{
		AuthorizedResourceVerbs: []v3.AuthorizedResourceVerbs{
			{
				APIGroup: "",
				Resource: "namespaces",
				Verbs:    []v3.AuthorizedResourceVerb{{Verb: "create"}, {Verb: "get"}},
			}, {
				APIGroup: "",
				Resource: "pods",
				Verbs:    []v3.AuthorizedResourceVerb{{Verb: "create"}, {Verb: "delete"}, {Verb: "patch"}},
			},
		},
	}); err != nil {
		return err
	}

	return nil
}

func checkAuthorizationReviewStatus(actual, expected v3.AuthorizationReviewStatus) error {
	if reflect.DeepEqual(actual, expected) {
		return nil
	}

	actualBytes, _ := json.Marshal(actual)
	expectedBytes, _ := json.Marshal(expected)

	return fmt.Errorf("Expected status: %s\nActual Status: %s", string(expectedBytes), string(actualBytes))
}

// TestPacketCaptureClient exercises the PacketCaptures client.
func TestPacketCaptureClient(t *testing.T) {
	rootTestFunc := func() func(t *testing.T) {
		const name = "test-packetcapture"
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.PacketCapture{}
			}, true)
			defer shutdownServer()
			if err := testPacketCapturesClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run("test-packet-captures", rootTestFunc()) {
		t.Errorf("test-packet-captures failed")
	}
}

func testPacketCapturesClient(client calicoclient.Interface, name string) error {
	ctx := context.Background()
	err := createEnterprise(client, ctx)
	if err == nil {
		return fmt.Errorf("Could not create a license")
	}

	ns := "default"
	packetCaptureClient := client.ProjectcalicoV3().PacketCaptures(ns)
	packetCapture := &v3.PacketCapture{ObjectMeta: metav1.ObjectMeta{Name: name}}

	// start from scratch
	packetCaptures, err := packetCaptureClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing packetCaptures (%s)", err)
	}
	if packetCaptures.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}
	if len(packetCaptures.Items) > 0 {
		return fmt.Errorf("packetCaptures should not exist on start, had %v packetCaptures", len(packetCaptures.Items))
	}

	packetCaptureServer, err := packetCaptureClient.Create(ctx, packetCapture, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the packetCapture '%v' (%v)", packetCapture, err)
	}

	updatedPacketCapture := packetCaptureServer.DeepCopy()
	updatedPacketCapture.Labels = map[string]string{"foo": "bar"}
	packetCaptureServer, err = packetCaptureClient.Update(ctx, updatedPacketCapture, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error in updating the packetCapture '%v' (%v)", packetCapture, err)
	}

	updatedPacketCaptureWithStatus := packetCaptureServer.DeepCopy()
	updatedPacketCaptureWithStatus.Status = v3.PacketCaptureStatus{
		Files: []v3.PacketCaptureFile{
			{
				Node:      "node",
				FileNames: []string{"file1", "file2"},
			},
		},
	}

	packetCaptureServer, err = packetCaptureClient.UpdateStatus(ctx, updatedPacketCaptureWithStatus, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating the packetCapture '%v' (%v)", packetCaptureServer, err)
	}
	if !reflect.DeepEqual(packetCaptureServer.Status, updatedPacketCaptureWithStatus.Status) {
		return fmt.Errorf("didn't update status %#v", updatedPacketCaptureWithStatus.Status)
	}

	// Should be listing the packetCapture.
	packetCaptures, err = packetCaptureClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing packetCaptures (%s)", err)
	}
	if len(packetCaptures.Items) != 1 {
		return fmt.Errorf("should have exactly one packetCapture, had %v packetCaptures", len(packetCaptures.Items))
	}

	packetCaptureServer, err = packetCaptureClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting packetCapture %s (%s)", name, err)
	}
	if name != packetCaptureServer.Name &&
		packetCapture.ResourceVersion == packetCaptureServer.ResourceVersion {
		return fmt.Errorf("didn't get the same packetCapture back from the server \n%+v\n%+v", packetCapture, packetCaptureServer)
	}

	// Watch Test:
	opts := metav1.ListOptions{Watch: true}
	wIface, err := packetCaptureClient.Watch(ctx, opts)
	if err != nil {
		return fmt.Errorf("Error on watch")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range wIface.ResultChan() {
			fmt.Println("Watch object: ", e)
			break
		}
	}()

	err = packetCaptureClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("packetCapture should be deleted (%s)", err)
	}

	wg.Wait()
	return nil
}

// TestDeepPacketInspectionClient exercises the DeepPacketInspection client.
func TestDeepPacketInspectionClient(t *testing.T) {
	rootTestFunc := func() func(t *testing.T) {
		const name = "test-deeppacketinspection"
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.DeepPacketInspection{}
			}, true)
			defer shutdownServer()
			if err := testDeepPacketInspectionClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run("test-deep-packet-inspections", rootTestFunc()) {
		t.Errorf("test-deep-packet-inspections failed")
	}
}

func testDeepPacketInspectionClient(client calicoclient.Interface, name string) error {
	ctx := context.Background()
	err := createEnterprise(client, ctx)
	if err == nil {
		return fmt.Errorf("Could not create a license")
	}

	ns := "default"
	deepPacketInspectionClient := client.ProjectcalicoV3().DeepPacketInspections(ns)
	deepPacketInspection := &v3.DeepPacketInspection{ObjectMeta: metav1.ObjectMeta{Name: name}}

	// start from scratch
	deepPacketInspections, err := deepPacketInspectionClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing deepPacketInspections (%s)", err)
	}
	if deepPacketInspections.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}
	if len(deepPacketInspections.Items) > 0 {
		return fmt.Errorf("deepPacketInspection should not exist on start, had %v deepPacketInspection", len(deepPacketInspections.Items))
	}

	deepPacketInspectionServer, err := deepPacketInspectionClient.Create(ctx, deepPacketInspection, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the deepPacketInspection '%v' (%v)", deepPacketInspection, err)
	}

	updatedDeepPacketInspection := deepPacketInspectionServer.DeepCopy()
	updatedDeepPacketInspection.Labels = map[string]string{"foo": "bar"}
	updatedDeepPacketInspection.Spec = v3.DeepPacketInspectionSpec{Selector: "k8s-app == 'sample-app'"}
	deepPacketInspectionServer, err = deepPacketInspectionClient.Update(ctx, updatedDeepPacketInspection, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error in updating the deepPacketInspection '%v' (%v)", deepPacketInspection, err)
	}
	if !reflect.DeepEqual(deepPacketInspectionServer.Labels, updatedDeepPacketInspection.Labels) {
		return fmt.Errorf("didn't update label %#v", deepPacketInspectionServer.Labels)
	}
	if !reflect.DeepEqual(deepPacketInspectionServer.Spec, updatedDeepPacketInspection.Spec) {
		return fmt.Errorf("didn't update spec %#v", deepPacketInspectionServer.Spec)
	}

	// Should be listing the deepPacketInspection.
	deepPacketInspections, err = deepPacketInspectionClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing deepPacketInspections (%s)", err)
	}
	if len(deepPacketInspections.Items) != 1 {
		return fmt.Errorf("should have exactly one deepPacketInspection, had %v deepPacketInspections", len(deepPacketInspections.Items))
	}

	deepPacketInspectionServer, err = deepPacketInspectionClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting deepPacketInspection %s (%s)", name, err)
	}
	if name != deepPacketInspectionServer.Name &&
		deepPacketInspection.ResourceVersion == deepPacketInspectionServer.ResourceVersion {
		return fmt.Errorf("didn't get the same deepPacketInspection back from the server \n%+v\n%+v", deepPacketInspection, deepPacketInspectionServer)
	}

	// Watch Test:
	opts := metav1.ListOptions{Watch: true}
	wIface, err := deepPacketInspectionClient.Watch(ctx, opts)
	if err != nil {
		return fmt.Errorf("Error on watch")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range wIface.ResultChan() {
			fmt.Println("Watch object: ", e)
			break
		}
	}()

	err = deepPacketInspectionClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("deepPacketInspection should be deleted (%s)", err)
	}

	wg.Wait()
	return nil
}

// TestUISettingsGroupClient exercises the UISettingsGroup client.
func TestUISettingsGroupClient(t *testing.T) {
	rootTestFunc := func() func(t *testing.T) {
		const name = "test-uisettingsgroup"
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.UISettingsGroup{}
			}, true)
			defer shutdownServer()
			if err := testUISettingsGroupClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run("test-uisettingsgroup", rootTestFunc()) {
		t.Errorf("test-uisettingsgroup failed")
	}
}

func testUISettingsGroupClient(client calicoclient.Interface, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := createEnterprise(client, ctx)
	if err == nil {
		return fmt.Errorf("Could not create a license")
	}

	uiSettingsGroupClient := client.ProjectcalicoV3().UISettingsGroups()
	uiSettingsGroup := &v3.UISettingsGroup{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v3.UISettingsGroupSpec{Description: "this is a settings group"},
	}

	// start from scratch
	uiSettingsGroups, err := uiSettingsGroupClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing uiSettingsGroups (%s)", err)
	}
	if uiSettingsGroups.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}
	if len(uiSettingsGroups.Items) > 0 {
		return fmt.Errorf("uiSettingsGroup should not exist on start, had %v uiSettingsGroup", len(uiSettingsGroups.Items))
	}

	uiSettingsGroupServer, err := uiSettingsGroupClient.Create(ctx, uiSettingsGroup, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the uiSettingsGroup '%v' (%v)", uiSettingsGroup, err)
	}

	updatedUISettingsGroup := uiSettingsGroupServer.DeepCopy()
	updatedUISettingsGroup.Labels = map[string]string{"foo": "bar"}
	updatedUISettingsGroup.Spec.Description = "updated description"
	uiSettingsGroupServer, err = uiSettingsGroupClient.Update(ctx, updatedUISettingsGroup, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error in updating the uiSettingsGroup '%v' (%v)", uiSettingsGroup, err)
	}
	if !reflect.DeepEqual(uiSettingsGroupServer.Labels, updatedUISettingsGroup.Labels) {
		return fmt.Errorf("didn't update label %#v", uiSettingsGroupServer.Labels)
	}
	if !reflect.DeepEqual(uiSettingsGroupServer.Spec, updatedUISettingsGroup.Spec) {
		return fmt.Errorf("didn't update spec %#v", uiSettingsGroupServer.Spec)
	}

	// Should be listing the uiSettingsGroup.
	uiSettingsGroups, err = uiSettingsGroupClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing uiSettingss (%s)", err)
	}
	if len(uiSettingsGroups.Items) != 1 {
		return fmt.Errorf("should have exactly one uiSettingsGroup, had %v uiSettingss", len(uiSettingsGroups.Items))
	}

	uiSettingsGroupServer, err = uiSettingsGroupClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting uiSettingsGroup %s (%s)", name, err)
	}
	if name != uiSettingsGroupServer.Name &&
		uiSettingsGroup.ResourceVersion == uiSettingsGroupServer.ResourceVersion {
		return fmt.Errorf("didn't get the same uiSettingsGroup back from the server \n%+v\n%+v", uiSettingsGroup, uiSettingsGroupServer)
	}

	// Watch Test:
	opts := metav1.ListOptions{Watch: true}
	wIface, err := uiSettingsGroupClient.Watch(ctx, opts)
	if err != nil {
		return fmt.Errorf("Error on watch")
	}

	err = uiSettingsGroupClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("uiSettingsGroup should be deleted (%s)", err)
	}

	select {
	case e := <-wIface.ResultChan():
		// Received the watch event.
		fmt.Println("Watch object: ", e)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestUISettingsClient exercises the UISettings client.
func TestUISettingsClient(t *testing.T) {
	rootTestFunc := func() func(t *testing.T) {
		const name = "test-uisettings"
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.UISettings{}
			}, true)
			defer shutdownServer()
			if err := testUISettingsClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run("test-uisettings", rootTestFunc()) {
		t.Errorf("test-uisettings failed")
	}
}

func testUISettingsClient(client calicoclient.Interface, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := createEnterprise(client, ctx)
	if err == nil {
		return fmt.Errorf("Could not create a license")
	}

	groupName := "groupname-a"
	name = groupName + "." + name
	name2 := groupName + "." + name + ".2"

	uiSettingsClient := client.ProjectcalicoV3().UISettings()
	uiSettingsGroupClient := client.ProjectcalicoV3().UISettingsGroups()
	uiSettings := &v3.UISettings{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			OwnerReferences: []metav1.OwnerReference{},
		},
		Spec: v3.UISettingsSpec{
			Group:       groupName,
			Description: "namespace 123",
			View:        nil,
			Layer: &v3.UIGraphLayer{
				Nodes: []v3.UIGraphNode{{
					Type:      "this",
					Name:      "name",
					Namespace: "namespace",
					ID:        "this/namespace/name",
				}},
				Icon: "svg-1",
			},
			Dashboard: nil,
		},
	}
	uiSettingsGroup := &v3.UISettingsGroup{
		ObjectMeta: metav1.ObjectMeta{Name: groupName},
		Spec: v3.UISettingsGroupSpec{
			Description: "my groupName",
		},
	}

	// start from scratch. Listing without specifying the groupName should be fine since we have full access across
	// all groups.
	uiSettingsList, err := uiSettingsClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing uiSettings with no group selector (%s)", err)
	}
	if uiSettingsList.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}
	if len(uiSettingsList.Items) > 0 {
		return fmt.Errorf("uiSettingsGroup should not exist on start, had %v uiSettingsGroup", len(uiSettingsList.Items))
	}

	// Listing with the group name will fail because the group does not exist.
	_, err = uiSettingsClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.group=" + groupName})
	if err == nil {
		return fmt.Errorf("expected error listing the uiSettings with group when group does not exist")
	}

	// Attempt to create UISettings without the groupName existing,
	_, err = uiSettingsClient.Create(ctx, uiSettings, metav1.CreateOptions{})
	if err == nil {
		return fmt.Errorf("expected error creating the uiSettings without group")
	}

	// Create a UISettingsGroup.
	uiSettingsGroupServer, err := uiSettingsGroupClient.Create(ctx, uiSettingsGroup, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the uiSettingsGroup '%v' (%v)", uiSettingsGroup, err)
	}
	defer func() {
		_ = uiSettingsGroupClient.Delete(ctx, groupName, metav1.DeleteOptions{})
	}()

	uiSettingsServer, err := uiSettingsClient.Create(ctx, uiSettings, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the uiSettings '%v' (%v)", uiSettings, err)
	}
	defer func() {
		_ = uiSettingsClient.Delete(ctx, name, metav1.DeleteOptions{})
	}()
	if len(uiSettingsServer.OwnerReferences) != 1 {
		return fmt.Errorf("expecting OwnerReferences to contain a single entry after create '%v'", uiSettingsServer.OwnerReferences)
	}
	if uiSettingsServer.OwnerReferences[0].Kind != "UISettingsGroup" ||
		uiSettingsServer.OwnerReferences[0].Name != groupName ||
		uiSettingsServer.OwnerReferences[0].APIVersion != "projectcalico.org/v3" ||
		uiSettingsServer.OwnerReferences[0].UID != uiSettingsGroupServer.UID {
		return fmt.Errorf("expecting OwnerReferences be the owning group after create: '%v'", uiSettingsServer.OwnerReferences)
	}
	if len(uiSettingsServer.Spec.User) != 0 {
		return fmt.Errorf("expecting User field not to be filled in: %v", uiSettingsServer.Spec.User)
	}

	// / Try updating without the owner reference. This should fail.
	updatedUISettings := uiSettingsServer.DeepCopy()
	updatedUISettings.Labels = map[string]string{"foo": "bar"}
	updatedUISettings.Spec.Description = "updated description"
	updatedUISettings.OwnerReferences = nil
	_, err = uiSettingsClient.Update(ctx, updatedUISettings, metav1.UpdateOptions{})
	if err == nil {
		return fmt.Errorf("expecting error updating UISettings without the owner reference (%v)", uiSettings)
	}

	// Set the owner references from the Get and try again.
	updatedUISettings.OwnerReferences = uiSettingsServer.OwnerReferences
	uiSettingsServer, err = uiSettingsClient.Update(ctx, updatedUISettings, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error in updating the uiSettings '%v' (%v)", uiSettings, err)
	}
	if !reflect.DeepEqual(uiSettingsServer.Labels, updatedUISettings.Labels) {
		return fmt.Errorf("didn't update label %#v", uiSettingsServer.Labels)
	}
	if !reflect.DeepEqual(uiSettingsServer.Spec, updatedUISettings.Spec) {
		return fmt.Errorf("didn't update spec %#v", uiSettingsServer.Spec)
	}
	if len(uiSettingsServer.OwnerReferences) != 1 {
		return fmt.Errorf("expecting OwnerReferences to contain a single entry after update '%v'", uiSettingsServer.OwnerReferences)
	}
	if uiSettingsServer.OwnerReferences[0].Kind != "UISettingsGroup" ||
		uiSettingsServer.OwnerReferences[0].Name != groupName ||
		uiSettingsServer.OwnerReferences[0].APIVersion != "projectcalico.org/v3" ||
		uiSettingsServer.OwnerReferences[0].UID != uiSettingsGroupServer.UID {
		return fmt.Errorf("expecting OwnerReferences be the owning group after update: '%v'", uiSettingsServer.OwnerReferences)
	}

	// List should include everything if not specifying the group.
	uiSettingsList, err = uiSettingsClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing uiSettingss without group selector (%s)", err)
	}
	if len(uiSettingsList.Items) != 1 {
		return fmt.Errorf("should have exactly one uiSettings, had %v uiSettingss", len(uiSettingsList.Items))
	}

	// Should be listing the uiSettings by field selector.
	uiSettingsList, err = uiSettingsClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.group=" + groupName})
	if err != nil {
		return fmt.Errorf("error listing uiSettingss with group selector (%s)", err)
	}
	if len(uiSettingsList.Items) != 1 {
		return fmt.Errorf("should have exactly one uiSettings, had %v uiSettingss", len(uiSettingsList.Items))
	}

	uiSettingsServer, err = uiSettingsClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting uiSettings %s (%s)", name, err)
	}
	if name != uiSettingsServer.Name &&
		uiSettings.ResourceVersion == uiSettingsServer.ResourceVersion {
		return fmt.Errorf("didn't get the same uiSettings back from the server \n%+v\n%+v", uiSettings, uiSettingsServer)
	}

	// Modify the group to have the user filter.
	uiSettingsGroupServer.Spec.FilterType = "User"
	_, err = uiSettingsGroupClient.Update(ctx, uiSettingsGroupServer, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating the uiSettingsGroup '%v' (%v)", uiSettingsGroup, err)
	}

	// Create a second group that should be tied to the user.
	uiSettings.Name = name2
	uiSettingsServer2, err := uiSettingsClient.Create(ctx, uiSettings, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the second uiSettings '%v' (%v)", uiSettings, err)
	}
	defer func() {
		_ = uiSettingsClient.Delete(ctx, name2, metav1.DeleteOptions{})
	}()
	if len(uiSettingsServer2.Spec.User) == 0 {
		return fmt.Errorf("expecting User field to be filled in")
	}

	// List UISettings without group. This should return both settings.
	uiSettingsList, err = uiSettingsClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing uiSettingss without group selector (%s)", err)
	}
	if len(uiSettingsList.Items) != 2 {
		return fmt.Errorf("should have exactly two uiSettings, had %v uiSettingss", len(uiSettingsList.Items))
	}

	// List UISettings with field selector shouold limit to user specific settings now.
	uiSettingsList, err = uiSettingsClient.List(ctx, metav1.ListOptions{FieldSelector: "spec.group=" + groupName})
	if err != nil {
		return fmt.Errorf("error listing uiSettingss with group selector (%s)", err)
	}
	if len(uiSettingsList.Items) != 1 {
		return fmt.Errorf("should have exactly one uiSettings, had %v uiSettingss", len(uiSettingsList.Items))
	}
	if uiSettingsList.Items[0].Name != name2 {
		return fmt.Errorf("should have received %v, instead received %v", name2, uiSettingsList.Items[0].Name)
	}

	// Watch Test. Deleting the second should work.
	opts := metav1.ListOptions{Watch: true, FieldSelector: "spec.group=" + groupName}
	wIface, err := uiSettingsClient.Watch(ctx, opts)
	if err != nil {
		return fmt.Errorf("Error on watch")
	}

	err = uiSettingsClient.Delete(ctx, name2, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("uiSettings should be deleted (%s)", err)
	}

	select {
	case e := <-wIface.ResultChan():
		// Received the watch event.
		fmt.Println("Watch object: ", e)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestCalicoNodeStatusClient exercises the CalicoNodeStatus client.
func TestCalicoNodeStatusClient(t *testing.T) {
	const name = "test-caliconodestatus"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.CalicoNodeStatus{}
			}, true)
			defer shutdownServer()
			if err := testCalicoNodeStatusClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-caliconodestatus test failed")
	}
}

func testCalicoNodeStatusClient(client calicoclient.Interface, name string) error {
	seconds := uint32(11)
	caliconodestatusClient := client.ProjectcalicoV3().CalicoNodeStatuses()
	caliconodestatus := &v3.CalicoNodeStatus{
		ObjectMeta: metav1.ObjectMeta{Name: name},

		Spec: v3.CalicoNodeStatusSpec{
			Node: "node1",
			Classes: []v3.NodeStatusClassType{
				v3.NodeStatusClassTypeAgent,
				v3.NodeStatusClassTypeBGP,
				v3.NodeStatusClassTypeRoutes,
			},
			UpdatePeriodSeconds: &seconds,
		},
	}
	ctx := context.Background()

	// start from scratch
	caliconodestatuses, err := caliconodestatusClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing caliconodestatuses (%s)", err)
	}
	if caliconodestatuses.Items == nil {
		return fmt.Errorf("items field should not be set to nil")
	}

	caliconodestatusNew, err := caliconodestatusClient.Create(ctx, caliconodestatus, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the object '%v' (%v)", caliconodestatus, err)
	}
	if name != caliconodestatusNew.Name {
		return fmt.Errorf("didn't get the same object back from the server \n%+v\n%+v", caliconodestatus, caliconodestatusNew)
	}

	_, err = caliconodestatusClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", name, err)
	}

	err = caliconodestatusClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("object should be deleted (%s)", err)
	}

	return nil
}

// TestIPAMConfigClient exercises the IPAMConfig client.
func TestIPAMConfigClient(t *testing.T) {
	const name = "test-ipamconfig"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.IPAMConfiguration{}
			}, false)
			defer shutdownServer()
			if err := testIPAMConfigClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-ipamconfig test failed")
	}
}

func testIPAMConfigClient(client calicoclient.Interface, name string) error {
	ipamConfigClient := client.ProjectcalicoV3().IPAMConfigurations()
	ipamConfig := &v3.IPAMConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},

		Spec: v3.IPAMConfigurationSpec{
			StrictAffinity:   true,
			MaxBlocksPerHost: 28,
		},
	}
	ctx := context.Background()

	_, err := ipamConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing IPAMConfigurations: %s", err)
	}

	_, err = ipamConfigClient.Create(ctx, ipamConfig, metav1.CreateOptions{})
	if err == nil {
		return fmt.Errorf("should not be able to create ipam config %s ", ipamConfig.Name)
	}

	ipamConfig.Name = "default"
	ipamConfigNew, err := ipamConfigClient.Create(ctx, ipamConfig, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the object '%v' (%v)", ipamConfig, err)
	}

	if ipamConfigNew.Name != ipamConfig.Name {
		return fmt.Errorf("didn't get the same object back from the server \n%+v\n%+v", ipamConfig, ipamConfigNew)
	}

	if ipamConfigNew.Spec.StrictAffinity != true || ipamConfig.Spec.MaxBlocksPerHost != 28 {
		return fmt.Errorf("didn't get the correct object back from the server \n%+v\n%+v", ipamConfig, ipamConfigNew)
	}

	ipamConfigNew, err = ipamConfigClient.Get(ctx, ipamConfig.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", ipamConfig.Name, err)
	}

	ipamConfigNew.Spec.StrictAffinity = false
	ipamConfigNew.Spec.MaxBlocksPerHost = 0

	_, err = ipamConfigClient.Update(ctx, ipamConfigNew, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating object %s (%s)", name, err)
	}

	ipamConfigUpdated, err := ipamConfigClient.Get(ctx, ipamConfig.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", ipamConfig.Name, err)
	}

	if ipamConfigUpdated.Spec.StrictAffinity != false || ipamConfigUpdated.Spec.MaxBlocksPerHost != 0 {
		return fmt.Errorf("didn't get the correct object back from the server \n%+v\n%+v", ipamConfigUpdated, ipamConfigNew)
	}

	err = ipamConfigClient.Delete(ctx, ipamConfig.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("object should be deleted (%s)", err)
	}

	return nil
}

// TestBlockAffinityClient exercises the BlockAffinity client.
func TestBlockAffinityClient(t *testing.T) {
	const name = "test-blockaffinity"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.BlockAffinity{}
			}, true)
			defer shutdownServer()
			if err := testBlockAffinityClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-blockaffinity test failed")
	}
}

func testBlockAffinityClient(client calicoclient.Interface, name string) error {
	blockAffinityClient := client.ProjectcalicoV3().BlockAffinities()
	blockAffinity := &v3.BlockAffinity{
		ObjectMeta: metav1.ObjectMeta{Name: name},

		Spec: v3.BlockAffinitySpec{
			CIDR:  "10.0.0.0/24",
			Node:  "node1",
			State: "pending",
		},
	}
	libV3BlockAffinity := &libapiv3.BlockAffinity{
		ObjectMeta: metav1.ObjectMeta{Name: name},

		Spec: libapiv3.BlockAffinitySpec{
			CIDR:    "10.0.0.0/24",
			Node:    "node1",
			State:   "pending",
			Deleted: "false",
		},
	}
	ctx := context.Background()

	// Calico libv3 client instantiation in order to get around the API create restrictions
	// TODO: Currently these tests only run on a Kubernetes datastore since profile creation
	// does not work in etcd. Figure out how to divide this configuration to etcd once that
	// is fixed.
	config := apiconfig.NewCalicoAPIConfig()
	config.Spec = apiconfig.CalicoAPIConfigSpec{
		DatastoreType: apiconfig.Kubernetes,
		EtcdConfig: apiconfig.EtcdConfig{
			EtcdEndpoints: "http://localhost:2379",
		},
		KubeConfig: apiconfig.KubeConfig{
			Kubeconfig: os.Getenv("KUBECONFIG"),
		},
	}
	apiClient, err := libclient.New(*config)
	if err != nil {
		return fmt.Errorf("unable to create Calico lib v3 client: %s", err)
	}

	_, err = blockAffinityClient.Create(ctx, blockAffinity, metav1.CreateOptions{})
	if err == nil {
		return fmt.Errorf("should not be able to create block affinity %s ", blockAffinity.Name)
	}

	// Create the block affinity using the libv3 client.
	_, err = apiClient.BlockAffinities().Create(ctx, libV3BlockAffinity, options.SetOptions{})
	if err != nil {
		return fmt.Errorf("error creating the object through the Calico v3 API '%v' (%v)", libV3BlockAffinity, err)
	}

	blockAffinityNew, err := blockAffinityClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", name, err)
	}

	blockAffinityList, err := blockAffinityClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing BlockAffinity (%s)", err)
	}
	if blockAffinityList.Items == nil {
		return fmt.Errorf("items field should not be set to nil")
	}

	blockAffinityNew.Spec.State = "confirmed"

	_, err = blockAffinityClient.Update(ctx, blockAffinityNew, metav1.UpdateOptions{})
	if err == nil {
		return fmt.Errorf("should not be able to update block affinity %s", blockAffinityNew.Name)
	}

	err = blockAffinityClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil == err {
		return fmt.Errorf("should not be able to delete block affinity %s", blockAffinity.Name)
	}

	// Test watch
	w, err := blockAffinityClient.Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching block affinities (%s)", err)
	}

	_, err = apiClient.BlockAffinities().Delete(ctx, name, options.DeleteOptions{ResourceVersion: blockAffinityNew.ResourceVersion})
	if err != nil {
		return fmt.Errorf("error deleting the object through the Calico v3 API '%v' (%v)", name, err)
	}

	// Verify watch
	var events []watch.Event
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
loop:
	for range 2 {
		select {
		case e := <-w.ResultChan():
			events = append(events, e)
		case <-timeout:
			timeoutErr = fmt.Errorf("timed out waiting for events")
			break loop
		}
	}
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestBGPFilterClient exercises the BGPFilter client.
func TestBGPFilterClient(t *testing.T) {
	const name = "test-bgpfilter"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.BGPFilter{}
			}, false)
			defer shutdownServer()
			if err := testBGPFilterClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-bgpfilter test failed")
	}
}

func testBGPFilterClient(client calicoclient.Interface, name string) error {
	bgpFilterClient := client.ProjectcalicoV3().BGPFilters()
	r1v4 := v3.BGPFilterRuleV4{
		CIDR:          "10.10.10.0/24",
		MatchOperator: v3.In,
		Source:        v3.BGPFilterSourceRemotePeers,
		Interface:     "*.calico",
		Action:        v3.Accept,
	}
	r1v6 := v3.BGPFilterRuleV6{
		CIDR:          "dead:beef:1::/64",
		MatchOperator: v3.Equal,
		Source:        v3.BGPFilterSourceRemotePeers,
		Interface:     "*.calico",
		Action:        v3.Accept,
	}
	r2v4 := v3.BGPFilterRuleV4{
		CIDR:          "10.10.10.0/24",
		MatchOperator: v3.In,
		Source:        v3.BGPFilterSourceRemotePeers,
		Action:        v3.Accept,
	}
	r2v6 := v3.BGPFilterRuleV6{
		CIDR:          "dead:beef:1::/64",
		MatchOperator: v3.Equal,
		Source:        v3.BGPFilterSourceRemotePeers,
		Action:        v3.Accept,
	}
	r3v4 := v3.BGPFilterRuleV4{
		CIDR:          "10.10.10.0/24",
		MatchOperator: v3.In,
		Interface:     "*.calico",
		Action:        v3.Accept,
	}
	r3v6 := v3.BGPFilterRuleV6{
		CIDR:          "dead:beef:1::/64",
		MatchOperator: v3.Equal,
		Interface:     "*.calico",
		Action:        v3.Accept,
	}
	r4v4 := v3.BGPFilterRuleV4{
		Source:    v3.BGPFilterSourceRemotePeers,
		Interface: "*.calico",
		Action:    v3.Accept,
	}
	r4v6 := v3.BGPFilterRuleV6{
		Source:    v3.BGPFilterSourceRemotePeers,
		Interface: "*.calico",
		Action:    v3.Accept,
	}
	r5v4 := v3.BGPFilterRuleV4{
		CIDR:          "10.10.10.0/24",
		MatchOperator: v3.In,
		Source:        v3.BGPFilterSourceRemotePeers,
		Action:        v3.Accept,
	}
	r5v6 := v3.BGPFilterRuleV6{
		CIDR:          "dead:beef:1::/64",
		MatchOperator: v3.Equal,
		Action:        v3.Accept,
	}
	r6v4 := v3.BGPFilterRuleV4{
		Source: v3.BGPFilterSourceRemotePeers,
		Action: v3.Accept,
	}
	r6v6 := v3.BGPFilterRuleV6{
		Source: v3.BGPFilterSourceRemotePeers,
		Action: v3.Accept,
	}
	r7v4 := v3.BGPFilterRuleV4{
		Interface: "*.calico",
		Action:    v3.Accept,
	}
	r7v6 := v3.BGPFilterRuleV6{
		Interface: "*.calico",
		Action:    v3.Accept,
	}
	r8v4 := v3.BGPFilterRuleV4{
		Action: v3.Accept,
	}
	r8v6 := v3.BGPFilterRuleV6{
		Action: v3.Accept,
	}

	// This test expect equal number of rules in each of ExportV4, ImportV4, ExportV6 and ImportV6.
	bgpFilter := &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.BGPFilterSpec{
			ExportV4: []v3.BGPFilterRuleV4{r1v4, r7v4, r6v4, r5v4, r2v4, r8v4},
			ImportV4: []v3.BGPFilterRuleV4{r2v4, r3v4, r4v4, r7v4, r8v4, r1v4},
			ExportV6: []v3.BGPFilterRuleV6{r5v6, r1v6, r6v6, r4v6, r8v6, r2v6},
			ImportV6: []v3.BGPFilterRuleV6{r6v6, r1v6, r3v6, r7v6, r2v6, r4v6},
		},
	}
	ctx := context.Background()

	_, err := bgpFilterClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing BGPFilters: %s", err)
	}

	bgpFilterNew, err := bgpFilterClient.Create(ctx, bgpFilter, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the object '%v' (%v)", bgpFilter, err)
	}

	if bgpFilterNew.Name != bgpFilter.Name {
		return fmt.Errorf("didn't get the same object back from the server \n%+v\n%+v", bgpFilter, bgpFilterNew)
	}

	size := len(bgpFilter.Spec.ExportV4)
	if len(bgpFilterNew.Spec.ExportV4) != size || len(bgpFilterNew.Spec.ImportV4) != size ||
		len(bgpFilterNew.Spec.ExportV6) != size || len(bgpFilterNew.Spec.ImportV6) != size {
		return fmt.Errorf("didn't get the correct object back from the server \n%+v\n%+v", bgpFilter, bgpFilterNew)
	}

	for i := 0; i < size; i++ {
		if bgpFilterNew.Spec.ExportV4[i] != bgpFilter.Spec.ExportV4[i] {
			return fmt.Errorf("didn't get the correct object back from the server. Incorrect ExportV4: \n%+v\n%+v",
				bgpFilter.Spec.ExportV4, bgpFilterNew.Spec.ExportV4)
		}
		if bgpFilterNew.Spec.ImportV4[i] != bgpFilter.Spec.ImportV4[i] {
			return fmt.Errorf("didn't get the correct object back from the server. Incorrect ImportV4: \n%+v\n%+v",
				bgpFilter.Spec.ImportV4, bgpFilterNew.Spec.ImportV4)
		}
		if bgpFilterNew.Spec.ExportV6[i] != bgpFilter.Spec.ExportV6[i] {
			return fmt.Errorf("didn't get the correct object back from the server. Incorrect ExportV6: \n%+v\n%+v",
				bgpFilter.Spec.ExportV6, bgpFilterNew.Spec.ExportV6)
		}
		if bgpFilterNew.Spec.ImportV6[i] != bgpFilter.Spec.ImportV6[i] {
			return fmt.Errorf("didn't get the correct object back from the server. Incorrect ImportV6: \n%+v\n%+v",
				bgpFilter.Spec.ImportV6, bgpFilterNew.Spec.ImportV6)
		}
	}

	bgpFilterNew, err = bgpFilterClient.Get(ctx, bgpFilter.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", bgpFilter.Name, err)
	}

	bgpFilterNew.Spec.ExportV4 = nil

	_, err = bgpFilterClient.Update(ctx, bgpFilterNew, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating object %s (%s)", name, err)
	}

	bgpFilterUpdated, err := bgpFilterClient.Get(ctx, bgpFilter.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", bgpFilter.Name, err)
	}

	if bgpFilterUpdated.Spec.ExportV4 != nil {
		return fmt.Errorf("didn't get the correct object back from the server \n%+v\n%+v", bgpFilterUpdated, bgpFilterNew)
	}

	err = bgpFilterClient.Delete(ctx, bgpFilter.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("object should be deleted (%s)", err)
	}

	return nil
}

// TestExternalNetworkClient exercises the ExternalNetwork client.
func TestExternalNetworkClient(t *testing.T) {
	const name = "test-externalnetwork"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.ExternalNetwork{}
			}, false)
			defer shutdownServer()
			if err := testExternalNetworkClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-externalnetwork test failed")
	}
}

func testExternalNetworkClient(client calicoclient.Interface, name string) error {
	externalNetworkClient := client.ProjectcalicoV3().ExternalNetworks()
	index := uint32(28)
	externalNetwork := &v3.ExternalNetwork{
		ObjectMeta: metav1.ObjectMeta{Name: name},

		Spec: v3.ExternalNetworkSpec{
			RouteTableIndex: &index,
		},
	}
	ctx := context.Background()

	_, err := externalNetworkClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ExternalNetworks: %s", err)
	}

	externalNetworkNew, err := externalNetworkClient.Create(ctx, externalNetwork, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the object '%v' (%v)", externalNetwork, err)
	}

	if externalNetworkNew.Name != externalNetwork.Name {
		return fmt.Errorf("didn't get the same object back from the server \n%+v\n%+v", externalNetwork, externalNetworkNew)
	}

	if *externalNetwork.Spec.RouteTableIndex != 28 {
		return fmt.Errorf("didn't get the correct object back from the server \n%+v\n%+v", externalNetwork, externalNetworkNew)
	}

	externalNetworkNew, err = externalNetworkClient.Get(ctx, externalNetwork.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", externalNetwork.Name, err)
	}

	index = 10
	externalNetworkNew.Spec.RouteTableIndex = &index

	_, err = externalNetworkClient.Update(ctx, externalNetworkNew, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating object %s (%s)", name, err)
	}

	externalNetworkUpdated, err := externalNetworkClient.Get(ctx, externalNetwork.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", externalNetwork.Name, err)
	}

	if *externalNetworkUpdated.Spec.RouteTableIndex != 10 {
		return fmt.Errorf("didn't get the correct object back from the server \n%+v\n%+v", externalNetworkUpdated, externalNetworkNew)
	}

	err = externalNetworkClient.Delete(ctx, externalNetwork.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("object should be deleted (%s)", err)
	}

	return nil
}

// TestEgressGatewayPolicyClient exercises the EgressGatewayPolicy client.
func TestEgressGatewayPolicyClient(t *testing.T) {
	const name = "test-egressgatewaypolicy"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.EgressGatewayPolicy{}
			}, false)
			defer shutdownServer()
			if err := testEgressGatewayPolicyClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-egressgatewaypolicy test failed")
	}
}

func testEgressGatewayPolicyClient(client calicoclient.Interface, name string) error {
	egressGWPolicyClient := client.ProjectcalicoV3().EgressGatewayPolicies()
	egressRuleOnPrem := v3.EgressGatewayRule{
		Destination: &v3.EgressGatewayPolicyDestinationSpec{
			CIDR: "10.10.10.0/24",
		},
		Description: "A sample network",
		Gateway: &v3.EgressSpec{
			NamespaceSelector: "projectcalico.org/name == 'default'",
			Selector:          "egress-code == 'red'",
			MaxNextHops:       2,
		},
	}
	egressGWPolicy := &v3.EgressGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},

		Spec: v3.EgressGatewayPolicySpec{
			Rules: []v3.EgressGatewayRule{egressRuleOnPrem},
		},
	}
	ctx := context.Background()

	_, err := egressGWPolicyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing EgressGatewayPolicies: %s", err)
	}

	egressGWPolicyNew, err := egressGWPolicyClient.Create(ctx, egressGWPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating the object '%v' (%v)", egressGWPolicy, err)
	}

	if egressGWPolicyNew.Name != egressGWPolicy.Name {
		return fmt.Errorf("didn't get the same object back from the server \n%+v\n%+v", egressGWPolicy, egressGWPolicyNew)
	}

	if len(egressGWPolicyNew.Spec.Rules) != 1 || egressGWPolicyNew.Spec.Rules[0].Description != egressGWPolicy.Spec.Rules[0].Description {
		return fmt.Errorf("didn't get the correct object back from the server \n%+v\n%+v", egressGWPolicy, egressGWPolicyNew)
	}

	egressGWPolicyNew, err = egressGWPolicyClient.Get(ctx, egressGWPolicy.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", egressGWPolicy.Name, err)
	}
	if egressGWPolicyNew.GetUID() == "" {
		return fmt.Errorf("UID should be set after a get")
	}

	egressRuleInternet := v3.EgressGatewayRule{
		Destination: &v3.EgressGatewayPolicyDestinationSpec{
			CIDR: "0.0.0.0/0",
		},
		Description: "Internet access",
		Gateway: &v3.EgressSpec{
			NamespaceSelector: "projectcalico.org/name == 'default'",
			Selector:          "egress-code == 'blue'",
		},
	}
	egressGWPolicyNew.Spec.Rules = []v3.EgressGatewayRule{egressRuleOnPrem, egressRuleInternet}

	_, err = egressGWPolicyClient.Update(ctx, egressGWPolicyNew, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating object %s (%s)", name, err)
	}

	egressGWPolicyUpdated, err := egressGWPolicyClient.Get(ctx, egressGWPolicy.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", egressGWPolicy.Name, err)
	}

	if len(egressGWPolicyUpdated.Spec.Rules) != 2 ||
		egressGWPolicyUpdated.Spec.Rules[0].Description != egressGWPolicyNew.Spec.Rules[0].Description ||
		egressGWPolicyUpdated.Spec.Rules[1].Description != egressGWPolicyNew.Spec.Rules[1].Description {
		return fmt.Errorf("didn't get the correct object back from the server \n%+v\n%+v", egressGWPolicyUpdated, egressGWPolicyNew)
	}

	egressPolicyList, err := egressGWPolicyClient.List(ctx, metav1.ListOptions{})
	if err != nil || len(egressPolicyList.Items) != 1 {
		return fmt.Errorf("error listing EgressGatwayPolicies: %s\n%+v", err, egressPolicyList.Items)
	}

	err = egressGWPolicyClient.Delete(ctx, egressGWPolicy.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("object should be deleted (%s)", err)
	}

	egressPolicyList, err = egressGWPolicyClient.List(ctx, metav1.ListOptions{})
	if err != nil || len(egressPolicyList.Items) != 0 {
		return fmt.Errorf("error listing EgressGatwayPolicies: %s\n%+v", err, egressPolicyList.Items)
	}

	return nil
}

// TestPolicyWatch checks that the WatchManager closes watch when a new Tier is added
func TestPolicyWatch(t *testing.T) {
	const name = "test-policywatch"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.GlobalNetworkPolicy{}
			}, true)
			defer shutdownServer()
			if err := testPolicyWatch(client); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-policywatch test failed")
	}
}

func testPolicyWatch(client calicoclient.Interface) error {
	globalNetworkPolicy := &v3.GlobalNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "global-net-pol-watch"}}
	_, err := client.ProjectcalicoV3().GlobalNetworkPolicies().Create(context.Background(), globalNetworkPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating GlobalNetworkPolicy (%s)", err)
	}
	defer func() {
		_ = client.ProjectcalicoV3().GlobalNetworkPolicies().Delete(context.Background(), globalNetworkPolicy.Name, metav1.DeleteOptions{})
	}()

	w, err := client.ProjectcalicoV3().GlobalNetworkPolicies().Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching GlobalNetworkPolicy (%s)", err)
	}

	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(5 * time.Second)
	var timeoutErr error
	var event watch.Event

	go func() {
		defer done.Done()
		for {
			select {
			case event = <-w.ResultChan():
				return
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out waiting for events")
				return
			}
		}
	}()

	done.Wait()

	if timeoutErr != nil {
		return timeoutErr
	}

	if event.Type != watch.Added {
		return fmt.Errorf("unexpected event type %s", event)
	}

	order := float64(100.0)
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-tier"},
		Spec: v3.TierSpec{
			Order: &order,
		},
	}

	// Creating a new Tier should force the watch to be closed
	_, err = client.ProjectcalicoV3().Tiers().Create(context.Background(), tier, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating Tier (%s)", err)
	}
	defer func() {
		_ = client.ProjectcalicoV3().Tiers().Delete(context.Background(), tier.Name, metav1.DeleteOptions{})
	}()

	done = sync.WaitGroup{}
	done.Add(1)
	var chClosedError error
	timeout = time.After(5 * time.Second)

	go func() {
		defer done.Done()
		for {
			select {
			case _, ok := <-w.ResultChan():
				if !ok {
					return
				}
			case <-timeout:
				chClosedError = fmt.Errorf("watch should be closed")
				return
			}
		}
	}()

	done.Wait()

	if chClosedError != nil {
		return chClosedError
	}

	return nil
}
