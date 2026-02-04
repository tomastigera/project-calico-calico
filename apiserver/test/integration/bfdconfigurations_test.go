// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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
	"fmt"
	"testing"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// TestBFDConfigurationClient exercises the BFDConfiguration client.
func TestBFDConfigurationClient(t *testing.T) {
	const name = "test-bfdconfig"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshAPIServerAndClient(t, func() runtime.Object {
				return &v3.BFDConfiguration{}
			}, true)
			defer shutdownServer()
			if err := testBFDConfigurationClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-bfdconfig test failed")
	}
}

func mustParseDuration(d string) *metav1.Duration {
	duration, err := time.ParseDuration(d)
	if err != nil {
		panic(err)
	}
	return &metav1.Duration{Duration: duration}
}

func testBFDConfigurationClient(client calicoclient.Interface, _ string) error {
	ctx := context.Background()

	bfdConfigClient := client.ProjectcalicoV3().BFDConfigurations()

	// Objects to test. Each should CRUD successfully.
	objs := []*v3.BFDConfiguration{
		{
			// Empty case
			ObjectMeta: metav1.ObjectMeta{Name: "res1"},
			Spec:       v3.BFDConfigurationSpec{},
		},
		{
			// Multiple interfaces.
			ObjectMeta: metav1.ObjectMeta{Name: "res1"},
			Spec: v3.BFDConfigurationSpec{
				Interfaces: []v3.BFDInterface{
					{
						// Partially specified.
						MatchPattern: "eth*",
						Multiplier:   10,
					},
					{
						// Fully specified.
						MatchPattern:        "ens1",
						Multiplier:          8,
						MinimumRecvInterval: mustParseDuration("1s"),
						MinimumSendInterval: mustParseDuration("1s"),
						IdleSendInterval:    mustParseDuration("1s"),
					},
				},
			},
		},
	}

	for _, bfdConfig := range objs {
		resName := bfdConfig.Name

		// start from scratch
		bfdConfigList, err := bfdConfigClient.List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("error listing bfdConfiguration (%s)", err)
		}
		if bfdConfigList.Items == nil {
			return fmt.Errorf("Items field should not be set to nil")
		}

		bfdRes, err := bfdConfigClient.Create(ctx, bfdConfig, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating the bfdConfiguration '%v' (%v)", bfdConfig, err)
		}
		if resName != bfdRes.Name {
			return fmt.Errorf("didn't get the same bfdConfig back from server\n%+v\n%+v", bfdConfig, bfdRes)
		}

		_, err = bfdConfigClient.Get(ctx, resName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("error getting bfdConfiguration %s (%s)", resName, err)
		}

		err = bfdConfigClient.Delete(ctx, resName, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("BFDConfiguration should be deleted (%s)", err)
		}
	}

	return nil
}
