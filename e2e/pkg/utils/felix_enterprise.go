// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
// limitations under the License.

package utils

import (
	"context"
	"fmt"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// UpdateFelixConfig applies a mutation to the default FelixConfiguration.
// The mutate callback receives the current spec and should modify it in place.
func UpdateFelixConfig(cli ctrlclient.Client, mutate func(spec *v3.FelixConfigurationSpec)) error {
	cc := v3.NewFelixConfiguration()
	err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, cc)
	if err != nil {
		return err
	}

	mutate(&cc.Spec)
	return cli.Update(context.Background(), cc)
}

// SetFlowLogsFlushInterval updates the default FelixConfiguration's FlowLogsFlushInterval
// and returns a cleanup function that restores the original value. The passed config object
// is populated with the fetched FelixConfiguration.
func SetFlowLogsFlushInterval(cli ctrlclient.Client, interval time.Duration) (cleanup func(), err error) {
	ctx := context.Background()
	felixConfig := v3.NewFelixConfiguration()
	if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, felixConfig); err != nil {
		return nil, fmt.Errorf("failed to get default FelixConfiguration: %w", err)
	}

	oldInterval := felixConfig.Spec.FlowLogsFlushInterval
	felixConfig.Spec.FlowLogsFlushInterval = &metav1.Duration{Duration: interval}

	if err := cli.Update(ctx, felixConfig); err != nil {
		return nil, fmt.Errorf("failed to update FelixConfiguration FlowLogsFlushInterval: %w", err)
	}

	return func() {
		cfg := v3.NewFelixConfiguration()
		ExpectWithOffset(1, cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, cfg)).To(Succeed())
		cfg.Spec.FlowLogsFlushInterval = oldInterval
		ExpectWithOffset(1, cli.Update(ctx, cfg)).To(Succeed())
	}, nil
}
