// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package infrastructure

import (
	"fmt"

	"github.com/onsi/ginkgo/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type LocalRemoteInfraFactories struct {
	Local  InfraFactory
	Remote InfraFactory
}

func (r *LocalRemoteInfraFactories) IsRemoteSetup() bool {
	return r.Remote != nil
}

func (r *LocalRemoteInfraFactories) AllFactories() []InfraFactory {
	factories := []InfraFactory{r.Local}
	if r.IsRemoteSetup() {
		factories = append(factories, r.Remote)
	}
	return factories
}

// DatastoreDescribeRemoteOnly invokes Describe, providing a factory that provides remote and local datastores. It creates just
// one Describe invocation - use DatastoreDescribeWithRemote to get both local and local/remote describes.
func DatastoreDescribeRemoteOnly(description string, body func(factories LocalRemoteInfraFactories)) bool {
	description = fmt.Sprintf("%s (local kubernetes, remote kubernetes)", description)
	return ginkgo.Describe(description, func() {
		var coreFilesAtStart set.Set[string]
		var currentInfra []DatastoreInfra
		ginkgo.BeforeEach(func() {
			coreFilesAtStart = readCoreFiles()
			currentInfra = nil
		})

		body(LocalRemoteInfraFactories{
			Local: func(opts ...CreateOption) DatastoreInfra {
				infra := createK8sDatastoreInfra(opts...)
				currentInfra = append(currentInfra, infra)
				return infra
			},
			Remote: func(opts ...CreateOption) DatastoreInfra {
				infra := createRemoteK8sDatastoreInfra(opts...)
				currentInfra = append(currentInfra, infra)
				return infra
			},
		})

		ginkgo.AfterEach(func() {
			// Always stop the infra after each test (collects diags on failure and cleans up).
			logrus.Info("DatastoreDescribe AfterEach: stopping infrastructure.")
			if len(currentInfra) > 0 {
				for i := len(currentInfra) - 1; i >= 0; i-- {
					if currentInfra[i] != nil {
						currentInfra[i].Stop()
					}
				}
				currentInfra = nil
			}
		})

		ginkgo.AfterEach(func() {
			// Then, perform the core file check.
			logrus.Info("DatastoreDescribe AfterEach: checking for core files.")
			afterCoreFiles := readCoreFiles()
			for item := range coreFilesAtStart.All() {
				afterCoreFiles.Discard(item)
			}
			if afterCoreFiles.Len() != 0 {
				if ginkgo.CurrentSpecReport().Failed() {
					ginkgo.Fail(fmt.Sprintf("Test FAILED and new core files were detected during tear-down: %v.  "+
						"Felix must have panicked during the test.", afterCoreFiles.Slice()))
					return
				}
				ginkgo.Fail(fmt.Sprintf("Test PASSED but new core files were detected during tear-down: %v.  "+
					"Felix must have panicked during the test.", afterCoreFiles.Slice()))
			}
		})
	})
}
