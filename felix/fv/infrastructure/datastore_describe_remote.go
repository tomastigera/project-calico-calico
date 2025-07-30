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

	. "github.com/onsi/ginkgo"
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
	Describe(fmt.Sprintf("%s (local kubernetes, remote kubernetes)", description),
		func() {
			body(LocalRemoteInfraFactories{Local: createK8sDatastoreInfra, Remote: createRemoteK8sDatastoreInfra})
		})

	return true
}
