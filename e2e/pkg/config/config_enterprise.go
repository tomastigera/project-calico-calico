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

package config

import "fmt"

// Default ports used when no port forwarding has been configured.
const (
	defaultElasticsearchPort = 9200
	defaultManagerPort       = 9443
)

var (
	elasticsearchPort = defaultElasticsearchPort
	managerPort       = defaultManagerPort
)

// SetElasticsearchPort sets the local port allocated for Elasticsearch port forwarding.
func SetElasticsearchPort(port int) {
	elasticsearchPort = port
}

// SetManagerPort sets the local port allocated for Manager port forwarding.
func SetManagerPort(port int) {
	managerPort = port
}

// ElasticsearchURL returns the URL of the Elasticsearch instance to use for tests.
// The port is set dynamically by SetElasticsearchPort when port forwarding is configured.
func ElasticsearchURL() string {
	return fmt.Sprintf("https://localhost:%d", elasticsearchPort)
}

// ManagerURL returns the URL of the Calico Manager instance to use for tests.
// The port is set dynamically by SetManagerPort when port forwarding is configured.
func ManagerURL() string {
	return fmt.Sprintf("https://localhost:%d", managerPort)
}
