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
	DefaultElasticsearchPort = 9200
	DefaultManagerPort       = 9443
)

// ElasticsearchURLForPort returns the Elasticsearch URL for a given local port.
func ElasticsearchURLForPort(port int) string {
	return fmt.Sprintf("https://localhost:%d", port)
}

// ManagerURLForPort returns the Manager URL for a given local port.
func ManagerURLForPort(port int) string {
	return fmt.Sprintf("https://localhost:%d", port)
}

// Deprecated: SetElasticsearchPort exists for backward compatibility with external consumers.
// New code should use the PortForwardInfo struct returned by elasticsearch.PortForward() instead.
var elasticsearchPort = DefaultElasticsearchPort

// Deprecated: SetManagerPort exists for backward compatibility with external consumers.
// New code should use the PortForwardInfo struct returned by elasticsearch.PortForward() instead.
var managerPort = DefaultManagerPort

// Deprecated: Use ElasticsearchURLForPort instead.
func SetElasticsearchPort(port int) {
	elasticsearchPort = port
}

// Deprecated: Use ManagerURLForPort instead.
func SetManagerPort(port int) {
	managerPort = port
}

// Deprecated: Use ElasticsearchURLForPort with the port from PortForwardInfo instead.
func ElasticsearchURL() string {
	return fmt.Sprintf("https://localhost:%d", elasticsearchPort)
}

// Deprecated: Use ManagerURLForPort with the port from PortForwardInfo instead.
func ManagerURL() string {
	return fmt.Sprintf("https://localhost:%d", managerPort)
}
