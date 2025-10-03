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

// ElasticsearchURL returns the URL of the Elasticsearch instance to use for tests.
// Currently hardcoded to localhost:9200 as tests that access ES are expected to configure
// temporary port forwarding to the ES instance.
func ElasticsearchURL() string {
	return "https://localhost:9200"
}

// ManagerURL returns the URL of the Calico Manager instance to use for tests.
// Currently hardcoded to localhost:9443 as tests that access the Manager are expected to configure
// temporary port forwarding to the Manager instance.
func ManagerURL() string {
	return "https://localhost:9443"
}
