// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

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

package argutils

import (
	"fmt"
	"net"
	"os"
	"regexp"

	"github.com/tigera/api/pkg/lib/numorstring"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	// Ensure a user-supplied resource name is valid according to Kubernetes convention for
	// resource names
	validResourceNameRegex = regexp.MustCompile(`^[0-9a-z\-.]{1,253}$`)

	// Ensure user-supplied value is a valid time duration with one of the acceptable time
	// units (smh).
	validSinceRegex = regexp.MustCompile(`^[0-9]+[smh]$`)
)

// ValidateIP takes a string as an input and makes sure it's a valid IPv4 or IPv6 address.
// Returns the parsed IP, and prints error and exits if not valid.
func ValidateIP(str string) cnet.IP {
	// Parse the input string as an IP address (IPv4 or IPv6).
	// This also validates the IP address.
	ip := net.ParseIP(str)
	if ip == nil {
		fmt.Printf("Error executing command: invalid IP address specified: %s\n", str)
		os.Exit(1)
	}
	return cnet.IP{IP: ip}
}

// ValidateASNumber takes a string as an input and makes sure it's a valid ASNumber.
// Returns the parsed ASNumber, and prints error and exits if not.
func ValidateASNumber(str string) numorstring.ASNumber {
	asn, err := numorstring.ASNumberFromString(str)
	if err != nil {
		fmt.Printf("Error executing command: invalid AS Number specified: %s\n", str)
		os.Exit(1)
	}
	return asn
}

// ValidateResourceName takes a string as an input and makes sure it has valid naming format.
func ValidateResourceName(str string) string {
	if !validResourceNameRegex.MatchString(str) {
		fmt.Printf("Error executing command: resource name has invalid format: %s\n", str)
		os.Exit(1)
	}
	return str
}

// ValidateSinceDuration takes a string as an input and makes sure it has a valid value and
// time unit.
func ValidateSinceDuration(str string) {
	if !validSinceRegex.MatchString(str) {
		fmt.Printf("Error executing command: invalid duration for since flag (try 10s, 5m, or 1h): %s\n", str)
		os.Exit(1)
	}
}

// ValidateMaxLogs takes a int as an input and makes sure it has a non-negative value
func ValidateMaxLogs(num int) {
	if num < 0 {
		fmt.Printf("Error executing command: negative value for max-logs flag\n")
		os.Exit(1)
	}
}
