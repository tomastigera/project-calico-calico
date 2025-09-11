// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
package stats

import (
	"fmt"
	"strings"

	"github.com/projectcalico/calico/felix/bpf/tc"
)

func AttachTcpStatsBpfProgram(ifaceName, logLevel string, nsID uint16) error {
	tcxSupported := tc.IsTcxSupported()
	if !tcxSupported {
		_, err := tc.EnsureQdisc(ifaceName)
		if err != nil {
			return err
		}
	}

	logLevel = strings.ToLower(logLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}

	fileName := fmt.Sprintf("tcp_stats_%s.o", logLevel)
	return tc.AttachTcpStatsProgram(ifaceName, fileName, nsID, tcxSupported)
}
