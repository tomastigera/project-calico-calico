// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

package bpfdefs

import (
	"fmt"
	"os"
	"path"
	"strings"
)

const (
	DefaultBPFfsPath    = "/sys/fs/bpf"
	DefaultCgroupV2Path = "/run/calico/cgroup"

	GlobalPinDir = DefaultBPFfsPath + "/tc/globals/"
	ObjectDir    = "/usr/lib/calico/bpf"
	CtlbPinDir   = "ctlb"
	TcxPinDir    = DefaultBPFfsPath + "/tcx"

	DnsObjDir            = DefaultBPFfsPath + "/dns"
	DnsParserProgram     = "cali_ipt_parse_dns"
	IPTMatchIPSetProgram = "cali_ipt_match_ipset"
)

func GetCgroupV2Path() string {
	cgroupV2CustomPath := os.Getenv("CALICO_CGROUP_PATH")
	if cgroupV2CustomPath == "" {
		return DefaultCgroupV2Path
	}
	return cgroupV2CustomPath
}

func IPSetMatchProg(ipSetID uint64, ipver uint8, logLevel string) string {
	return path.Join(IPSetMatchPinPath(ipSetID, ipver, logLevel), IPTMatchIPSetProgram)
}

func IPSetMatchPinPath(ipSetID uint64, ipver uint8, logLevel string) string {
	logLevel = logLevelToLower(logLevel)
	pinPath := path.Join(DnsObjDir, logLevel)
	return path.Join(pinPath, fmt.Sprintf("ipset_matcher_%d_v%d", ipSetID, ipver))
}

func IPTDNSParserProg(logLevel string) string {
	logLevel = logLevelToLower(logLevel)
	return path.Join(path.Join(DnsObjDir, logLevel), DnsParserProgram)
}

func logLevelToLower(bpfLogLevel string) string {
	logLevel := strings.ToLower(bpfLogLevel)
	if logLevel == "off" {
		logLevel = "no_log"
	}
	return logLevel
}

func IPTDnsPinPath(bpfLogLevel string) string {
	logLevel := logLevelToLower(bpfLogLevel)
	return path.Join(DnsObjDir, logLevel)
}
