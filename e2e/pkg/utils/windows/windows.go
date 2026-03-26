/*
Copyright (c) 2018 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This package makes public methods out of some of the utility methods for testing windows cluster found at test/e2e/network_policy.go
// Eventually these utilities should replace those and be used for any calico tests

package windows

import (
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/sirupsen/logrus"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
)

// ClusterIsWindows returns true if the cluster supports running Windows tests and false otherwise.
//
// TODO: Right now, we assume that the presence of "RunsOnWindows" in the focus strings means
// that the tests are running on a Windows cluster. This isn't necessarily true. We could be more
// precise by either checking the cluster itself, or adding a CLi flag to control this behavior.
func ClusterIsWindows() bool {
	cfg, _ := ginkgo.GinkgoConfiguration()
	for _, s := range cfg.FocusStrings {
		if strings.Contains(s, "RunsOnWindows") {
			return true
		}
	}
	return false
}

// DumpFelixDiags collects Felix diagnostic information from all Windows nodes.
// Call this in AfterEach/DeferCleanup when a test fails, to help diagnose cases
// where Felix stops writing flow logs or intercepting DNS responses.
func DumpFelixDiags() {
	logrus.Info("[DIAGS] Collecting Felix diagnostics from Windows nodes")

	// List all calico-node-windows pods.
	output, err := e2ekubectl.RunKubectl("calico-system",
		"get", "pod",
		"-l", "k8s-app=calico-node-windows",
		"-o", "jsonpath={range .items[*]}{.metadata.name} {.spec.nodeName}{\"\\n\"}{end}")
	if err != nil {
		logrus.WithError(err).Warn("[DIAGS] Failed to list calico-node-windows pods")
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		podName, nodeName := parts[0], parts[1]
		logrus.Infof("[DIAGS] === Felix diagnostics for node %s (pod %s) ===", nodeName, podName)

		// Get the last 10 minutes of Felix container logs.
		logsOutput, err := e2ekubectl.RunKubectl("calico-system",
			"logs", podName, "-c", "felix", "--since=10m")
		if err != nil {
			logrus.WithError(err).Warnf("[DIAGS] Failed to get Felix logs from %s", podName)
		} else {
			logrus.Infof("[DIAGS] Felix logs (last 10m) from %s:\n%s", nodeName, logsOutput)
		}

		// Check flows.log freshness: read the last 5 entries to see the most recent timestamps.
		tailOutput, err := e2ekubectl.RunKubectl("calico-system",
			"exec", podName, "-c", "felix", "--",
			"powershell.exe", "-Command",
			"Get-Content C:\\TigeraCalico\\flowlogs\\flows.log -Tail 5 -ErrorAction SilentlyContinue")
		if err != nil {
			logrus.WithError(err).Warnf("[DIAGS] Failed to read flows.log tail from %s", nodeName)
		} else {
			logrus.Infof("[DIAGS] flows.log last 5 entries from %s:\n%s", nodeName, tailOutput)
		}

		// Check Felix process status.
		psOutput, err := e2ekubectl.RunKubectl("calico-system",
			"exec", podName, "-c", "felix", "--",
			"powershell.exe", "-Command",
			"Get-Process calico-node -ErrorAction SilentlyContinue | Select-Object Id, CPU, WorkingSet64, StartTime | Format-List")
		if err != nil {
			logrus.WithError(err).Warnf("[DIAGS] Failed to get Felix process info from %s", nodeName)
		} else {
			logrus.Infof("[DIAGS] Felix process info on %s:\n%s", nodeName, psOutput)
		}
	}
}
