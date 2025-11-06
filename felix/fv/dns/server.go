// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

package dns

import (
	"encoding/json"
	"fmt"

	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/containers"
)

type CleanupProvider interface {
	AddCleanup(func())
}

func StartServer(infra CleanupProvider, records map[string][]RecordIP) *containers.Container {
	recordsStr, err := json.Marshal(records)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	c := containers.Run("dnsserver",
		containers.RunOpts{AutoRemove: true, WithStdinPipe: true},
		"-i", "--privileged", "-e", fmt.Sprintf("IP=%s", "53"), "-e", fmt.Sprintf("PORT=%s", "53"), "-e",
		fmt.Sprintf("RECORDS=%s", string(recordsStr)), "tigera-test/dns-server:latest")
	infra.AddCleanup(c.Stop)
	return c
}
