// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.

package main

import (
	"os"
	"path/filepath"

	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
	"github.com/projectcalico/calico/cni-plugin/pkg/plugin"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

func main() {
	// Use the name of the binary to determine which routine to run.
	_, filename := filepath.Split(os.Args[0])
	switch filename {
	case "calico", "calico.exe":
		plugin.Main(buildinfo.Version)
	case "calico-ipam", "calico-ipam.exe":
		ipamplugin.Main(buildinfo.Version)
	default:
		panic("Unknown binary name: " + filename)
	}
}
