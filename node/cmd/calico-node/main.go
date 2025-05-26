// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	confdConfig "github.com/projectcalico/calico/confd/pkg/config"
	confd "github.com/projectcalico/calico/confd/pkg/run"
	felix "github.com/projectcalico/calico/felix/daemon"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/node/cmd/calico-node/bpf"
	"github.com/projectcalico/calico/node/pkg/allocateip"
	"github.com/projectcalico/calico/node/pkg/cni"
	"github.com/projectcalico/calico/node/pkg/earlynetworking"
	"github.com/projectcalico/calico/node/pkg/flowlogs"
	"github.com/projectcalico/calico/node/pkg/health"
	"github.com/projectcalico/calico/node/pkg/hostpathinit"
	"github.com/projectcalico/calico/node/pkg/lifecycle/shutdown"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup"
	"github.com/projectcalico/calico/node/pkg/metrics"
	"github.com/projectcalico/calico/node/pkg/nodeinit"
	"github.com/projectcalico/calico/node/pkg/status"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

// Create a new flag set.
var flagSet = flag.NewFlagSet("Calico", flag.ContinueOnError)

// Build the set of supported flags.
var (
	version                    = flagSet.Bool("v", false, "Display version")
	runFelix                   = flagSet.Bool("felix", false, "Run Felix")
	runBPF                     = flagSet.Bool("bpf", false, "Run BPF debug tool")
	runInit                    = flagSet.Bool("init", false, "Do privileged initialisation of a new node (mount file systems etc).")
	bestEffort                 = flagSet.Bool("best-effort", false, "Used in combination with the init flag. Report errors but do not fail if an error occurs during initialisation.")
	runStartup                 = flagSet.Bool("startup", false, "Do non-privileged start-up routine.")
	runShutdown                = flagSet.Bool("shutdown", false, "Do shutdown routine.")
	monitorAddrs               = flagSet.Bool("monitor-addresses", false, "Monitor change in node IP addresses")
	runAllocateTunnelAddrs     = flagSet.Bool("allocate-tunnel-addrs", false, "Configure tunnel addresses for this node")
	allocateTunnelAddrsRunOnce = flagSet.Bool("allocate-tunnel-addrs-run-once", false, "Run allocate-tunnel-addrs in oneshot mode")
	monitorToken               = flagSet.Bool("monitor-token", false, "Watch for Kubernetes token changes, update CNI config")
	nonClusterHost             = flagSet.Bool("noncluster-host", false, "Run in non-cluster host mode")
)

// Felix flags
var felixConfig = flagSet.String("felix-config", "/etc/calico/felix.cfg", "Path to the Felix config file")

// Build set of supported flags for metrics.
var runBGPMetrics = flagSet.Bool("bgp-metrics", false, "Run server for BGP Prometheus metrics endpoint")

// Options for liveness checks.
var (
	felixLive = flagSet.Bool("felix-live", false, "Run felix liveness checks")
	birdLive  = flagSet.Bool("bird-live", false, "Run bird liveness checks")
	bird6Live = flagSet.Bool("bird6-live", false, "Run bird6 liveness checks")
)

// Options for readiness checks.
var (
	birdReady       = flagSet.Bool("bird-ready", false, "Run BIRD readiness checks")
	bird6Ready      = flagSet.Bool("bird6-ready", false, "Run BIRD6 readiness checks")
	felixReady      = flagSet.Bool("felix-ready", false, "Run felix readiness checks")
	bgpMetricsReady = flagSet.Bool("bgp-metrics-ready", false, "Run BGP metrics server readiness checks")
)

// thresholdTime is introduced for bird readiness check. Default value is 30 sec.
var thresholdTime = flagSet.Duration("threshold-time", 30*time.Second, "Threshold time for bird readiness")

// Options for node status.
var (
	runStatusReporter = flagSet.Bool("status-reporter", false, "Run node status reporter")
	showStatus        = flagSet.Bool("show-status", false, "Print out node status")
)

// Options for watching node flowlogs.
var flows = flagSet.Int("flows", 0, "Fetch a number of Flows. Use a negative value to watch forever.")

// confd flags
var (
	runConfd          = flagSet.Bool("confd", false, "Run confd")
	confdRunOnce      = flagSet.Bool("confd-run-once", false, "Run confd in oneshot mode")
	confdKeep         = flagSet.Bool("confd-keep-stage-file", false, "Keep stage file when running confd")
	confdConfDir      = flagSet.String("confd-confdir", "/etc/calico/confd", "Confd configuration directory.")
	confdCalicoConfig = flagSet.String("confd-calicoconfig", "", "Calico configuration file.")
)

// Early networking flags
var runEarlyNetworking = flagSet.Bool("early", false, "Do early networking setup (e.g. for a dual-homed node)")

// non-root hostpath init flags
var initHostpaths = flagSet.Bool("hostpath-init", false, "Initialize hostpaths for non-root access")

func main() {
	// Log to stdout.  this prevents our logs from being interpreted as errors by, for example,
	// fluentd's default configuration.
	logrus.SetOutput(os.Stdout)

	// Set up logging formatting.
	logutils.ConfigureFormatter("node")

	// Parse the provided flags.
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Perform some validation on the parsed flags. Only one of the following may be
	// specified at a time.
	onlyOne := []*bool{version, runFelix, runStartup, runConfd, runBGPMetrics, monitorAddrs}
	oneSelected := false
	for _, o := range onlyOne {
		if oneSelected && *o {
			fmt.Println("More than one incompatible argument provided")
			os.Exit(1)
		}

		if *o {
			oneSelected = true
		}
	}

	// Check for liveness / readiness flags. Will only run checks specified by flags.
	if *felixLive || *birdReady || *bird6Ready || *felixReady || *birdLive || *bird6Live || *bgpMetricsReady {
		health.Run(*birdReady, *bird6Ready, *felixReady, *felixLive, *birdLive, *bird6Live, *bgpMetricsReady, *thresholdTime)
		os.Exit(0)
	}

	// Decide which action to take based on the given flags.
	if *version {
		buildinfo.PrintVersion()
		os.Exit(0)
	} else if *runFelix {
		logutils.ConfigureFormatter("felix")
		felix.Run(*felixConfig, buildinfo.Version, buildinfo.BuildDate, buildinfo.GitRevision, *nonClusterHost)
	} else if *runBPF {
		// Command-line tools should log to stderr to avoid confusion with the output.
		logrus.SetOutput(os.Stderr)
		bpf.RunBPFCmd()
	} else if *runInit {
		if *bestEffort {
			logutils.ConfigureFormatter("init-best-effort")
		} else {
			logutils.ConfigureFormatter("init")
		}
		nodeinit.Run(*bestEffort)
	} else if *runStartup {
		logutils.ConfigureFormatter("startup")
		startup.Run()
	} else if *runShutdown {
		logutils.ConfigureFormatter("shutdown")
		shutdown.Run()
	} else if *monitorAddrs {
		logutils.ConfigureFormatter("monitor-addresses")
		startup.ConfigureLogging()
		startup.MonitorIPAddressSubnets()
	} else if *runConfd {
		logutils.ConfigureFormatter("confd")
		cfg, err := confdConfig.InitConfig(true)
		if err != nil {
			panic(err)
		}
		cfg.ConfDir = *confdConfDir
		cfg.KeepStageFile = *confdKeep
		cfg.Onetime = *confdRunOnce
		cfg.CalicoConfig = *confdCalicoConfig
		confd.Run(cfg)
	} else if *runAllocateTunnelAddrs {
		logutils.ConfigureFormatter("tunnel-ip-allocator")
		if *allocateTunnelAddrsRunOnce {
			allocateip.Run(nil)
		} else {
			allocateip.Run(make(chan struct{}))
		}
	} else if *monitorToken {
		logutils.ConfigureFormatter("cni-config-monitor")
		cni.Run()
	} else if *runBGPMetrics {
		logutils.ConfigureFormatter("bgp-metrics")
		// To halt the metrics process, close the signal
		signal := make(chan struct{})
		metrics.Run(signal)
	} else if *runEarlyNetworking {
		logutils.ConfigureFormatter("early-networking")
		earlynetworking.Run()
	} else if *initHostpaths {
		logutils.ConfigureFormatter("hostpath-init")
		hostpathinit.Run()
	} else if *runStatusReporter {
		logutils.ConfigureFormatter("status-reporter")
		status.Run()
	} else if *showStatus {
		status.Show()
		os.Exit(0)
	} else if *flows != 0 {
		flowlogs.RunFlowsCmd(*flows)
	} else {
		fmt.Println("No valid options provided. Usage:")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
}
