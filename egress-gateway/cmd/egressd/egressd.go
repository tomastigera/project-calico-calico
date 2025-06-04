package main

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	docopt "github.com/docopt/docopt-go"
	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/projectcalico/calico/egress-gateway/controlplane"
	"github.com/projectcalico/calico/egress-gateway/data"
	"github.com/projectcalico/calico/egress-gateway/httpprobe"
	"github.com/projectcalico/calico/egress-gateway/icmpprobe"
	"github.com/projectcalico/calico/egress-gateway/sync"
	utilnet "github.com/projectcalico/calico/egress-gateway/util/net"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

var USAGE_FMT string = `Egress Daemon - L2 and L3 management daemon for Tigera egress gateways.

Usage:
  %[1]s start <gateway-ips> [options]
  %[1]s (-h | --help)
  %[1]s --version

Options:
  --socket-path=<path>    Path to nodeagent-UDS over-which routing information is pulled [default: /var/run/nodeagent/socket]
  --log-severity=<trace|debug|info|warn|error|fatal>    Minimum reported log severity [default: info]
  --vni=<vni>    The VNI of the VXLAN interface being programmed [default: 4097]

Environment variables:
  HEALTH_PORT     Port on which to serve readiness/liveness health reports. [default: 8080]

  HTTP_PROBE_URLS  Optional comma-delimited list of URLs to send periodic probes to;  If all probes fail then the
                   daemon will report non-ready on the health port.
  HTTP_PROBE_INTERVAL: Interval between HTTP probes; uses Go's interval format, examples: 10s 1m30s. [default: 10s]
  HTTP_PROBE_TIMEOUT: Timeout for HTTP probes; uses Go's interval format, examples: 10s 1m30s. [default: 10s]

  ICMP_PROBE_IPS:      Comma-delimited list of IP addresses to send ICMP pings to.  If all probes fail then the
                       daemon will report non-ready on the health port.
  ICMP_PROBE_INTERVAL: Interval at which to send ICMP probes.
  ICMP_PROBE_TIMEOUT:  Timeout for the set of ICMP pings.  If no ping responses are received within the timeout
                       then the daemon will report non-ready.  Timeout should be longer than ICMP_PROBE_INTERVAL.
`

type envConfig struct {
	HealthPort int `split_words:"true" default:"8080"`

	HTTPProbeURLs     []string      `envconfig:"HTTP_PROBE_URLS" default:""`
	HTTPProbeInterval time.Duration `envconfig:"HTTP_PROBE_INTERVAL" default:"10s"`
	HTTPProbeTimeout  time.Duration `envconfig:"HTTP_PROBE_TIMEOUT" default:"10s"`

	ICMPProbes        []string      `envconfig:"ICMP_PROBE_IPS" default:""`
	ICMPProbeInterval time.Duration `envconfig:"ICMP_PROBE_INTERVAL" default:"5s"`
	ICMPProbeTimeout  time.Duration `envconfig:"ICMP_PROBE_TIMEOUT" default:"15s"`

	HealthTimeoutDatastore time.Duration `envconfig:"HEALTH_TIMEOUT_DATASTORE" default:"90s"`
}

func main() {
	args, err := docopt.ParseArgs(fmt.Sprintf(USAGE_FMT, os.Args[0]), nil, buildinfo.GitRevision)
	if err != nil {
		return
	}

	// parse log severity
	if argLogSeverity, ok := args["--log-severity"].(string); !ok {
		exitWithErrorAndUsage(fmt.Errorf("invalid log severity value %v", args["--log-severity"]))
	} else {
		ls, err := log.ParseLevel(argLogSeverity)
		if err != nil {
			exitWithErrorAndUsage(err)
		}

		log.SetLevel(ls)
	}
	// Replace logrus' formatter with a custom one using our time format,
	// shared with the Python code.
	logutils.ConfigureFormatter("egressd")
	log.Info("Egress gateway daemon starting up...")

	// Set up health reporting; this will be polled both by local kubelet and, if configured, remote Felix nodes.
	healthAgg := health.NewHealthAggregator()
	var envVars envConfig
	err = envconfig.Process("", &envVars)
	if err != nil {
		exitWithErrorAndUsage(fmt.Errorf("failed to parse environment variables: %w", err))
	}
	if envVars.HealthPort < 0 || envVars.HealthPort > math.MaxUint16 {
		exitWithErrorAndUsage(fmt.Errorf("health port is out of range: %d", envVars.HealthPort))
	}

	// parse this gateway's IP from string
	var ip net.IP
	if argEgressPodIPs, ok := args["<gateway-ips>"].(string); !ok {
		exitWithErrorAndUsage(fmt.Errorf("invalid egress-gateway IPs '%v'", args["<gateway-ips>"]))
	} else {
		ip = utilnet.ParseEgressPodIPs(argEgressPodIPs)
		if ip == nil {
			exitWithErrorAndUsage(fmt.Errorf("invalid egress-gateway IPs '%v'", argEgressPodIPs))
		}
		log.WithField("ipv4", ip).Info("Parsed IPv4 address from argument.")
	}

	var vni int
	argVNI, ok := args["--vni"].(string)
	if !ok {
		exitWithErrorAndUsage(fmt.Errorf("invalid VNI value '%v'", args["--vni"]))
	}
	vni, err = strconv.Atoi(argVNI)
	if err != nil {
		exitWithErrorAndUsage(fmt.Errorf("invalid VNI value '%s'", argVNI))
	}
	log.WithField("vni", vni).Info("Parsed VNI from argument.")

	syncSocket, ok := args["--socket-path"].(string)
	if !ok {
		exitWithErrorAndUsage(fmt.Errorf("invalid socket path value '%v'", args["--socket-path"]))
	}
	log.WithField("path", syncSocket).Info("Path to sync API socket.")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// source felix updates (over gRPC)
	syncClient := sync.NewClient(ctx, syncSocket, getDialOptions())
	datastore := data.NewRouteStore(syncClient.GetUpdatesPipeline, ip, healthAgg, envVars.HealthTimeoutDatastore)
	// register datastore observers
	routeManager := controlplane.NewRouteManager(datastore, "vxlan0", vni, healthAgg)

	// If configured, start a background goroutine to do an HTTP probe.
	if len(envVars.HTTPProbeURLs) > 0 {
		log.WithField("probeURLs", envVars.HTTPProbeURLs).Info("HTTP probes are configured.")
		if envVars.HTTPProbeTimeout < envVars.HTTPProbeInterval {
			exitWithErrorAndUsage(fmt.Errorf("HTTP probes timeout should be larger than HTTP probe interval"))
		}
		err := httpprobe.StartBackgroundHTTPProbe(
			ctx,
			envVars.HTTPProbeURLs,
			envVars.HTTPProbeInterval,
			envVars.HTTPProbeTimeout,
			healthAgg,
		)
		if err != nil {
			exitWithErrorAndUsage(fmt.Errorf("failed to start HTTP probe: %w", err))
		}
	} else {
		log.Info("No HTTP probes configured.")
	}

	// If configured, start probing over ICMP.
	var icmpProbeAddrs []net.IP
	for _, rawAddr := range envVars.ICMPProbes {
		if rawAddr == "" {
			continue
		}
		ipAddr := net.ParseIP(rawAddr)
		if ipAddr == nil {
			exitWithErrorAndUsage(fmt.Errorf("failed to parse ICMP probe IP address: %q", rawAddr))
		}
		icmpProbeAddrs = append(icmpProbeAddrs, ipAddr)
	}
	if len(icmpProbeAddrs) > 0 {
		log.WithField("icmpProbes", envVars.ICMPProbes).Info("ICMP probes configured")
		if envVars.ICMPProbeTimeout < envVars.ICMPProbeInterval {
			exitWithErrorAndUsage(fmt.Errorf("ICMP probes timeout should be larger than ICMP probe interval"))
		}

		err := icmpprobe.StartBackgroundICMPProbes(ctx, icmpProbeAddrs, envVars.ICMPProbeInterval, envVars.ICMPProbeTimeout, healthAgg)
		if err != nil {
			exitWithErrorAndUsage(fmt.Errorf("failed to start ICMP probes: %w", err))
		}
	} else {
		log.Info("No ICMP probes configured.")
	}

	// begin syncing
	log.Info("Starting worker goroutines.")
	go routeManager.Start(ctx)
	go datastore.SyncForever(ctx)
	go syncClient.SyncForever(ctx)

	// If enabled, serve health on the configured port.  We do this last, so we don't expose the health endpoint
	// before we've registered the reporters.
	if envVars.HealthPort > 0 {
		log.WithField("port", envVars.HealthPort).Info("Starting health server.")
		healthAgg.ServeHTTP(true, ip.String(), envVars.HealthPort)
	}

	// Block until a signal is received.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	log.Info("Main goroutine finished starting workers, waiting for shutdown signal...")
	sig := <-c
	log.Infof("Received interrupt: %v Exiting.", sig)
}

func getDialOptions() []grpc.DialOption {
	d := &net.Dialer{}
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(
			func(ctx context.Context, target string) (net.Conn, error) {
				return d.DialContext(ctx, "unix", target)
			},
		),
	}
}

func exitWithErrorAndUsage(err error) {
	fmt.Printf(USAGE_FMT, os.Args[0])
	log.Fatal(err)
}
