// Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.
package flags

import (
	"encoding/json"
	"flag"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Config struct {
	Command            string      // this is arg[1] from os.Args
	ListenNetwork      string      `json:"listenNetwork,omitempty"`
	ListenAddress      string      `json:"listenAddress,omitempty"`
	DialNetwork        string      `json:"dialNetwork,omitempty"`
	DialAddress        string      `json:"dialAddress,omitempty"`
	LogLevel           string      `json:"logLevel,omitempty"`
	PerHostALPEnabled  bool        `json:"perHostAlpEnabled,omitempty"`
	PerHostWAFEnabled  bool        `json:"perHostWafEnabled,omitempty"`
	SidecarALPEnabled  bool        `json:"sidecarAlpEnabled,omitempty"`
	SidecarWAFEnabled  bool        `json:"sidecarWafEnabled,omitempty"`
	SidecarLogsEnabled bool        `json:"sidecarLogsEnabled,omitempty"`
	WAFRulesetFiles    stringArray `json:"wafRulesetFiles,omitempty"`
	WAFRulesetRootDir  string      `json:"wafRulesetRootDir,omitempty"`
	WAFDirectives      stringArray `json:"wafDirectives,omitempty"`
	SubscriptionType   string      `json:"subscriptionType,omitempty"`
	HTTPServerAddr     string      `json:"httpServerAddr,omitempty"`
	HTTPServerPort     string      `json:"httpServerPort,omitempty"`
	// envoy init config
	EnvoyInboundPort      string `json:"envoyInboundPort,omitempty"`
	EnvoyMetricsPort      string `json:"envoyMetricsPort,omitempty"`
	EnvoyLivenessPort     string `json:"envoyLivenessPort,omitempty"`
	EnvoyReadinessPort    string `json:"envoyReadinessPort,omitempty"`
	EnvoyStartupProbePort string `json:"envoyStartupProbePort,omitempty"`
	EnvoyHealthCheckPort  string `json:"envoyHealthCheckPort,omitempty"`
	NumTrustedHopsXFF     int    `json:"envoyNumTrustedHopsXFF,omitempty"`
	UseRemoteAddressXFF   bool   `json:"envoyUseRemoteAddressXFF,omitempty"`

	*flag.FlagSet `json:"-"`
}

func New() *Config {
	fs := flag.NewFlagSet("dikastes", flag.ExitOnError)

	cfg := &Config{
		FlagSet: fs,
	}

	fs.StringVar(&cfg.ListenAddress, "listen", "/var/run/dikastes/dikastes.sock", "Listen address")
	fs.StringVar(&cfg.ListenNetwork, "listen-network", "unix", "Listen network e.g. tcp, unix")
	fs.StringVar(&cfg.DialAddress, "dial", "", "PolicySync address e.g. /var/run/nodeagent/socket")
	fs.StringVar(&cfg.DialNetwork, "dial-network", "unix", "PolicySync network e.g. tcp, unix")
	fs.BoolVar(&cfg.PerHostALPEnabled, "per-host-alp-enabled", false, "Enable ALP.")
	fs.BoolVar(&cfg.PerHostWAFEnabled, "per-host-waf-enabled", false, "Enable WAF.")
	fs.BoolVar(&cfg.SidecarALPEnabled, "sidecar-alp-enabled", false, "Enable ALP.")
	fs.BoolVar(&cfg.SidecarWAFEnabled, "sidecar-waf-enabled", false, "Enable WAF.")
	fs.BoolVar(&cfg.SidecarLogsEnabled, "sidecar-logs-enabled", false, "Enable HTTP logging.")
	fs.Var(&cfg.WAFRulesetFiles, "waf-ruleset-file", "WAF ruleset file path to load. e.g. /etc/modsecurity-ruleset/tigera.conf. Can be specified multiple times.")
	fs.StringVar(&cfg.WAFRulesetRootDir, "waf-ruleset-root-dir", "", "WAF ruleset root dir path. e.g. /etc/waf")
	fs.Var(&cfg.WAFDirectives, "waf-directive", "Additional directives to specify for WAF (if enabled). Can be specified multiple times.")

	fs.StringVar(
		&cfg.LogLevel,
		"log-level",
		getEnv("LOG_LEVEL", "info"),
		"Log at specified level e.g. panic, fatal, info, debug, trace",
	)

	fs.StringVar(&cfg.SubscriptionType,
		"subscription-type",
		getEnv("DIKASTES_SUBSCRIPTION_TYPE", "per-host-policies"),
		"Subscription type e.g. per-pod-policies, per-host-policies",
	)
	fs.StringVar(
		&cfg.HTTPServerAddr,
		"http-server-addr",
		getEnv("DIKASTES_HTTP_BIND_ADDR", "0.0.0.0"),
		"HTTP server address",
	)
	fs.StringVar(
		&cfg.HTTPServerPort,
		"http-server-port",
		getEnv("DIKASTES_HTTP_PORT", ""),
		"HTTP server port",
	)

	// envoy init settings
	fs.StringVar(
		&cfg.EnvoyInboundPort,
		"envoy-inbound-port",
		getEnv("ENVOY_INBOUND_PORT", "16001"),
		"Envoy inbound port",
	)

	fs.StringVar(
		&cfg.EnvoyMetricsPort,
		"envoy-metrics-port",
		getEnv("ENVOY_METRICS_PORT", "9901"),
		"Envoy metrics port",
	)

	fs.StringVar(
		&cfg.EnvoyLivenessPort,
		"envoy-liveness-port",
		getEnv("ENVOY_LIVENESS_PORT", "16004"),
		"Envoy liveness port",
	)

	fs.StringVar(
		&cfg.EnvoyReadinessPort,
		"envoy-readiness-port",
		getEnv("ENVOY_READINESS_PORT", "16005"),
		"Envoy readiness port",
	)

	fs.StringVar(
		&cfg.EnvoyStartupProbePort,
		"envoy-startup-probe-port",
		getEnv("ENVOY_STARTUP_PROBE_PORT", "16006"),
		"Envoy startup probe port",
	)

	fs.StringVar(
		&cfg.EnvoyHealthCheckPort,
		"envoy-health-check-port",
		getEnv("ENVOY_HEALTH_CHECK_PORT", "16007"),
		"Envoy health check port",
	)

	return cfg
}

var subcmds = map[string]bool{
	"init-sidecar": true,
	"server":       true,
}

func (c *Config) Parse(args []string) error {
	// we handle the presence of subcommands here
	// legacy arguments are:
	// - dikastes init-siecar --sidecar-alp-enabled --sidecar-waf-enabled --sidecar-logs-enabled
	// - dikastes server -dial /var/run/nodeagent/nodeagent.sock -listen /var/run/dikastes/dikastes.sock
	// - dikastes client <namespace> <account> -dial /var/run/nodeagent/nodeagent.sock
	// new arguments are (preferred, client is now deprecated):
	// - dikastes --dial /var/run/nodeagent/nodeagent.sock --listen /var/run/dikastes/dikastes.sock

	switch {
	case len(args) < 2: // args[0] is program name, args[1] is subcommand
		return c.FlagSet.Parse(args) // handle no subcommand, no args
	case subcmds[args[1]]: // handle with subcommand
		c.Command = args[1]
		return c.FlagSet.Parse(args[2:])
	case args[1] == "client":
		os.Exit(1) // client is deprecated
	default: // all other cases
		return c.FlagSet.Parse(args[1:])
	}
	return nil
}

func (c *Config) Fields() log.Fields {
	b, err := json.Marshal(c)
	if err != nil {
		return log.Fields{}
	}
	var f log.Fields
	if err := json.Unmarshal(b, &f); err != nil {
		return log.Fields{}
	}
	return f
}

type stringArray []string

func (i *stringArray) String() string {
	return strings.Join(*i, ", ")
}

func (i *stringArray) Value() []string {
	return *i
}

func (i *stringArray) Set(value string) error {
	*i = append(*i, strings.Trim(value, "\"'"))
	return nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
