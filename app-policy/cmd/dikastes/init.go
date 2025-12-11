package main

import (
	"context"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"

	envoyconfig "github.com/projectcalico/calico/app-policy/envoy/config"
	"github.com/projectcalico/calico/app-policy/flags"
)

func runInit(config *flags.Config) {
	// Initialize iptables/nftables rules.
	switch config.Dataplane {
	case "iptables":
		initIptables(config)
	case "nftables":
		initNftables(config)
	default:
		log.Fatal("Unsupported dataplane: " + config.Dataplane)
	}

	// Save envoy-config file
	tpl := template.Must(template.New("envoy-config").
		Parse(envoyconfig.Config))
	envFile, err := os.Create(envoyconfig.Path)
	if err != nil {
		log.WithError(err).Fatal("Can't create envoy-config file")
	}
	err = tpl.Execute(envFile, config)
	if err != nil {
		log.WithError(err).Fatal("Error while processing envoy-config file")
	}
	err = envFile.Close()
	if err != nil {
		log.Fatal("Error while saving envoy-config file")
	}
}

func initIptables(config *flags.Config) {
	natv4, err := iptables.New()
	if err != nil {
		log.Fatal(err)
	}

	_ = natv4.NewChain("nat", inputRedirectChain)
	_ = natv4.NewChain("nat", inputProxyInbound)

	inboundStaticRules := generateRules(
		config.EnvoyInboundPort,
		config.EnvoyMetricsPort,
		config.EnvoyLivenessPort,
		config.EnvoyReadinessPort,
		config.EnvoyStartupProbePort,
		config.EnvoyHealthCheckPort,
	)
	for _, rule := range inboundStaticRules {
		if err := natv4.Append(rule.table, rule.chain, rule.ruleSpecs...); err != nil {
			log.
				WithFields(log.Fields{
					"table": rule.table,
					"chain": rule.chain,
					"rule":  strings.Join(rule.ruleSpecs, " "),
				}).
				WithError(err).
				Fatal("failed to add rule")
		}
	}
}

func initNftables(config *flags.Config) {
	nft, err := knftables.New(knftables.IPv4Family, "nat")
	if err != nil {
		log.WithError(err).Fatal("Failed to create nftables instance")
	}

	tx := nft.NewTransaction()
	tx.Add(&knftables.Table{})

	// Add in the base chain and hook it to prerouting with priority DNAT.
	tx.Add(&knftables.Chain{
		Name:     "prerouting",
		Hook:     knftables.PtrTo(knftables.PreroutingHook),
		Type:     knftables.PtrTo(knftables.NATType),
		Priority: knftables.PtrTo(knftables.DNATPriority),
	})

	// Add in sub-chains which are referenced by the rules.
	tx.Add(&knftables.Chain{Name: inputRedirectChain})
	tx.Add(&knftables.Chain{Name: inputProxyInbound})

	// Generate and add the static rules.
	inboundStaticRules := generateRulesNftables(
		config.EnvoyInboundPort,
		config.EnvoyMetricsPort,
		config.EnvoyLivenessPort,
		config.EnvoyReadinessPort,
		config.EnvoyStartupProbePort,
		config.EnvoyHealthCheckPort,
	)
	for _, rule := range inboundStaticRules {
		tx.Add(&rule)
	}

	// Commit the transaction to apply the changes.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := nft.Run(ctx, tx); err != nil {
		log.WithError(err).Fatal("Failed to commit nftables transaction")
	}
}
