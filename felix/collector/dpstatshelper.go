// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package collector

import (
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/dnslog"
	"github.com/projectcalico/calico/felix/collector/file"
	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/goldmane"
	"github.com/projectcalico/calico/felix/collector/l7log"
	p "github.com/projectcalico/calico/felix/collector/prometheus"
	"github.com/projectcalico/calico/felix/collector/syslog"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/wafevents"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/wireguard"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	// Log dispatcher names
	FlowLogsFileReporterName     = "file"
	DNSLogsFileReporterName      = "dnsfile"
	L7LogsFileReporterName       = "l7file"
	WAFEventsFileReporterName    = "waf"
	FlowLogsGoldmaneReporterName = "goldmane"
)

// New creates the required dataplane stats collector, reporters and aggregators.
// Returns a collector that statistics should be reported to.
func New(
	configParams *config.Config,
	lookupsCache *calc.LookupsCache,
	healthAggregator *health.HealthAggregator,
) Collector {
	registry := prometheus.NewRegistry()

	if configParams.WireguardEnabled {
		registry.MustRegister(wireguard.MustNewWireguardMetrics())
	}
	statsCollector := newCollector(
		lookupsCache,
		&Config{
			StatsDumpFilePath:            configParams.GetStatsDumpFilePath(),
			AgeTimeout:                   config.DefaultAgeTimeout,
			InitialReportingDelay:        config.DefaultInitialReportingDelay,
			ExportingInterval:            config.DefaultExportingInterval,
			EnableServices:               configParams.FlowLogsFileIncludeService,
			EnableNetworkSets:            configParams.FlowLogsEnableNetworkSets,
			EnableDestDomainsByClient:    configParams.FlowLogsDestDomainsByClient,
			PolicyEvaluationMode:         configParams.FlowLogsPolicyEvaluationMode,
			FlowLogsFlushInterval:        configParams.FlowLogsFlushInterval,
			MaxOriginalSourceIPsIncluded: configParams.FlowLogsMaxOriginalIPsIncluded,
			IsBPFDataplane:               configParams.BPFEnabled,
			DisplayDebugTraceLogs:        configParams.FlowLogsCollectorDebugTrace,
		},
	)

	if configParams.PrometheusReporterEnabled {
		log.WithFields(log.Fields{
			"port":     configParams.PrometheusReporterPort,
			"certFile": configParams.PrometheusReporterCertFile,
			"keyFile":  configParams.PrometheusReporterKeyFile,
			"caFile":   configParams.PrometheusReporterCAFile,
		}).Info("Starting prometheus reporter")

		pr := p.NewReporter(
			registry,
			configParams.PrometheusReporterPort,
			configParams.DeletedMetricsRetentionSecs,
			configParams.PrometheusReporterCertFile,
			configParams.PrometheusReporterKeyFile,
			configParams.PrometheusReporterCAFile,
		)
		pr.AddAggregator(p.NewPolicyRulesAggregator(configParams.DeletedMetricsRetentionSecs, configParams.FelixHostname))
		pr.AddAggregator(p.NewDeniedPacketsAggregator(configParams.DeletedMetricsRetentionSecs, configParams.FelixHostname))
		statsCollector.RegisterMetricsReporter(pr)
	}

	dispatchers := map[string]types.Reporter{}

	if configParams.FlowLogsFileEnabled {
		log.WithFields(log.Fields{
			"directory": configParams.GetFlowLogsFileDirectory(),
			"max_size":  configParams.FlowLogsFileMaxFileSizeMB,
			"max_files": configParams.FlowLogsFileMaxFiles,
		}).Info("Creating Flow Logs FileReporter")
		fd := file.NewReporter(
			configParams.GetFlowLogsFileDirectory(),
			file.FlowLogFilename,
			configParams.FlowLogsFileMaxFileSizeMB,
			configParams.FlowLogsFileMaxFiles,
		)
		dispatchers[FlowLogsFileReporterName] = fd
	}

	goldmaneAddr := configParams.FlowLogsGoldmaneServer
	if goldmaneAddr != "" {
		log.Infof("Creating Flow Logs GoldmaneReporter with address %v", goldmaneAddr)
		gd, err := goldmane.NewReporter(goldmaneAddr)
		if err != nil {
			log.WithError(err).Fatalf("Failed to create Flow Logs GoldmaneReporter.")
		} else {
			dispatchers[FlowLogsGoldmaneReporterName] = gd
		}
	}

	if len(dispatchers) > 0 {
		log.Info("Creating Flow Logs Reporter")
		var offsetReader flowlog.LogOffset = &flowlog.NoOpLogOffset{}
		if configParams.FlowLogsDynamicAggregationEnabled {
			offsetReader = flowlog.NewRangeLogOffset(flowlog.NewFluentDLogOffsetReader(configParams.GetFlowLogsPositionFilePath()),
				int64(configParams.FlowLogsAggregationThresholdBytes))
		}
		cw := flowlog.NewReporter(dispatchers, configParams.FlowLogsFlushInterval, healthAggregator,
			configParams.FlowLogsEnableHostEndpoint, configParams.FlowLogsCollectorDebugTrace, offsetReader)
		configureFlowAggregation(configParams, cw)
		statsCollector.RegisterMetricsReporter(cw)
	}

	if configParams.SyslogReporterEnabled {
		log.Info("Creating a Syslog Reporter")
		syslogReporter := syslog.New(configParams.SyslogReporterNetwork, configParams.SyslogReporterAddress)
		if syslogReporter != nil {
			statsCollector.RegisterMetricsReporter(syslogReporter)
		}
	}

	if configParams.DNSLogsFileEnabled {
		// Create the reporter, aggregator and dispatcher for DNS logging.
		dnsLogReporter := dnslog.NewReporter(
			map[string]types.Reporter{
				DNSLogsFileReporterName: file.NewReporter(
					configParams.DNSLogsFileDirectory,
					file.DNSLogFilename,
					configParams.DNSLogsFileMaxFileSizeMB,
					configParams.DNSLogsFileMaxFiles,
				),
			},
			configParams.DNSLogsFlushInterval,
			healthAggregator,
		)
		dnsLogReporter.AddAggregator(
			dnslog.NewAggregator().
				AggregateOver(dnslog.AggregationKind(configParams.DNSLogsFileAggregationKind)).
				IncludeLabels(configParams.DNSLogsFileIncludeLabels).
				PerNodeLimit(configParams.DNSLogsFilePerNodeLimit),
			[]string{DNSLogsFileReporterName},
		)
		statsCollector.SetDNSLogReporter(dnsLogReporter)
	}

	if configParams.L7LogsFileEnabled {
		// Create the reporter, aggregator and dispatcher for L7 logging.
		l7LogReporter := l7log.NewReporter(
			map[string]types.Reporter{
				L7LogsFileReporterName: file.NewReporter(
					configParams.L7LogsFileDirectory,
					file.L7LogFilename,
					configParams.L7LogsFileMaxFileSizeMB,
					configParams.L7LogsFileMaxFiles,
				),
			},
			configParams.L7LogsFlushInterval,
			healthAggregator,
		)
		// Create the aggregation kind
		aggKind := l7log.AggregationKindFromConfigParams(configParams)
		l7LogReporter.AddAggregator(
			l7log.NewAggregator().
				AggregateOver(aggKind).
				PerNodeLimit(configParams.L7LogsFilePerNodeLimit),
			[]string{L7LogsFileReporterName},
		)
		statsCollector.SetL7LogReporter(l7LogReporter)
	}

	if configParams.WAFEventLogsFileEnabled {
		statsCollector.SetWAFEventsReporter(wafevents.NewReporter(
			[]types.Reporter{
				file.NewReporter(
					configParams.WAFEventLogsFileDirectory,
					file.WAFEventLogFilename,
					configParams.WAFEventLogsFileMaxFileSizeMB,
					configParams.WAFEventLogsFileMaxFiles,
				),
			},
			configParams.WAFEventLogsFlushInterval,
			healthAggregator,
		))
	}

	return statsCollector
}

// configureFlowAggregation adds appropriate aggregators to the FlowLogReporter, depending on configuration.
func configureFlowAggregation(configParams *config.Config, fr *flowlog.FlowLogReporter) {
	addedFileAllow := false
	addedFileDeny := false
	if configParams.FlowLogsFileEnabled {
		if !addedFileAllow && configParams.FlowLogsFileEnabledForAllowed {
			log.Info("Creating Flow Logs Aggregator for allowed")
			caa := flowlog.NewAggregator().
				AggregateOver(flowlog.AggregationKind(configParams.FlowLogsFileAggregationKindForAllowed)).
				DisplayDebugTraceLogs(configParams.FlowLogsCollectorDebugTrace).
				IncludeLabels(configParams.FlowLogsFileIncludeLabels).
				IncludePolicies(configParams.FlowLogsFileIncludePolicies).
				IncludeService(configParams.FlowLogsFileIncludeService).
				IncludeProcess(configParams.FlowLogsCollectProcessInfo).
				IncludeTcpStats(configParams.FlowLogsCollectTcpStats).
				MaxOriginalIPsSize(configParams.FlowLogsMaxOriginalIPsIncluded).
				MaxDomains(configParams.FlowLogsFileDomainsLimit).
				PerFlowProcessLimit(configParams.FlowLogsFilePerFlowProcessLimit).
				PerFlowProcessArgsLimit(configParams.FlowLogsFilePerFlowProcessArgsLimit).
				NatOutgoingPortLimit(configParams.FlowLogsFileNatOutgoingPortLimit).
				ForAction(rules.RuleActionAllow)
			log.Info("Adding Flow Logs Aggregator (allowed) for File logs")
			fr.AddAggregator(caa, []string{FlowLogsFileReporterName})
		}
		if !addedFileDeny && configParams.FlowLogsFileEnabledForDenied {
			log.Info("Creating Flow Logs Aggregator for denied")
			cad := flowlog.NewAggregator().
				AggregateOver(flowlog.AggregationKind(configParams.FlowLogsFileAggregationKindForDenied)).
				DisplayDebugTraceLogs(configParams.FlowLogsCollectorDebugTrace).
				IncludeLabels(configParams.FlowLogsFileIncludeLabels).
				IncludePolicies(configParams.FlowLogsFileIncludePolicies).
				IncludeService(configParams.FlowLogsFileIncludeService).
				IncludeTcpStats(configParams.FlowLogsCollectTcpStats).
				IncludeProcess(configParams.FlowLogsCollectProcessInfo).
				MaxOriginalIPsSize(configParams.FlowLogsMaxOriginalIPsIncluded).
				MaxDomains(configParams.FlowLogsFileDomainsLimit).
				PerFlowProcessLimit(configParams.FlowLogsFilePerFlowProcessLimit).
				PerFlowProcessArgsLimit(configParams.FlowLogsFilePerFlowProcessArgsLimit).
				NatOutgoingPortLimit(configParams.FlowLogsFileNatOutgoingPortLimit).
				ForAction(rules.RuleActionDeny)
			log.Info("Adding Flow Logs Aggregator (denied) for File logs")
			fr.AddAggregator(cad, []string{FlowLogsFileReporterName})
		}
	}
	if configParams.FlowLogsGoldmaneServer != "" {
		log.Info("Creating golemane Aggregator for allowed")
		gaa := flowlog.NewAggregator().
			AggregateOver(flowlog.AggregationKind(configParams.FlowLogsFileAggregationKindForAllowed)).
			DisplayDebugTraceLogs(configParams.FlowLogsCollectorDebugTrace).
			IncludeLabels(true).
			IncludePolicies(true).
			IncludeService(true).
			MaxOriginalIPsSize(configParams.FlowLogsMaxOriginalIPsIncluded).
			ForAction(rules.RuleActionAllow)
		log.Info("Adding Flow Logs Aggregator (allowed) for goldmane")
		fr.AddAggregator(gaa, []string{FlowLogsGoldmaneReporterName})
		log.Info("Creating goldmane Aggregator for denied")
		gad := flowlog.NewAggregator().
			AggregateOver(flowlog.AggregationKind(configParams.FlowLogsFileAggregationKindForDenied)).
			DisplayDebugTraceLogs(configParams.FlowLogsCollectorDebugTrace).
			IncludeLabels(true).
			IncludePolicies(true).
			IncludeService(true).
			MaxOriginalIPsSize(configParams.FlowLogsMaxOriginalIPsIncluded).
			ForAction(rules.RuleActionDeny)
		log.Info("Adding Flow Logs Aggregator (denied) for goldmane")
		fr.AddAggregator(gad, []string{FlowLogsGoldmaneReporterName})
	}
}
