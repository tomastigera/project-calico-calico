package main

import (
	"flag"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/gateway/pkg/waf"
)

func main() {
	var opts waf.ServerOptions

	var mustKeepFields string
	flag.IntVar(&opts.TcpPort, "tcpPort", 0, "gRPC port")
	flag.IntVar(&opts.HttpPort, "httpPort", 8080, "HTTP port (health monitoring)")
	flag.StringVar(&opts.SocketPath, "socketPath", "", "path to extProcServer unix socket")
	flag.StringVar(&opts.WafRulesetRootDir, "wafRulesetRootDir", "", "path to WAF ruleset")
	flag.StringVar(&opts.LogFileDirectory, "logFileDirectory", "", "log file directory")
	flag.StringVar(&opts.LogFileName, "logFileName", "", "log file name")
	flag.DurationVar(&opts.LogAggregationPeriod, "logAggregationPeriod", 60*time.Second, "log aggregation period")
	flag.StringVar(&mustKeepFields, "mustKeepFields", "rules", "comma separated list of fields to keep in WAF logs for aggregation")
	flag.Parse()

	opts.MustKeepFields = strings.Split(mustKeepFields, ",")

	fileLogger, stopAggController, err := waf.NewFileLogger(opts.LogFileDirectory, opts.LogFileName, opts.LogAggregationPeriod, opts.MustKeepFields)
	if err != nil {
		logrus.WithError(err).Fatal("Execution stopped with an error.")
	}
	defer stopAggController()

	filter := waf.NewWAFHTTPFilter(opts, fileLogger)
	err = filter.Start()
	if err != nil {
		logrus.WithError(err).Fatal("Execution stopped with an error.")
	}
}
