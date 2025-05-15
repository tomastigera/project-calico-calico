package main

import (
	"flag"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/gateway/pkg/waf"
)

func main() {
	var opts waf.ServerOptions

	flag.IntVar(&opts.TcpPort, "tcpPort", 0, "gRPC port")
	flag.IntVar(&opts.HttpPort, "httpPort", 8080, "HTTP port (health monitoring)")
	flag.StringVar(&opts.SocketPath, "socketPath", "", "path to extProcServer unix socket")
	flag.StringVar(&opts.WafRulesetRootDir, "wafRulesetRootDir", "", "path to WAF ruleset")
	flag.Parse()

	filter := waf.NewWafHTTPFilter(opts, waf.DebugLogger)
	err := filter.Start()
	if err != nil {
		logrus.WithError(err).Fatal("Execution stopped with an error.")
	}
}
