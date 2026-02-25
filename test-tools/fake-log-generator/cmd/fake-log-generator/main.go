// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

var (
	requestDurations = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "linseed_request_duration_seconds",
		Help: "A Histogram of the linseed request duration in seconds",

		// Cumulative bucket upper bounds
		Buckets: []float64{0.5, 0.7, 0.8, 0.9, 1, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.8, 2, 5, 10},
	})
)

// LoadedConfig holds the config from env vars
type LoadedConfig struct {
	PromPort       int    `envconfig:"PROMETHEUSMETRICSPORT" default:"2112"`      // The prometheus port to expose
	Rate           int    `envconfig:"RATE" default:"2"`                          // The rate of log production in logs/second
	BatchSize      int    `envconfig:"BATCH_SIZE" default:"10"`                   // The size of the batch of logs to upload
	FlowFile       string `envconfig:"FLOW_LOG_FILE" default:"./flows/flows.log"` // The path to the file of example flows to use
	TokenPath      string `envconfig:"LINSEED_TOKEN" default:"/certs/token"`      // The path to the token file
	TenantID       string `envconfig:"ELASTIC_INDEX_SUFFIX" default:""`           // The tenantID to send to linseed
	DirectOutput   bool   `envconfig:"DIRECT_OUTPUT" default:"false"`             // whether to write logs to a file (for a real FluentD to upload) or to write to linseed directly
	URL            string `envconfig:"LINSEED_ENDPOINT" default:"https://tigera-linseed.tigera-elasticsearch.svc:9443"`
	CACertPath     string `envconfig:"LINSEED_CA_PATH" default:"/certs/cacert.crt"`
	ClientCertPath string `envconfig:"TLS_CRT_PATH" default:"/certs/tls.crt"`
	ClientKeyPath  string `envconfig:"TLS_KEY_PATH" default:"/certs/tls.key"`
	LogLevel       string `envconfig:"LOG_LEVEL" default:"INFO"` // The log level (one of PANIC, FATAL, ERROR, WARN, INFO, DEBUG, or TRACE)
}

// Config holds the config for this tool
type Config struct {
	loaded       LoadedConfig
	period       time.Duration
	restConfig   rest.Config
	exampleFlows []v1.FlowLog
}

func loadConfig() LoadedConfig {
	var cfg LoadedConfig

	err := envconfig.Process("", &cfg)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.WithFields(log.Fields{
		"BatchSize":              cfg.BatchSize,
		"Rate":                   cfg.Rate,
		"FlowFile":               cfg.FlowFile,
		"TokenPath":              cfg.TokenPath,
		"TenantID":               cfg.TenantID,
		"DirectOutput":           cfg.DirectOutput,
		"restcfg.URL":            cfg.URL,
		"restcfg.CACertPath":     cfg.CACertPath,
		"restcfg.ClientCertPath": cfg.ClientCertPath,
		"restcfg.ClientKeyPath":  cfg.ClientKeyPath,
		"restcfg.LogLevel":       cfg.LogLevel,
	}).Info("Loaded configuration using envconfig")

	return cfg
}

func main() {
	/*
		   Read in the sample logs from file

		   calculate period for required log rate
		   while true:
			record time
		   	Pick a random log.
			replace timestamps.
			write to file
			check time, see how long we have left before end of period.  Log if negative
		   	sleep for remaining time in period

	*/

	// Replace logrus' formatter with a custom one using our time format,
	// shared with the Python code.
	logutils.ConfigureFormatter("fake-log-gen")

	var cfg Config
	cfg.loaded = loadConfig()
	setLogLevel(cfg.loaded.LogLevel)
	cfg.restConfig.URL = cfg.loaded.URL
	cfg.restConfig.CACertPath = cfg.loaded.CACertPath
	cfg.restConfig.ClientCertPath = cfg.loaded.ClientCertPath
	cfg.restConfig.ClientKeyPath = cfg.loaded.ClientKeyPath
	cfg.period = time.Duration((float64(cfg.loaded.BatchSize) / float64(cfg.loaded.Rate))) * time.Second
	cfg.exampleFlows = readFlowLogs(cfg.loaded.FlowFile)

	// Start prometheus metrics
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.loaded.PromPort), nil)
		if err != nil {
			log.Fatal(log.WithError(err))
		}
	}()

	var cli client.Client
	var err error
	if cfg.loaded.DirectOutput {
		log.Info("Will write to Linseed direct")
		cli, err = client.NewClient(cfg.loaded.TenantID, cfg.restConfig, rest.WithTokenPath(cfg.loaded.TokenPath))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Info("Will write to file")
	}

	var startTime time.Time
	endTime := time.Now()
	log.Info("Starting log generation\n")
	for {
		startTime = endTime
		endTime = flowLogIteration(startTime, cfg, cli)
	}
}

func flowLogIteration(startTime time.Time, cfg Config, cli client.Client) (endTime time.Time) {
	endTime = startTime.Add(cfg.period)

	logs := makeFlowLogs(cfg.loaded.BatchSize, cfg.exampleFlows)
	if cfg.loaded.DirectOutput {
		_ = sendFlowLogs(cfg.loaded.TenantID, cli, logs)
	} else {
		writeFlowLogs(cfg.loaded.FlowFile, logs)
	}
	leftTime := time.Until(endTime)
	if leftTime < 0 {
		log.Warn("Unable to complete this iteration in time, logs are being rate-limited")
	} else {
		time.Sleep(leftTime)
	}
	return endTime
}

func readFlowLogs(exampleFlowFile string) []v1.FlowLog {
	file, err := os.Open(exampleFlowFile)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = file.Close() }()

	var flows []v1.FlowLog
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		flow := v1.FlowLog{}
		line := scanner.Text()
		err := json.Unmarshal([]byte(line), &flow)
		if err != nil {
			log.WithError(err).Panicf("Error reading flow logs on line:\n %s\n", line)
		}
		flows = append(flows, flow)
	}
	if err := scanner.Err(); err != nil {
		log.WithError(err).Fatal("Failed to read flow logs file.")
	}
	return flows
}

func writeFlowLogs(FlowFile string, logs []v1.FlowLog) {
	log.Debug("writing logs")
	f, err := os.OpenFile(FlowFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.WithError(err).Fatal("Error opening file to write logs to")
	}
	defer func() { _ = f.Close() }()
	for _, mylog := range logs {
		flowlog, err := json.Marshal(mylog)
		if err != nil {
			log.Fatal(err)
		}
		record := fmt.Sprintf("%s\n", flowlog)
		if _, err := f.WriteString(record); err != nil {
			log.WithError(err).Fatal("Error writing logs to file")
		}
	}
}

func sendFlowLogs(TenantID string, cli client.Client, logs []v1.FlowLog) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before := time.Now()
	bulk, err := cli.FlowLogs(TenantID).Create(ctx, logs)
	diff := time.Since(before)
	requestDurations.Observe(diff.Seconds())

	if err != nil {
		log.Errorf("ERROR: %v  response: %+v in %v", err, bulk, diff.Milliseconds())
	}
	log.Infof("response: %+v in %v", bulk, diff)
	return diff
}

func makeFlowLogs(BatchSize int, exampleFlows []v1.FlowLog) []v1.FlowLog {
	logs := []v1.FlowLog{}
	for range BatchSize {
		logs = append(logs, makeFlowLog(exampleFlows))
	}
	return logs
}

func makeFlowLog(exampleflows []v1.FlowLog) v1.FlowLog {
	// pick a random log from the example logs, change the timestamps on it and return it.
	data := exampleflows[rand.Intn(len(exampleflows))]
	now := time.Now().Unix()
	data.EndTime = now
	data.StartTime = now - int64(rand.Intn(400))
	return data
}

func setLogLevel(logLevel string) {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatal(err)
	} else {
		log.SetLevel(level)
		log.Info(fmt.Sprintf("Log level set to %s", level))
	}
}
