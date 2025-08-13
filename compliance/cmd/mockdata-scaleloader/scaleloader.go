package main

import (
	"flag"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"

	"github.com/projectcalico/calico/compliance/mockdata/scaleloader"
	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/projectcalico/calico/lma/pkg/elastic"
)

type Scenario struct {
	Playbooks []scaleloader.PlaybookCfg `yaml:"playbooks"`
	Duration  string                    `yaml:"duration"`
	StartTime string                    `yaml:"start"`
}

func main() {
	var scenario string
	var playbookBase string
	var logLevel string
	flag.StringVar(&scenario, "scenario", "", "Scenario file to load")
	flag.StringVar(&playbookBase, "playbook-dir", "./", "Directory containing the playbooks")
	flag.StringVar(&logLevel, "log-level", "info", "Log level")
	flag.Parse()

	args := flag.Args()
	if len(args) > 1 {
		log.WithField("args", args).Fatal("Too many args, expected at most 1")
	}

	if (scenario != "") && (len(args) != 0) {
		log.Fatal("Both '-scenario' option and args provided, pick one.")
	}

	if len(args) == 1 {
		scenario = args[0]
	}

	l, err := log.ParseLevel(logLevel)
	if err != nil {
		log.WithError(err).Fatal("Failed to parse log level")
	}
	log.SetLevel(l)

	if scenario == "" {
		log.Fatal("No scenario specified")
	}

	scenarioFile, err := os.ReadFile(scenario)
	if err != nil {
		log.Fatalf("Unable to read scenario file: %v", err)
	}

	var scen Scenario
	err = yaml.Unmarshal(scenarioFile, &scen)
	if err != nil {
		log.Fatalf("Unable to unmarshal scenario file: %v", err)
	}

	log.Infof("Loading Scenario: %s", scenario)
	sl, err := scaleloader.NewScaleLoader(playbookBase, scen.Playbooks)
	if err != nil {
		log.Fatalf("Failed to load scenario %v", err)
	}

	// Initialize elastic.
	es := elastic.MustGetElasticClient()

	// Create a linseed client. TODO
	config := rest.Config{
		// URL:             cfg.LinseedURL,
		// CACertPath:      cfg.LinseedCA,
		// ClientKeyPath:   cfg.LinseedClientKey,
		// ClientCertPath:  cfg.LinseedClientCert,
	}
	linseed, err := client.NewClient("", config)
	if err != nil {
		log.WithError(err).Fatal("failed to create linseed client")
	}
	store := api.NewComplianceStore(linseed, "")

	var duration time.Duration
	if scen.Duration == "" {
		duration = time.Hour * 24
		log.WithField("duration", duration).Info("Using default duration")
	} else {
		var err error
		duration, err = time.ParseDuration(scen.Duration)
		if err != nil {
			log.WithError(err).Fatal("Unable to parse Duration in scenario")
		}
	}

	var start time.Time
	if scen.StartTime == "" {
		start = time.Now().Add(-duration)
		log.WithField("start", start).Info("Using default start time (current time - duration)")
	} else {
		var err error
		start, err = time.Parse("2006-01-02T15:04:05", scen.StartTime)
		if err != nil {
			log.WithError(err).Fatal("Unable to parse StartTime in scenario")
		}
	}

	sl.PopulateES(start, duration, es, store)

	// Retrieve the testdata.
	log.Info("success")
}
