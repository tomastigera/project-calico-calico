package main

import (
	"fmt"
	"net/http"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/voltron/internal/pkg/bootstrap"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
)

const (
	// EnvConfigPrefix represents the prefix used to load ENV variables required for startup
	EnvConfigPrefix = "GUARDIAN"
)

// Config is a configuration used for Guardian
type config struct {
	LogLevel   string `default:"DEBUG"`
	VoltronURL string `required:"true" split_words:"true" default:"localhost:30000"`
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	log.Info("Recv Request")
	_, _ = fmt.Fprintf(w, "Received on path: %s", r.URL.Path)
}

func main() {
	cfg := config{}
	if err := envconfig.Process(EnvConfigPrefix, &cfg); err != nil {
		log.Fatal(err)
	}

	bootstrap.ConfigureLogging(cfg.LogLevel)

	log.Infof("Attempting to Dial at %s", cfg.VoltronURL)

	clnTunnel, err := tunnel.Dial(cfg.VoltronURL)
	if err != nil {
		log.Fatal("Could not connect to Voltron")
	}

	log.Info("Guardian side stream established.")

	http.HandleFunc("/", defaultHandler)
	err = http.Serve(clnTunnel, nil)
	if err != nil {
		log.Fatal("Couldn't start Guardian server")
	}
}
