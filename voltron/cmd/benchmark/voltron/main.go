package main

import (
	"net"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/voltron/internal/pkg/bootstrap"
	"github.com/projectcalico/calico/voltron/internal/pkg/utils"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
)

const (
	// EnvConfigPrefix represents the prefix used to load ENV variables required for startup
	EnvConfigPrefix = "VOLTRON"
)

// Config is a configuration used for Voltron
type config struct {
	LogLevel string `default:"INFO"`
	Port     string `default:"5555"`
}

// SimpleServer is a struct that allows a simple server & its tunnel to be spun up.
type SimpleServer struct {
	listenAddress string
	tunnelAddress string
}

// NewSimpleServer creates a simple Sender which listens on TCP Socket at listenAddress
// and forwards it to tunnel on tunnelAddress
func NewSimpleServer(listenAddress, tunnelAddress string) *SimpleServer {
	s := &SimpleServer{
		listenAddress: listenAddress,
		tunnelAddress: tunnelAddress,
	}

	log.Infof("Created Sender with Server Address %s and Tunnel Address %s", s.listenAddress, s.tunnelAddress)
	return s
}

// Start listens on TCP socket for incoming connections and connects to the other end of the tunnel.
func (s *SimpleServer) Start() {
	// Create Server
	lisServer, err := net.Listen("tcp", s.listenAddress)
	if err != nil {
		log.Fatalf("Main Fail to Listen, %s", err)
	}
	defer func() { _ = lisServer.Close() }()

	// Tunnel Starts Listening
	lisTunnel, err := net.Listen("tcp", s.tunnelAddress)
	if err != nil {
		log.Fatalf("Fail to Listen, %s", err)
	}

	// Create server for the tunnel
	srv, err := tunnel.NewServer()
	if err != nil {
		log.Fatal("Fail to Create tunnel")
	}

	go func() {
		log.Infof("Main Srv Listening on %s", lisServer.Addr())
		err := srv.Serve(lisTunnel)
		if err != nil {
			log.Fatalf("Error starting main server: %s", err)
		}
	}()

	// Tunnel Set Up. Voltron accepts Tunnel from Guardian (Guardian Dials)

	srvTunnel, err := srv.AcceptTunnel()
	if err != nil {
		log.Fatal("Fail to Establish Tunnel.")
	}

	log.Infof("Tunnel established & server listening on address: %s", lisTunnel.Addr())

	log.Info("Main Server listening for connections")
	for {
		conn, err := lisServer.Accept()
		if err != nil {
			log.Errorf("Error Accepting Connection %s", err.Error())
		}

		rwc, err := srvTunnel.OpenStream()
		if err != nil {
			log.Fatalf("Error opening stream %s", err)
		}

		go utils.SocketCopy(rwc, conn)
	}
}
func main() {
	cfg := config{}
	if err := envconfig.Process(EnvConfigPrefix, &cfg); err != nil {
		log.Fatal(err)
	}

	bootstrap.ConfigureLogging(cfg.LogLevel)

	sender := NewSimpleServer("localhost:"+cfg.Port, "localhost:30000")
	sender.Start()
}
