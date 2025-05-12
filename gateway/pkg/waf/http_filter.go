package waf

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/projectcalico/calico/felix/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type ServerOptions struct {
	TcpPort           int
	HttpPort          int
	SocketPath        string
	WafRulesetRootDir string
	LogToFile         bool
}

type WafHTTPFilter struct {
	options        ServerOptions
	extProcServer  *ExtProcServer
	healthServer   *http.Server
	tcpGRPCServer  *grpc.Server
	unixGRPCServer *grpc.Server
}

func NewWafHTTPFilter(opts ServerOptions, logger func(*proto.WAFEvent)) *WafHTTPFilter {
	// We hardcode the default configuration for now. Will update later.
	directives := []string{
		"Include @coraza.conf-recommended",
		"Include @crs-setup.conf.example",
		"Include @owasp_crs/*.conf",
		"SecRuleEngine On",

		// Tigera CRS customizations
		// Add some common content-types expected in micro-service traffic
		`SecAction \
    "id:900220,\
    phase:1,\
    nolog,\
    pass,\
    t:none,\
    setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |application/grpc| |application/grpc+proto| |application/grpc+json| |application/octet-stream|'"`,

		//Removes the rule "Host header is a numeric IP address"
		"SecRuleRemoveById 920350",
	}

	extProcServer := NewExtProcServer(opts.WafRulesetRootDir, directives, logger)

	return &WafHTTPFilter{
		options:       opts,
		extProcServer: extProcServer,
	}
}

func (f *WafHTTPFilter) Start() error {
	if f.options.TcpPort == 0 && f.options.SocketPath == "" {
		return fmt.Errorf("please configure port or socketPath")
	}
	if f.options.TcpPort != 0 {
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", f.options.TcpPort))
		if err != nil {
			return fmt.Errorf("failed to listen: %v", err)
		}

		f.tcpGRPCServer = grpc.NewServer()
		envoy_service_proc_v3.RegisterExternalProcessorServer(f.tcpGRPCServer, f.extProcServer)

		go func() {
			err = f.tcpGRPCServer.Serve(lis)
			if err != nil {
				log.Fatalf("failed to serve: %v", err)
			}
		}()
	}
	if f.options.SocketPath != "" {
		// Create Unix listener
		f.unixGRPCServer = grpc.NewServer()
		envoy_service_proc_v3.RegisterExternalProcessorServer(f.unixGRPCServer, f.extProcServer)

		// udsAddr := "/var/run/ext-proc/extproc.sock"
		if _, err := os.Stat(f.options.SocketPath); err == nil {
			if err := os.RemoveAll(f.options.SocketPath); err != nil {
				log.Fatalf("failed to remove: %v", err)
			}
		}

		ul, err := net.Listen("unix", f.options.SocketPath)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}

		err = os.Chmod(f.options.SocketPath, 0o700)
		if err != nil {
			log.Fatalf("failed to set permissions: %v", err)
		}

		// envoy distroless uid (65532)
		// Dockerfile uid
		err = os.Chown(f.options.SocketPath, 10001, 0)
		if err != nil {
			log.Fatalf("failed to set permissions: %v", err)
		}

		go func() {
			err = f.unixGRPCServer.Serve(ul)
			if err != nil {
				log.Fatalf("failed to serve: %v", err)
			}
		}()
	}

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", getHealthCheckHandler(f.options))

	f.healthServer = &http.Server{Addr: fmt.Sprintf(":%d", f.options.HttpPort), Handler: healthMux}
	return f.healthServer.ListenAndServe()
}

func (f *WafHTTPFilter) Stop() error {
	if f.tcpGRPCServer != nil {
		f.tcpGRPCServer.Stop()
	}
	if f.unixGRPCServer != nil {
		f.unixGRPCServer.Stop()
	}
	err := f.healthServer.Close()
	return err
}

// used by k8s readiness probes
// makes a processing request to check if the processor service is healthy
func getHealthCheckHandler(opts ServerOptions) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create gRPC dial options
		dialOpts := []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}

		var target string
		if opts.TcpPort != 0 {
			target = fmt.Sprintf("localhost:%d", opts.TcpPort)
		} else {
			target = "unix://" + opts.SocketPath
		}

		conn, err := grpc.NewClient(target, dialOpts...)
		if err != nil {
			log.Fatalf("Could not connect: %v", err)
		}
		client := envoy_service_proc_v3.NewExternalProcessorClient(conn)

		processor, err := client.Process(context.Background())
		if err != nil {
			log.Fatalf("Could not check: %v", err)
		}

		err = processor.Send(&envoy_service_proc_v3.ProcessingRequest{
			Request: &envoy_service_proc_v3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &envoy_service_proc_v3.HttpHeaders{},
			},
		})
		if err != nil {
			log.Fatalf("Could not check: %v", err)
		}

		response, err := processor.Recv()
		if err != nil {
			log.Fatalf("Could not check: %v", err)
		}

		if response != nil && response.GetRequestHeaders().Response.Status == envoy_service_proc_v3.CommonResponse_CONTINUE {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}
}
