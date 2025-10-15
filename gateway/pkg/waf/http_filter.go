// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package waf

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthzv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/projectcalico/calico/app-policy/health"
	"github.com/projectcalico/calico/app-policy/waf"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/gateway/pkg/license"
	"github.com/projectcalico/calico/gateway/pkg/waf/service"
	"github.com/projectcalico/calico/gateway/pkg/waf/transaction"
	"github.com/projectcalico/calico/gateway/pkg/waf/unlicensed"
)

type ServerOptions struct {
	TcpPort              int
	HttpPort             int
	SocketPath           string
	WafRulesetRootDir    string
	LogFileDirectory     string
	LogFileName          string
	LogAggregationPeriod time.Duration
	MustKeepFields       []string
}

type WAFHTTPFilter struct {
	options          ServerOptions
	license          license.GatewayLicense
	logger           func(*proto.WAFEvent)
	wafServerManager *service.WAFServiceManager
	healthServer     *http.Server
	tcpGRPCServer    *grpc.Server
	unixGRPCServer   *grpc.Server

	healthzv1.HealthServer
	grpcListenAddr net.Addr
}

func NewWAFHTTPFilter(opts ServerOptions, license license.GatewayLicense, logger func(*proto.WAFEvent)) *WAFHTTPFilter {

	var wafRulesetRootFS fs.FS

	if opts.WafRulesetRootDir != "" {
		// When a ruleset root path is provided, we use it as a root
		// the fs used to configure WAF rules.
		// All path will be relative to rulesetRootDir.
		// This is the recommended option when specifying some ruleset(s).
		wafRulesetRootFS = os.DirFS(opts.WafRulesetRootDir)
	} else {
		// Default for testing
		wafRulesetRootFS = nil // Uses default coraza config
	}

	wafServerManager := service.NewWAFServiceManager(wafRulesetRootFS, logger)
	wafServerManager.OnUpdate(DefaultDirectives) // will panic if directives are not valid

	res := &WAFHTTPFilter{
		options:          opts,
		license:          license,
		logger:           logger,
		wafServerManager: wafServerManager,
		HealthServer:     health.NewHealthCheckService(&alwaysReadyReporter{}),
	}

	return res
}

func (f *WAFHTTPFilter) Start() error {
	if f.options.TcpPort == 0 && f.options.SocketPath == "" {
		return fmt.Errorf("please configure port or socketPath")
	}
	if f.options.TcpPort != 0 {
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", f.options.TcpPort))
		if err != nil {
			return fmt.Errorf("failed to listen: %v", err)
		}
		f.grpcListenAddr = lis.Addr()

		f.tcpGRPCServer = grpc.NewServer()
		envoy_service_proc_v3.RegisterExternalProcessorServer(f.tcpGRPCServer, f)
		healthzv1.RegisterHealthServer(f.tcpGRPCServer, f)

		go func() {
			err = f.tcpGRPCServer.Serve(lis)
			if err != nil {
				logrus.Fatalf("failed to serve: %v", err)
			}
		}()
	}
	if f.options.SocketPath != "" {
		// Create Unix listener
		f.unixGRPCServer = grpc.NewServer()
		envoy_service_proc_v3.RegisterExternalProcessorServer(f.unixGRPCServer, f)

		if _, err := os.Stat(f.options.SocketPath); err == nil {
			if err := os.RemoveAll(f.options.SocketPath); err != nil {
				logrus.Fatalf("failed to remove: %v", err)
			}
		}

		ul, err := net.Listen("unix", f.options.SocketPath)
		if err != nil {
			logrus.Fatalf("failed to listen: %v", err)
		}

		// We need to allow reading and writing to the socket by all users
		// as the sidecar runs as root (for the file logger to work) and the
		// envoy proxy runs as a non-root user.
		err = os.Chmod(f.options.SocketPath, 0o666)
		if err != nil {
			logrus.Fatalf("failed to set permissions: %v", err)
		}

		go func() {
			err = f.unixGRPCServer.Serve(ul)
			if err != nil {
				logrus.Fatalf("failed to serve: %v", err)
			}
		}()
	}

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", getHealthCheckHandler(f.options))

	f.healthServer = &http.Server{Addr: fmt.Sprintf(":%d", f.options.HttpPort), Handler: healthMux}
	return f.healthServer.ListenAndServe()
}

func (f *WAFHTTPFilter) Stop() error {
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
			logrus.Errorf("Could not connect: %v", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, "service connection failed")
			return
		}
		client := healthzv1.NewHealthClient(conn)
		defer func() {
			if err := conn.Close(); err != nil {
				logrus.Errorf("Could not close connection: %v", err)
			}
		}()

		// Check health
		logrus.Debugf("Checking health for %s", target)
		healthResp, err := client.Check(r.Context(), &healthzv1.HealthCheckRequest{})
		if err != nil {
			logrus.Errorf("Could not check health: %v", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, "health check failed")
			return
		}
		if healthResp.Status != healthzv1.HealthCheckResponse_SERVING {
			logrus.Errorf("Health check failed: %v", healthResp.Status)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, "service not ready")
			return
		}
		logrus.Debugf("Health check passed: %v", healthResp.Status)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "OK")
	}
}

// handleDirectivesUpdate processes the directivesJson metadata from the gRPC context.
// IMPORTANT: this function is coded to be run in a goroutine
func (s *WAFHTTPFilter) handleDirectivesUpdate(directivesJson []string) {
	logrus.Debugf("handleDirectivesUpdate called with directivesJson: %v", directivesJson)
	if len(directivesJson) > 0 {
		var directives []string
		err := json.Unmarshal([]byte(directivesJson[0]), &directives)
		if err != nil {
			logrus.Errorf("Error decoding directives: %#v", err)
		}
		s.wafServerManager.OnUpdate(append(DefaultDirectives, directives...))
	}
}

func (s *WAFHTTPFilter) Process(srv envoy_service_proc_v3.ExternalProcessor_ProcessServer) error {
	ctx := srv.Context()
	logrus.Info("start Process()")

	md, _ := metadata.FromIncomingContext(ctx)
	logrus.Debugf("gRPC context metadata: %v", md)
	xForwardedFor := md["x-forwarded-for"]

	// Update config in parallel so that we don't delay request processing
	go s.handleDirectivesUpdate(md["directivesjson"])

	// Request processor when we're unlicensed (license status can change over time)
	unlicensedRequestProcessor := unlicensed.NewUnlicensedRequestHandler()

	// Use latest wafServer in case there was a config change since handling the previous request.
	errCh := make(chan error, 1)
	s.wafServerManager.Read(func(w coraza.WAF, evp *waf.WafEventsPipeline) {
		if w == nil {
			logrus.Panic("wafServerManager returned nil WAF service")
		}
		// Create a request processor that will handle the WAF checks using the current WAF config.
		requestProcessor, err := transaction.NewRequestHandler(
			w,
			xForwardedFor,
			[]func(*proto.WAFEvent, corazatypes.Transaction){
				evp.ProcessProtoEvent,
				func(event *proto.WAFEvent, tx corazatypes.Transaction) {
					logrus.Debugf("WAF event: %s", event.String())
				},
			},
		)
		if err != nil {
			logrus.Errorf("Error creating request processor: %v", err)
			errCh <- status.Errorf(codes.Internal, "cannot create request processor: %v", err)
		}

		for {
			select {
			case <-ctx.Done():
				e := ctx.Err()
				logrus.WithError(e).Info("Done!")
				errCh <- status.Errorf(codes.Canceled, "context canceled: %v", e)
				return
			default:
			}
			req, err := srv.Recv()
			if err == io.EOF {
				errCh <- err
				return
			}
			if err != nil {
				errCh <- status.Errorf(codes.Unknown, "cannot receive stream request: %v", err)
				return
			}

			if s.license.IsLicensed() {
				logrus.Debug("Processing request")
				resp := requestProcessor.Process(req)
				if err := srv.Send(resp); err != nil {
					logrus.Warnf("send error %v", err)
				}
			} else {
				logrus.Debug("Processing (unlicensed) request")
				resp := unlicensedRequestProcessor.Process(req)
				if err := srv.Send(resp); err != nil {
					logrus.Warnf("send error %v", err)
				}
			}
		}
	})

	return <-errCh
}

type alwaysReadyReporter struct{}

func (a *alwaysReadyReporter) Readiness() bool { return true }
