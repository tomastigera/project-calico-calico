package waf

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/projectcalico/calico/app-policy/waf"
	"github.com/projectcalico/calico/felix/proto"
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
	wafServer      *waf.Server
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

	events := waf.NewEventsPipeline(logger)

	wafServer, err := waf.New(wafRulesetRootFS, nil, directives, false, events)
	if err != nil {
		logrus.Panicf("cannot initialize WAF: %v", err)
	}

	return &WafHTTPFilter{
		options:   opts,
		wafServer: wafServer,
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
		envoy_service_proc_v3.RegisterExternalProcessorServer(f.tcpGRPCServer, f)

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
		envoy_service_proc_v3.RegisterExternalProcessorServer(f.unixGRPCServer, f)

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

func (s *WafHTTPFilter) Process(srv envoy_service_proc_v3.ExternalProcessor_ProcessServer) error {
	ctx := srv.Context()
	logrus.Info("start Process()")

	md, _ := metadata.FromIncomingContext(ctx)
	logrus.Debug("gRPC context metadata: %v", md)

	for {
		select {
		case <-ctx.Done():
			e := ctx.Err()
			logrus.WithError(e).Info("Done!")
			return e
		default:
		}
		req, err := srv.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Unknown, "cannot receive stream request: %v", err)
		}

		logrus.Infof("Processing request %v", req)

		resp := &envoy_service_proc_v3.ProcessingResponse{}
		switch v := req.Request.(type) {
		case *envoy_service_proc_v3.ProcessingRequest_RequestHeaders:
			blockedByWAF := false

			headersList := v.RequestHeaders.Headers.GetHeaders()
			headersMap := make(map[string]string)
			for _, headerValue := range headersList {
				key := headerValue.GetKey()
				value := string(headerValue.GetRawValue())
				logrus.Debugf("Adding %s=%s to headersMap", key, value)
				headersMap[key] = value
			}

			id := headersMap["x-request-id"]

			var protocol string
			if req.Attributes != nil {
				if epa, ok := req.Attributes["envoy.filters.http.ext_proc"]; ok {
					if rqa, ok := epa.Fields["request.protocol"]; ok {
						protocol = rqa.GetStringValue()
					} else {
						logrus.Warn("Cound not read request.protocol")
					}
				}
			}

			now := time.Now()
			seconds := now.Unix()
			nanos := now.Nanosecond()

			checkReq := &waf.CheckRequest{
				Id:               id,
				Host:             headersMap[":host"],
				Method:           headersMap[":method"],
				Path:             headersMap[":path"],
				Protocol:         protocol,
				Headers:          headersMap,
				TimestampSeconds: seconds,
				TimestampNanos:   int32(nanos),
			}

			var xForwardedFor string
			if len(md["x-forwarded-for"]) > 0 {
				xForwardedFor = md["x-forwarded-for"][0]
			}
			checkReq.SrcHost = xForwardedFor

			// This checks both headers and body (phas 1 and phase 2).
			// The body checks are useless for now as we don't have that information.
			// Future work will need to break up those 2 checks, but using the same transaction for the 2 phases.
			wafResp, err := s.wafServer.CheckWAF(checkReq)
			if err != nil {
				logrus.Errorf("Error checking WAF: %#v", err)
			}
			logrus.Debugf("WAF result (status: %d %s): %#v", wafResp.Status.Code, wafResp.Status.Message, wafResp)
			if wafResp.Status.Code == 0 {
				blockedByWAF = false
			} else {
				blockedByWAF = true
			}

			resp = &envoy_service_proc_v3.ProcessingResponse{
				Response: &envoy_service_proc_v3.ProcessingResponse_RequestHeaders{
					RequestHeaders: &envoy_service_proc_v3.HeadersResponse{
						Response: &envoy_service_proc_v3.CommonResponse{
							Status: envoy_service_proc_v3.CommonResponse_CONTINUE,
						},
					},
				},
			}

			logrus.Debugf("blockedByWAF is set to %b", blockedByWAF)

			if blockedByWAF {
				resp.Response = &envoy_service_proc_v3.ProcessingResponse_ImmediateResponse{
					ImmediateResponse: &envoy_service_proc_v3.ImmediateResponse{
						Status: &envoy_type_v3.HttpStatus{
							Code: envoy_type_v3.StatusCode_Forbidden,
						},
						Body: []byte(wafResp.Status.Message),
					},
				}
			}
		case *envoy_service_proc_v3.ProcessingRequest_RequestBody:
			resp = &envoy_service_proc_v3.ProcessingResponse{
				Response: &envoy_service_proc_v3.ProcessingResponse_RequestBody{
					RequestBody: &envoy_service_proc_v3.BodyResponse{
						Response: &envoy_service_proc_v3.CommonResponse{
							Status: envoy_service_proc_v3.CommonResponse_CONTINUE,
						},
					},
				},
			}
		case *envoy_service_proc_v3.ProcessingRequest_ResponseHeaders:
			resp = &envoy_service_proc_v3.ProcessingResponse{
				Response: &envoy_service_proc_v3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &envoy_service_proc_v3.HeadersResponse{
						Response: &envoy_service_proc_v3.CommonResponse{
							Status: envoy_service_proc_v3.CommonResponse_CONTINUE,
						},
					},
				},
			}
		default:
			logrus.Infof("Unknown Request type %v\n", v)
		}
		if err := srv.Send(resp); err != nil {
			logrus.Warnf("send error %v", err)
		}
	}
}
