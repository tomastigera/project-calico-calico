package waf

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/projectcalico/calico/app-policy/waf"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ExtProcServer struct {
	wafServer *waf.Server
}

func NewExtProcServer(wafRulesetRootDir string, directives []string, logger func(*proto.WAFEvent)) *ExtProcServer {
	var wafRulesetRootFS fs.FS

	if wafRulesetRootDir != "" {
		// When a ruleset root path is provided, we use it as a root
		// the fs used to configure WAF rules.
		// All path will be relative to rulesetRootDir.
		// This is the recommended option when specifying some ruleset(s).
		wafRulesetRootFS = os.DirFS(wafRulesetRootDir)
	} else {
		// Default for testing
		wafRulesetRootFS = nil // Uses default coraza config
	}

	events := waf.NewEventsPipeline(logger)

	wafServer, err := waf.New(wafRulesetRootFS, nil, directives, false, events)
	if err != nil {
		logrus.Panicf("cannot initialize WAF: %v", err)
	}

	return &ExtProcServer{wafServer: wafServer}
}

func (s *ExtProcServer) Process(srv envoy_service_proc_v3.ExternalProcessor_ProcessServer) error {
	ctx := srv.Context()
	logrus.Info("start Process()")

	md, _ := metadata.FromIncomingContext(ctx)
	logrus.WithField("md", md).Debug("gRPC context metadata")
	var xForwardedFor string
	if len(md["x-forwarded-for"]) > 0 {
		xForwardedFor = md["x-forwarded-for"][0]
	}

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

			logrus.WithField("headersMap", headersMap).Info("Parsed headers")

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

			logrus.WithField("blockedByWAF", blockedByWAF).Debug("Are we blocking?")

			if blockedByWAF {
				resp.Response = &envoy_service_proc_v3.ProcessingResponse_ImmediateResponse{
					ImmediateResponse: &envoy_service_proc_v3.ImmediateResponse{
						Status: &envoy_type_v3.HttpStatus{
							Code: envoy_type_v3.StatusCode_Forbidden,
						},
						Body: []byte(fmt.Sprintf("Sorry you've been WAF'ed!\r\n%v", wafResp.Status.Message)),
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
			logrus.Printf("Unknown Request type %v\n", v)
		}
		if err := srv.Send(resp); err != nil {
			logrus.Printf("send error %v", err)
		}
	}
}
