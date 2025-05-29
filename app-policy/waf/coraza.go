// Copyright (c) 2023 Tigera, Inc. All rights reserved.
// Package waf implements a coraza-based checker.CheckProvider server.
// In this case, this authorization server provides a WAF service for the external authz request.
//
// The WAF service is implemented as a checker.CheckProvider for the checker.Checker server.
// The checker.Checker server is a gRPC server that implements envoy ext_authz
package waf

import (
	"fmt"
	"io/fs"
	"net/http"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	coraza "github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyauthz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	mergefs "github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
	log "github.com/sirupsen/logrus"
	code "google.golang.org/genproto/googleapis/rpc/code"
	status "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
)

var (
	OK            = newResponseWithCode(code.Code_OK, "OK")
	DENY          = newResponseWithCode(code.Code_PERMISSION_DENIED, "Forbidden")
	INTERNAL      = newResponseWithCode(code.Code_INTERNAL, "Internal Server Error")
	defaultRootFS fs.FS
)

func init() {
	// Default convenient option that uses the coraza-ruleset (with relative paths)
	// and anything from the file system (with absolute paths).
	defaultRootFS = mergefs.Merge(
		// Add mergefs OSFS first to avoid "invalid argument" error from golang 1.23+.
		//
		// Since golang 1.23 io/fs.SubFS, the error returned from Sub() call is changed
		// to ErrInvalid [1] (from "invalid name"). This change escapes mergefs ReadFile
		// error suppression in [2] so that it causes Coraza WAF initialization [3] to fail.
		// Reordering mergefsio.OSFS to the first will use os.ReadFile [4] for on-disk
		// configurations. Once the on-disk config is read successfully, mergefs ReaFile
		// won't retry Coraza ReadFile [5] so that ErrInvalid is avoided. io/fs ValidPath
		// check won't allow leading slash [6] and this is where the error is from.
		//
		// [1] https://github.com/golang/go/commit/bf821f65cfd61dcc431922eea2cb97ce0825d60c
		// [2] https://github.com/jcchavezs/mergefs/blob/07f27d25676181074133e7573825402b88bf2f99/readfile.go#L23
		// [3] https://github.com/corazawaf/coraza/blob/34cdde87ae4d3754e8da080387e0511b779fc228/waf.go#L64
		// [4] https://github.com/jcchavezs/mergefs/blob/07f27d25676181074133e7573825402b88bf2f99/io/os.go#L20
		// [5] https://github.com/corazawaf/coraza-coreruleset/blob/b20e2628b747fb7368178092fa472f3a9dc76f43/coreruleset.go#L62
		// [6] https://github.com/golang/go/blob/2f507985dc24d198b763e5568ebe5c04d788894f/src/io/fs/fs.go#L47
		mergefsio.OSFS,
		coreruleset.FS,
	)
}

func newResponseWithCode(code code.Code, message string) *envoyauthz.CheckResponse {
	return &envoyauthz.CheckResponse{Status: &status.Status{Code: int32(code), Message: message}}
}

type eventCallbackFn func(*proto.WAFEvent)

var _ checker.CheckProvider = (*Server)(nil)

type Server struct {
	coraza.WAF
	evp            *WafEventsPipeline
	perHostEnabled bool
}

func New(rootFS fs.FS, files, directives []string, tproxyEnabled bool, evp *WafEventsPipeline, initializers ...func() error) (*Server, error) {
	for _, initFn := range initializers {
		if err := initFn(); err != nil {
			return nil, fmt.Errorf("failed to initialize WAF: %w", err)
		}
	}

	srv := &Server{
		evp:            evp,
		perHostEnabled: tproxyEnabled,
	}

	if rootFS == nil {
		rootFS = defaultRootFS
	}
	cfg := coraza.NewWAFConfig().
		WithRootFS(rootFS).
		WithErrorCallback(func(rule corazatypes.MatchedRule) {
			evp.ProcessErrorRule(rule)
		}).
		WithRequestBodyAccess()

	for _, f := range files {
		log.WithField("file", f).Debug("loading directives from file")
		cfg = cfg.WithDirectivesFromFile(f)
	}

	for _, d := range directives {
		log.WithField("directive", d).Debug("loading directive")
		cfg = cfg.WithDirectives(d)
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, err
	}
	srv.WAF = waf

	return srv, nil
}

func (w *Server) Name() string {
	return "coraza"
}

func (w *Server) EnabledForRequest(ps *policystore.PolicyStore, req *envoyauthz.CheckRequest) bool {
	sidecar := checker.GetSidecar(ps, req)
	return (sidecar == nil && w.perHostEnabled) || (sidecar != nil && sidecar.ApplicationLayer.Waf == "Enabled")
}

func (w *Server) Check(st *policystore.PolicyStore, checkReq *envoyauthz.CheckRequest) (*envoyauthz.CheckResponse, error) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{"attributes": checkReq.Attributes}).Debug("check request received")
	}

	attrs := checkReq.Attributes
	dstHost, dstPort, _ := peerToHostPort(attrs.Destination)
	srcHost, srcPort, _ := peerToHostPort(attrs.Source)
	if st != nil {
		src, dst, _ := checker.LookupEndpointKeysFromSrcDst(st, srcHost, dstHost)
		// this logic is only triggered if:
		// - dikastes is connected to policysync
		// - has source information, most likely running in daemonset mode
		// - has no destination information, most likely running in daemonset mode
		// in this case, we allow traffic to continue to its destination hop/next processing leg.
		if len(src) > 0 && len(dst) == 0 {
			log.Debugf("allowing traffic to continue to its destination hop/next processing leg. (req: %s)", checkReq.String())
			return OK, nil
		}
	}

	request := toCheckRequest(checkReq)
	request.DstPort = int32(dstPort)
	request.SrcPort = int32(srcPort)

	return w.CheckWAF(request)
}

func (w *Server) CheckWAF(req *CheckRequest) (*envoyauthz.CheckResponse, error) {
	tx := w.NewTransactionWithID(req.Id)
	//  process the http info for the events pipeline and close the
	//  transaction
	defer tx.Close()

	if tx.IsRuleEngineOff() {
		return OK, nil
	}

	defer w.evp.Process(req, tx)

	tx.ProcessConnection(req.SrcHost, int(req.SrcPort), req.DstHost, int(req.DstPort))
	tx.ProcessURI(req.Path, req.Method, req.Protocol)
	for k, v := range req.Headers {
		tx.AddRequestHeader(k, v)
	}
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		tx.SetServerName(req.Host)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return w.processInterruption(it)
	}

	if tx.IsRequestBodyAccessible() {
		s := strings.NewReader(req.Body)
		switch it, _, err := tx.ReadRequestBodyFrom(s); {
		case err != nil:
			return nil, err
		case it != nil:
		}
	}
	switch it, err := tx.ProcessRequestBody(); {
	case err != nil:
		return nil, err
	case it != nil:
		return w.processInterruption(it)
	}
	return OK, nil
}

func (w *Server) processInterruption(it *corazatypes.Interruption) (*envoyauthz.CheckResponse, error) {
	resp := &envoyauthz.CheckResponse{Status: &status.Status{Code: int32(code.Code_OK)}}

	switch it.Action {
	// We only handle disruptive actions here.
	// However, not all disruptive actions mean a change in response code. See below:
	// - drop Initiates an immediate close of the TCP connection by sending a FIN packet.
	// - deny Stops rule processing and intercepts transaction.
	// - block Performs the disruptive action defined by the previous SecDefaultAction.
	// - pause Pauses transaction processing for the specified number of milliseconds. We don't support this, yet.
	// - proxy Intercepts the current transaction by forwarding the request to another web server using the proxy backend.
	// 		The forwarding is carried out transparently to the HTTP client (i.e., there’s no external redirection taking place)
	// - redirect Intercepts transaction by issuing an external (client-visible) redirection to the given location
	//
	// for more info about actions: https://coraza.io/docs/seclang/actions/ and note the Action Group for each.
	case "allow":
		// default response code is OK, do nothing but return OK
	case "drop", "deny", "block":
		resp = newResponseWithCode(
			statusFromAction(it, code.Code_PERMISSION_DENIED),
			messageFromInterruption(it),
		)
	case "pause", "proxy", "redirect":
		log.Warnf("unsupported action (%s), proceeding with no-op", it.Action)
	default:
		// all other actions should be non-disruptive. Do nothing but return OK
	}

	return resp, nil
}

func messageFromInterruption(it *corazatypes.Interruption) string {
	return fmt.Sprintf("WAF rule %d interrupting request: %s (%d)", it.RuleID, it.Action, it.Status)
}

func statusFromAction(it *corazatypes.Interruption, fallbackValue code.Code) code.Code {
	if it.Status != 0 {
		return statusToCode(it.Status)
	}
	return fallbackValue
}

func statusToCode(s int) code.Code {
	switch s {
	case http.StatusOK:
		return code.Code_OK
	case http.StatusBadRequest:
		return code.Code_INVALID_ARGUMENT
	case http.StatusUnauthorized:
		return code.Code_UNAUTHENTICATED
	case http.StatusForbidden:
		return code.Code_PERMISSION_DENIED
	case http.StatusNotFound:
		return code.Code_NOT_FOUND
	case http.StatusConflict:
		return code.Code_ALREADY_EXISTS
	case http.StatusTooManyRequests:
		return code.Code_RESOURCE_EXHAUSTED
	case 499: // HTTP 499 Client Closed Request
		return code.Code_CANCELLED
	case http.StatusInternalServerError:
		return code.Code_INTERNAL
	case http.StatusNotImplemented:
		return code.Code_UNIMPLEMENTED
	case http.StatusBadGateway:
		return code.Code_UNAVAILABLE
	case http.StatusServiceUnavailable:
		return code.Code_UNAVAILABLE
	case http.StatusGatewayTimeout:
		return code.Code_DEADLINE_EXCEEDED
	}
	return code.Code_UNKNOWN
}

func peerToHostPort(peer *envoyauthz.AttributeContext_Peer) (host string, port uint32, ok bool) {
	switch v := peer.Address.Address.(type) {
	case *envoycore.Address_SocketAddress:
		host = v.SocketAddress.Address
		switch vv := v.SocketAddress.PortSpecifier.(type) {
		case *envoycore.SocketAddress_PortValue:
			port = vv.PortValue
			ok = true
		}
		return
	}
	return "127.0.0.1", 80, false
}
