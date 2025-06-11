package transaction

import (
	"errors"
	"time"

	"github.com/corazawaf/coraza/v3"
	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/gateway/pkg/internal/utils"
)

type requestHandler struct {
	// instance is the WAF instance to use for this transaction
	instance coraza.WAF
	// transaction is the transaction to handle
	transaction   *Transaction
	xForwardedFor []string

	eventCallbacks []func(*proto.WAFEvent)
}

type RequestHandler interface {
	// Process processes a single ProcessingRequest and returns a ProcessingResponse.
	Process(*envoy_service_proc_v3.ProcessingRequest) *envoy_service_proc_v3.ProcessingResponse
}

func NewRequestHandler(instance coraza.WAF, xForwardedFor []string, eventCallbacks []func(*proto.WAFEvent)) (*requestHandler, error) {
	if instance == nil {
		return nil, errors.New("waf instance cannot be nil")
	}
	if len(xForwardedFor) == 0 {
		return nil, errors.New("x-forwarded-for data cannot be empty")
	}

	return &requestHandler{
		instance:       instance,
		xForwardedFor:  xForwardedFor,
		eventCallbacks: eventCallbacks,
	}, nil
}

// Process processes a single ProcessingRequest and returns a ProcessingResponse.
func (h *requestHandler) Process(req *envoy_service_proc_v3.ProcessingRequest) *envoy_service_proc_v3.ProcessingResponse {
	switch v := req.Request.(type) {
	case *envoy_service_proc_v3.ProcessingRequest_RequestHeaders:
		log.Tracef("--> Processing request headers: %v", v)
		return h.handleRequestHeaders(v)
	case *envoy_service_proc_v3.ProcessingRequest_RequestBody:
		log.Tracef("--> Processing request body: %v", v)
		return h.handleRequestBody(v)
	case *envoy_service_proc_v3.ProcessingRequest_ResponseHeaders:
		log.Tracef("--> Processing response headers: %v", v)
		return h.handleResponseHeaders(v)
	case *envoy_service_proc_v3.ProcessingRequest_ResponseBody:
		log.Tracef("--> Processing response body: %v", v)
		return h.handleResponseBody(v)
	default:
		log.Errorf("Unsupported request type: %T", v)
	}
	return &envoy_service_proc_v3.ProcessingResponse{}
}

// ProcessAll processes multiple requests in sequence, returning the first non-continue response.
// If all requests return continue responses, it returns a blank ProcessingResponse.
// This is useful for handling multiple phases of a transaction in a single call.
// - It is expected that the requests are in the order of their phases (e.g., request headers, request body, etc.).
// - If any request returns a non-continue response, it will stop processing further requests and return that response.
// - If all requests return continue responses, it returns a blank ProcessingResponse.
// NB: currently only used in tests. This immitates the behavior of the envoy ext_proc filter at the very basic level.
func (h *requestHandler) ProcessAll(reqs ...*envoy_service_proc_v3.ProcessingRequest) *envoy_service_proc_v3.ProcessingResponse {
	for _, req := range reqs {
		if req == nil {
			log.Warn("Received nil ProcessingRequest, skipping")
			continue
		}
		res := h.Process(req)
		log.Debugf("Received response: %T", res.Response)
		if !utils.IsContinueResponse(res) {
			log.Debugf("Received non-continue response: '%s'", res.String())
			return res
		}
		log.Debugf("Received continue response, continuing to next request")
	}
	// If all requests were handled and returned continue responses
	// we return a blank ProcessingResponse
	return &envoy_service_proc_v3.ProcessingResponse{}
}

func (h *requestHandler) handleRequestHeaders(reqHeaders *envoy_service_proc_v3.ProcessingRequest_RequestHeaders) (res *envoy_service_proc_v3.ProcessingResponse) {
	res = utils.NewPhaseContinueResponse(utils.PHASE_REQUEST_HEADERS)

	headersList := reqHeaders.RequestHeaders.Headers.GetHeaders()
	headersMap := make(map[string]string)
	for _, headerValue := range headersList {
		key := headerValue.GetKey()
		value := string(headerValue.GetRawValue())
		log.Debugf("Adding %s=%s to headersMap", key, value)
		headersMap[key] = value
	}

	id := headersMap["x-request-id"]
	now := time.Now()
	seconds := now.Unix()
	nanos := now.Nanosecond()
	var lastProxyHop string
	if len(h.xForwardedFor) > 0 {
		lastProxyHop = h.xForwardedFor[0]
	} else {
		// Fallback value if x-forwarded-for is empty
		// considering this is a local request, we can use localhost
		// -- the worst case scenario is that ip-based rules like geoip rules, known threat ips rules will not work
		lastProxyHop = "127.0.0.1"
	}

	// request headers phase is where we always create a new transaction
	// this phase is never called after the transaction has been created
	// or after any other phases
	h.transaction = NewTransaction(
		h.instance,
		id,
		// envoy uses :authority for the host header
		WithHost(headersMap[":authority"]),
		WithConnectionDetails(
			lastProxyHop, // src host
			"127.0.0.1",  // dst host
			55550,        // dummy value for src port
			80,           // dummy value for dst port
		),
		WithURI(
			headersMap[":path"],   // envoy uses :path for the request path
			headersMap[":method"], // envoy uses :method for the request method
			"HTTP/1.1",            // default protocol, can be changed later
		),
		WithHeaders(headersMap),
		WithTimeStamp(seconds, int32(nanos)),
	)

	it, status, msg := h.transaction.ProcessRequestHeaders()
	if it != nil {
		defer h.currentTransactionEmitToCallbacks()
		res.Response = utils.NewImmediateResponse(
			status,
			[]byte(msg),
		)
	}
	return
}

func (h *requestHandler) handleRequestBody(reqBody *envoy_service_proc_v3.ProcessingRequest_RequestBody) (res *envoy_service_proc_v3.ProcessingResponse) {
	res = utils.NewPhaseContinueResponse(utils.PHASE_REQUEST_BODY)

	if h.transaction == nil {
		log.Warn("handleRequestBody called on a nil transaction wrapper. Doing nothing.")
		return
	}

	chunk := reqBody.RequestBody.GetBody()
	endOfStream := reqBody.RequestBody.GetEndOfStream()

	it, written, err, status, msg := h.transaction.OnRequestBodyChunk(chunk, endOfStream)
	log.WithFields(log.Fields{
		"chunk":         chunk,
		"written_bytes": written,
		"end_of_stream": endOfStream,
		"status":        status,
		"message":       msg,
	}).Debug("request body chunk processed")

	switch {
	case it != nil:
		defer h.currentTransactionEmitToCallbacks()
		res.Response = utils.NewImmediateResponse(
			status,
			[]byte(msg),
		)

	case err != nil:
		log.Errorf("Error processing request body chunk: %v", err)
		res.Response = utils.NewImmediateResponse(
			envoy_type_v3.StatusCode_InternalServerError,
			[]byte("internal error processing request body chunk"),
		)
	}

	return
}

func (h *requestHandler) handleResponseHeaders(resHeaders *envoy_service_proc_v3.ProcessingRequest_ResponseHeaders) (res *envoy_service_proc_v3.ProcessingResponse) {
	log.Debugf("handleResponseHeaders called with: %v", resHeaders)
	res = utils.NewPhaseContinueResponse(utils.PHASE_RESPONSE_HEADERS)

	if h.transaction == nil {
		log.Warn("handleResponseHeaders called on a nil transaction wrapper. Doing nothing.")
		return
	}

	headersList := resHeaders.ResponseHeaders.Headers.GetHeaders()
	headersMap := make(map[string]string)
	for _, headerValue := range headersList {
		key := headerValue.GetKey()
		value := string(headerValue.GetRawValue())
		log.Debugf("Adding %s=%s to response headers map", key, value)
		headersMap[key] = value
	}

	it, status, msg := h.transaction.ProcessResponseHeaders(headersMap)
	if it != nil {
		defer h.currentTransactionEmitToCallbacks()
		res.Response = utils.NewImmediateResponse(
			status,
			[]byte(msg),
		)
	}

	return
}

func (h *requestHandler) handleResponseBody(resBody *envoy_service_proc_v3.ProcessingRequest_ResponseBody) (res *envoy_service_proc_v3.ProcessingResponse) {
	log.Debugf("handleResponseBody called with: %v", resBody)
	res = utils.NewPhaseContinueResponse(utils.PHASE_RESPONSE_BODY)

	if h.transaction == nil {
		log.Warn("handleResponseBody called on a nil transaction wrapper. Doing nothing.")
		return
	}

	chunk := resBody.ResponseBody.GetBody()
	endOfStream := resBody.ResponseBody.GetEndOfStream()

	it, written, err, status, msg := h.transaction.OnResponseBodyChunk(chunk, endOfStream)
	log.WithFields(log.Fields{
		"chunk":         chunk,
		"written_bytes": written,
		"end_of_stream": endOfStream,
		"status":        status,
		"message":       msg,
	}).Debug("response body chunk processed")

	switch {
	case it != nil:
		defer h.currentTransactionEmitToCallbacks()
		res.Response = utils.NewImmediateResponse(
			status,
			[]byte(msg),
		)

	case err != nil:
		log.Errorf("Error processing response body chunk: %v", err)
		res.Response = utils.NewImmediateResponse(
			envoy_type_v3.StatusCode_InternalServerError,
			[]byte("internal error processing response body chunk"),
		)
	}

	return
}

func (h *requestHandler) currentTransactionEmitToCallbacks() {
	if h.transaction == nil {
		log.Warn("currentTransactionEmitToCallbacks called on a nil transaction wrapper. Doing nothing.")
		return
	}
	event := h.transaction.ToProtoWAFEvent()
	h.emitEvent(event)
}

func (h *requestHandler) emitEvent(event *proto.WAFEvent) {
	for _, cb := range h.eventCallbacks {
		cb(event)
	}
}
