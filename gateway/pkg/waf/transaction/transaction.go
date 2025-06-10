package transaction

import (
	"strconv"

	"github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/projectcalico/calico/felix/proto"
)

type Transaction struct {
	tx corazatypes.Transaction

	ID string

	// connection details
	Host             string
	SrcHost, DstHost string
	SrcPort, DstPort int32
	// uri details
	Path, Method, Protocol string

	RequestHeaders, ResponseHeaders map[string]string

	// gateway/envoy-specific details
	RouteName string

	// timestamp details
	TimestampSeconds int64
	TimestampNanos   int32
}

type TransactionOption func(*Transaction)

func NewTransaction(wafInstance coraza.WAF, requestID string, opts ...TransactionOption) *Transaction {
	tw := &Transaction{}
	// handle default transaction ID
	var tx corazatypes.Transaction
	if requestID == "" {
		log.Warn("TransactionWrapper created without an ID, setting a default ID")
		tx = wafInstance.NewTransaction()
		tw.ID = tx.ID()
	} else {
		log.Tracef("Creating transaction with ID: %s", tw.ID)
		tx = wafInstance.NewTransactionWithID(tw.ID)
		tw.ID = requestID
	}
	tw.tx = tx

	for _, opt := range opts {
		opt(tw)
	}

	return tw
}

func (tw *Transaction) ToProtoWAFEvent() *proto.WAFEvent {
	if tw.tx == nil {
		log.Warn("called ToProtoWAFEvent on a nil transaction wrapper")
		return nil
	}

	entry := &proto.WAFEvent{
		TxId:    tw.ID,
		Host:    tw.Host,
		SrcIp:   tw.SrcHost,
		DstIp:   tw.DstHost,
		SrcPort: tw.SrcPort,
		DstPort: tw.DstPort,
		Rules:   []*proto.WAFRuleHit{},
		Request: &proto.HTTPRequest{
			Method:  tw.Method,
			Path:    tw.Path,
			Version: tw.Protocol,
			Headers: tw.RequestHeaders,
		},
		Timestamp: &timestamppb.Timestamp{
			Seconds: tw.TimestampSeconds,
			Nanos:   tw.TimestampNanos,
		},
	}

	entry.Action = "pass"
	if in := tw.tx.Interruption(); in != nil {
		entry.Action = in.Action
	}

	return entry
}

func WithHost(host string) TransactionOption {
	return func(tw *Transaction) {
		log.Trace("Setting server name to ", host)
		tw.tx.SetServerName(host)
		log.Trace("Adding Host header to transaction: ", host)
		tw.tx.AddRequestHeader("Host", host)
		tw.Host = host
	}
}
func WithConnectionDetails(srcHost, dstHost string, srcPort, dstPort int) TransactionOption {
	return func(tw *Transaction) {
		log.Tracef("Setting connection details: srcHost=%s, srcPort=%d, dstHost=%s, dstPort=%d", srcHost, srcPort, dstHost, dstPort)
		tw.tx.ProcessConnection(srcHost, srcPort, dstHost, dstPort)
		tw.SrcHost = srcHost
		tw.DstHost = dstHost
		tw.SrcPort = int32(srcPort)
		tw.DstPort = int32(dstPort)
	}
}

func WithURI(path, method, protocol string) TransactionOption {
	return func(tw *Transaction) {
		log.Tracef("Setting URI: path=%s, method=%s, protocol=%s", path, method, protocol)
		tw.tx.ProcessURI(path, method, protocol)
		tw.Path = path
		tw.Method = method
		tw.Protocol = protocol
	}
}

func WithHeaders(headersMap map[string]string) TransactionOption {
	return func(tw *Transaction) {
		for k, v := range headersMap {
			log.Tracef("Adding header to transaction: %s: %s", k, v)
			tw.tx.AddRequestHeader(k, v)
		}
		tw.RequestHeaders = headersMap
	}
}

func WithTimeStamp(seconds int64, nanos int32) TransactionOption {
	return func(tw *Transaction) {
		log.Tracef("Setting timestamp: seconds=%d, nanos=%d", seconds, nanos)
		tw.TimestampSeconds = seconds
		tw.TimestampNanos = nanos
	}
}

// ProcessRequestHeaders processes the request headers. (PHASE 1)
func (tw *Transaction) ProcessRequestHeaders() (it *corazatypes.Interruption, status envoy_type_v3.StatusCode, msg string) {
	if tw.tx == nil {
		log.Warn("ProcessRequestHeaders called on a nil transaction wrapper. Doing nothing.")
		return
	}

	if it := tw.tx.ProcessRequestHeaders(); it != nil {
		// If there is an interruption, we return it.
		status, msg = codeAndMessageFromInterruption(it)
		log.Tracef("Transaction %s interrupted with action: %s, status: %d, message: %s", tw.ID, it.Action, status, msg)
		return it, status, msg
	}

	// If there is no interruption, we return nil, blank status, and empty message.
	log.Tracef("Transaction %s processed REQUEST HEADERS without interruption", tw.ID)
	return
}

// ProcessResponseHeaders processes the response headers. (PHASE 3)
func (tw *Transaction) ProcessResponseHeaders(responseHeadersMap map[string]string) (it *corazatypes.Interruption, status envoy_type_v3.StatusCode, msg string) {
	if tw.tx == nil {
		return
	}
	tw.ResponseHeaders = responseHeadersMap

	respStatus := 200
	if v, ok := responseHeadersMap["status"]; ok {
		if s, err := strconv.Atoi(v); err == nil {
			respStatus = s
		}
	}

	protocol := "HTTP/1.1"
	if v, ok := responseHeadersMap["protocol"]; ok {
		protocol = v
	}

	// Add response headers to the transaction.
	for k, v := range responseHeadersMap {
		tw.tx.AddResponseHeader(k, v)
	}

	// Process the response headers and return any interruption.
	if it := tw.tx.ProcessResponseHeaders(respStatus, protocol); it != nil {
		status, msg = codeAndMessageFromInterruption(it)
		return it, status, msg
	}

	return
}

// OnResponseBodyChunk processes a chunk of the response body. (PHASE 2)
func (tw *Transaction) OnRequestBodyChunk(requestBodyChunk []byte, endOfStream bool) (it *corazatypes.Interruption, written int, err error, status envoy_type_v3.StatusCode, msg string) {
	if tw.tx == nil || !tw.tx.IsRequestBodyAccessible() {
		return
	}

	// Read the request body from the provided reader.
	it, written, err = tw.tx.WriteRequestBody(requestBodyChunk)
	if err != nil {
		log.Errorf("Error writing request body: %v", err)
		return nil, 0, err, envoy_type_v3.StatusCode_InternalServerError, "Error writing request body"
	}
	if endOfStream {
		// interruptions are usually returned right before the end of the stream in a complete stream.
		// if the stream is ended abrupty, we can still attempt to process the request body.
		//
		// when we get to here there's no more data to read, so we can process the request body.
		// If this is the end of the stream, process the request body.
		it, err := tw.tx.ProcessRequestBody()
		switch {
		case it != nil:
			status, msg = codeAndMessageFromInterruption(it)
			return it, 0, nil, status, msg
		case err != nil:
			log.Errorf("Error processing request body: %v", err)
			return nil, 0, err, envoy_type_v3.StatusCode_InternalServerError, "Error processing request body"
		}
	}
	return
}

// OnResponseBodyChunk processes a chunk of the response body. (PHASE 4)
func (tw *Transaction) OnResponseBodyChunk(responseBodyChunk []byte, endOfStream bool) (it *corazatypes.Interruption, written int, err error, status envoy_type_v3.StatusCode, msg string) {
	if tw.tx == nil {
		log.Warn("OnResponseBodyChunk called on a nil transaction wrapper. Doing nothing.")
		return
	}

	if !tw.tx.IsResponseBodyAccessible() ||
		!tw.tx.IsResponseBodyProcessable() {
		// If the response body is not accessible or processable, we cannot process it.
		log.Warn("Response body is not accessible or processable. Skipping response body processing.")
		return
	}

	// Write the response body to the transaction.
	it, written, err = tw.tx.WriteResponseBody(responseBodyChunk)
	if err != nil {
		log.Errorf("Error writing response body: %v", err)
		return nil, 0, err, envoy_type_v3.StatusCode_InternalServerError, "Error writing response body"
	}

	if endOfStream {
		it, err := tw.tx.ProcessResponseBody()
		switch {
		case it != nil:
			status, msg = codeAndMessageFromInterruption(it)
			log.Tracef("Transaction %s processed RESPONSE BODY with interruption: %s, status: %d, message: %s", tw.ID, it.Action, status, msg)
			return it, 0, nil, status, msg
		case err != nil:
			log.Errorf("Error processing response body: %v", err)
			return nil, 0, err, envoy_type_v3.StatusCode_InternalServerError, "Error processing response body"
		}
	}
	return
}

func (tw *Transaction) Close() {
	if tw.tx == nil {
		return
	}

	// Close the transaction to finalize it.
	tw.tx.Close()
}

func (tw *Transaction) ProcessLogging() {
	if tw.tx == nil {
		return
	}

	// Process the logging for the transaction.
	tw.tx.ProcessLogging()
}

func (tw *Transaction) GetTransaction() corazatypes.Transaction {
	return tw.tx
}
