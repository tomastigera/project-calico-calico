package unlicensed

import (
	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/gateway/pkg/internal/utils"
)

type unlicensedRequestHandler struct {
}

type RequestHandler interface {
	// Process processes a single ProcessingRequest and returns a ProcessingResponse.
	Process(*envoy_service_proc_v3.ProcessingRequest) *envoy_service_proc_v3.ProcessingResponse
}

func NewUnlicensedRequestHandler() *unlicensedRequestHandler {
	return &unlicensedRequestHandler{}
}

// Process processes a single ProcessingRequest and returns a ProcessingResponse.
func (h *unlicensedRequestHandler) Process(req *envoy_service_proc_v3.ProcessingRequest) *envoy_service_proc_v3.ProcessingResponse {
	switch v := req.Request.(type) {
	case *envoy_service_proc_v3.ProcessingRequest_RequestHeaders:
		log.Tracef("--> Processing (unlicensed) request headers: %v", v)
		return utils.NewPhaseContinueResponse(utils.PHASE_REQUEST_HEADERS)
	case *envoy_service_proc_v3.ProcessingRequest_RequestBody:
		log.Tracef("--> Processing (unlicensed) request body: %v", v)
		return utils.NewPhaseContinueResponse(utils.PHASE_REQUEST_BODY)
	case *envoy_service_proc_v3.ProcessingRequest_ResponseHeaders:
		log.Tracef("--> Processing (unlicensed) response headers: %v", v)
		return utils.NewPhaseContinueResponse(utils.PHASE_RESPONSE_HEADERS)
	case *envoy_service_proc_v3.ProcessingRequest_ResponseBody:
		log.Tracef("--> Processing (unlicensed) response body: %v", v)
		return utils.NewPhaseContinueResponse(utils.PHASE_RESPONSE_BODY)
	default:
		log.Errorf("Unsupported request type: %T", v)
	}
	return &envoy_service_proc_v3.ProcessingResponse{}
}
