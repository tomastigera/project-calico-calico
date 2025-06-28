package waf

import (
	"strconv"
	"sync"

	corazatypes "github.com/corazawaf/coraza/v3/types"
	envoyauthz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/projectcalico/calico/felix/proto"
)

type WafEventsPipeline struct {
	mu            sync.Mutex
	errorsByTx    map[string][]corazatypes.MatchedRule
	flushCallback eventCallbackFn
}

func NewEventsPipeline(cb eventCallbackFn) *WafEventsPipeline {
	return &WafEventsPipeline{
		errorsByTx:    map[string][]corazatypes.MatchedRule{},
		flushCallback: cb,
	}
}

func (p *WafEventsPipeline) ProcessErrorRule(rule corazatypes.MatchedRule) {
	txID := rule.TransactionID()

	p.mu.Lock()
	defer p.mu.Unlock()

	txErrs := p.errorsByTx[txID]
	txErrs = append(txErrs, rule)
	p.errorsByTx[txID] = txErrs
}

type CheckRequest struct {
	Id               string
	Host             string
	SrcHost          string
	SrcPort          int32
	DstHost          string
	DstPort          int32
	RouteName        string
	Method           string
	Path             string
	Protocol         string
	Headers          map[string]string
	Body             string
	TimestampSeconds int64
	TimestampNanos   int32
}

func toCheckRequest(checkReq *envoyauthz.CheckRequest) *CheckRequest {
	attr := checkReq.Attributes
	req := attr.Request
	http := req.Http

	return &CheckRequest{
		Id:               http.Id,
		Host:             http.Host,
		SrcHost:          attr.Source.Address.GetSocketAddress().Address,
		SrcPort:          int32(attr.Source.Address.GetSocketAddress().GetPortValue()),
		DstHost:          attr.Destination.Address.GetSocketAddress().Address,
		DstPort:          int32(attr.Destination.Address.GetSocketAddress().GetPortValue()),
		Method:           http.Method,
		Path:             http.Path,
		Protocol:         http.Protocol,
		Headers:          http.Headers,
		Body:             http.Body,
		TimestampSeconds: req.Time.Seconds,
		TimestampNanos:   req.Time.Nanos,
	}
}

func (p *WafEventsPipeline) ProcessProtoEvent(entry *proto.WAFEvent, tx corazatypes.Transaction) {
	txID := tx.ID()
	p.mu.Lock()
	matchedRules, ok := p.errorsByTx[txID]
	if !ok {
		p.mu.Unlock()
		return
	}
	delete(p.errorsByTx, txID)
	p.mu.Unlock()

	log.WithField("rules", matchedRules).Debug("Processing matched rules")

	for _, matchedRule := range matchedRules {
		rule := matchedRule.Rule()
		entry.Rules = append(entry.Rules, &proto.WAFRuleHit{
			Rule: &proto.WAFRule{
				Id:       strconv.Itoa(rule.ID()),
				Message:  matchedRule.Message(),
				Severity: rule.Severity().String(),
				File:     rule.File(),
				Line:     strconv.Itoa(rule.Line()),
			},
			Disruptive: matchedRule.Disruptive(),
		})
	}

	p.flushCallback(entry)
}

func (p *WafEventsPipeline) Process(req *CheckRequest, tx corazatypes.Transaction) {
	txID := tx.ID()

	p.mu.Lock()
	matchedRules, ok := p.errorsByTx[txID]
	if !ok {
		p.mu.Unlock()
		return
	}
	delete(p.errorsByTx, txID)
	p.mu.Unlock()

	log.WithField("rules", matchedRules).Debug("Processing matched rules")

	entry := &proto.WAFEvent{
		TxId:    txID,
		Host:    req.Host,
		SrcIp:   req.SrcHost,
		SrcPort: req.SrcPort,
		DstIp:   req.DstHost,
		DstPort: req.DstPort,
		Rules:   []*proto.WAFRuleHit{},
	}

	entry.Request = &proto.HTTPRequest{
		Method:  req.Method,
		Path:    req.Path,
		Version: req.Protocol,
		Headers: req.Headers,
	}
	entry.Timestamp = &timestamppb.Timestamp{
		Seconds: req.TimestampSeconds,
		Nanos:   req.TimestampNanos,
	}
	entry.Action = "pass"
	if in := tx.Interruption(); in != nil {
		entry.Action = in.Action
	}

	for _, matchedRule := range matchedRules {
		rule := matchedRule.Rule()
		entry.Rules = append(entry.Rules, &proto.WAFRuleHit{
			Rule: &proto.WAFRule{
				Id:       strconv.Itoa(rule.ID()),
				Message:  matchedRule.Message(),
				Severity: rule.Severity().String(),
				File:     rule.File(),
				Line:     strconv.Itoa(rule.Line()),
			},
			Disruptive: matchedRule.Disruptive(),
		})
	}

	p.flushCallback(entry)
}
