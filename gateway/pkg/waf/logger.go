package waf

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/file"
	"github.com/projectcalico/calico/felix/proto"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func DebugLogger(wafEvent *proto.WAFEvent) {
	logrus.Warnf("New WAF event! Need to do something about that! %v", wafEvent)
}

func NewFileLogger(directory string, filename string, aggregationPeriod time.Duration, mustKeepFields []string) (func(wafEvent *proto.WAFEvent), func(), error) {

	fileReporter := file.NewReporter(
		directory,
		filename,
		100,
		5,
	)
	err := fileReporter.Start()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start file reporter: %w", err)
	}

	aggController, err := NewAggregatorController(
		aggregationPeriod,
		mustKeepFields,
		func(logs []*v1.WAFLog) {
			err := fileReporter.Report(logs)
			if err != nil {
				logrus.Errorf("Failed to report WAF log: %v", err)
			}

		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create aggreagation controller: %w", err)
	}

	go aggController.Run()

	return func(wafEvent *proto.WAFEvent) {
		wafLog := ConvertWAFEventToWAFLog(wafEvent)
		aggController.AddLog(wafLog)
	}, aggController.Stop, nil
}

func ConvertWAFEventToWAFLog(r *proto.WAFEvent) *v1.WAFLog {
	wafLog := &v1.WAFLog{
		Timestamp: time.Unix(r.Timestamp.Seconds, int64(r.Timestamp.Nanos)).UTC(),
		Count:     1,
		Method:    r.Request.Method,
		Msg:       fmt.Sprintf("WAF detected %d violations [%s]", len(r.Rules), r.Action),
		Path:      r.Request.Path,
		Protocol:  r.Request.Version,
		RequestId: r.TxId,
		Source: &v1.WAFEndpoint{
			IP:      r.SrcIp,
			PortNum: r.SrcPort,
		},
	}
	for _, rule := range r.Rules {
		wafLog.Rules = append(wafLog.Rules, v1.WAFRuleHit{
			Message:    rule.Rule.Message,
			Disruptive: rule.Disruptive,
			Id:         rule.Rule.Id,
			Severity:   rule.Rule.Severity,
			File:       rule.Rule.File,
			Line:       rule.Rule.Line,
		})
	}
	return wafLog
}
