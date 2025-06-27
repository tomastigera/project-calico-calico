// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package flowlog

import (
	"fmt"
	"strings"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/rules"
)

const (
	FieldNotIncluded                 = "-"
	fieldNotIncludedForNumericFields = 0
	fieldAggregated                  = "*"

	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"

	ReporterSrc    ReporterType = "src"
	ReporterDst    ReporterType = "dst"
	ReporterFwd    ReporterType = "fwd"
	ReporterSrcFwd ReporterType = "src,fwd"
	ReporterDstFwd ReporterType = "dst,fwd"
)

func getActionAndReporterFromRuleID(r, hr *calc.RuleID) (a Action, flr ReporterType) {
	var (
		action    rules.RuleAction
		direction rules.RuleDir
		isForward bool
	)

	switch {
	case r != nil && hr != nil:
		if r.Action == rules.RuleActionDeny || hr.Action == rules.RuleActionDeny {
			// If either transit or non-transit action is a deny, then the flow is denied.
			action = rules.RuleActionDeny
		} else {
			// If the verdict is not a deny, then the final verdict is determined by the last
			// non-transit rule that ultimately applied the verdict.
			action = r.Action
		}
		direction = r.Direction
		isForward = true
	case r != nil:
		action = r.Action
		direction = r.Direction
	case hr != nil:
		action = hr.Action
		isForward = true
	}

	switch action {
	case rules.RuleActionDeny:
		a = ActionDeny
	case rules.RuleActionAllow:
		a = ActionAllow
	}

	switch direction {
	case rules.RuleDirIngress:
		if isForward {
			flr = ReporterDstFwd
		} else {
			flr = ReporterDst
		}
	case rules.RuleDirEgress:
		if isForward {
			flr = ReporterSrcFwd
		} else {
			flr = ReporterSrc
		}
	default:
		flr = ReporterFwd
	}

	return
}

func labelsToString(labels map[string]string) string {
	if labels == nil {
		return "-"
	}
	return fmt.Sprintf("[%v]", strings.Join(utils.FlattenLabels(labels), ","))
}

func stringToLabels(labelStr string) map[string]string {
	if labelStr == "-" {
		return nil
	}
	labels := strings.Split(labelStr[1:len(labelStr)-1], ",")
	return utils.UnflattenLabels(labels)
}

func getService(svc metric.ServiceInfo) FlowService {
	if svc.Name == "" {
		return FlowService{
			Namespace: FieldNotIncluded,
			Name:      FieldNotIncluded,
			PortName:  FieldNotIncluded,
			PortNum:   fieldNotIncludedForNumericFields,
		}
	} else if svc.Port == "" { // proxy.ServicePortName.Port refers to the PortName
		// A single port for a service may not have a name.
		return FlowService{
			Namespace: svc.Namespace,
			Name:      svc.Name,
			PortName:  FieldNotIncluded,
			PortNum:   svc.PortNum,
		}
	}
	return FlowService{
		Namespace: svc.Namespace,
		Name:      svc.Name,
		PortName:  svc.Port,
		PortNum:   svc.PortNum,
	}
}
