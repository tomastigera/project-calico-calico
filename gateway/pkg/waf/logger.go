package waf

import (
	"github.com/projectcalico/calico/felix/proto"
	"github.com/sirupsen/logrus"
)

func DebugLogger(wafEvent *proto.WAFEvent) {
	logrus.Warnf("New WAF event! Need to do something about that! %v", wafEvent)
}
