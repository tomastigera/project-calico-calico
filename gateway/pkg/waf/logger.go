package waf

import (
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
)

func DebugLogger(wafEvent *proto.WAFEvent) {
	logrus.Warnf("New WAF event! Need to do something about that! %v", wafEvent)
}
