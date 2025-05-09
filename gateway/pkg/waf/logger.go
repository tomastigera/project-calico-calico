package waf

import (
	"github.com/projectcalico/calico/felix/proto"
	"github.com/sirupsen/logrus"
)

func DebugLogger(wafEvent *proto.WAFEvent) {
	logrus.Info("New WAF event!")
	logrus.Println("Got a new WAF event. Need to do something about that! %v", wafEvent)
}
