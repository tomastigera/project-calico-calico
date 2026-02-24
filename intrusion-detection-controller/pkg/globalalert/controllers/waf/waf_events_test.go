package waf

import (
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

var _ = Describe("WAF new event", func() {
	var (
		wafLog   v1.WAFLog
		wafCache *WAFLogsCache
		err      error
	)

	BeforeEach(func() {
		wafCache = NewWAFLogsCache(time.Minute)
		err = json.Unmarshal([]byte(rawLog), &wafLog)
		Expect(err).NotTo(HaveOccurred())

	})

	Context("NewWAFEvent", func() {
		It("create a new WAF event", func() {
			expected := v1.Event{
				Type:            query.WafEventType,
				Origin:          "Web Application Firewall",
				Time:            v1.NewEventTimestamp(wafLog.Timestamp.Unix()),
				Name:            "WAF Event",
				Description:     "Traffic inside your cluster triggered Web Application Firewall rules",
				Severity:        80,
				Host:            "lorcan-bz-wodc-kadm-node-1",
				Protocol:        "HTTP/1.1",
				SourceIP:        &wafLog.Source.IP,
				SourceName:      "-",
				SourceNamespace: "-",
				DestIP:          &wafLog.Destination.IP,
				DestName:        "nginx-s12c97822-jnd92n",
				DestNamespace:   "nginx",
				MitreIDs:        &[]string{"T1190"},
				Mitigations:     &[]string{"Review the source of this event - an attacker could be inside your cluster attempting to exploit your web application. Calico network policy can be used to block the connection if the activity is not expected"},
				AttackVector:    "Network",
				MitreTactic:     "Initial Access",
				Record:          wafLog,
			}
			generatedEvent := NewWafEvent(wafLog)
			expected.Time = generatedEvent.Time
			Expect(generatedEvent).To(Equal(expected))

		})
	})

	Context("Testing WAF Event Cache", func() {
		It("Testing WAF Event Cache Add Pass", func() {
			wafCache.Add(&wafLog)
			isPresent := wafCache.Contains(&wafLog)
			Expect(isPresent).To(BeTrue())
		})

		It("Test WAF Event Cache Add Fail", func() {
			isPresent := wafCache.Contains(&wafLog)
			Expect(isPresent).To(BeFalse())
		})

	})
})
