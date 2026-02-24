// Copyright 2019 Tigera Inc. All rights reserved.

package events

import (
	"errors"
	"testing"

	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	geodb "github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/geodb"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/util"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func TestSuspiciousIP_Success(t *testing.T) {
	g := NewGomegaWithT(t)

	testFeed := &apiv3.GlobalThreatFeed{}
	testFeed.Name = "test"

	logs := []v1.FlowLog{
		{
			SourceIP:      util.Sptr("1.2.3.4"),
			SourcePort:    util.I64ptr(333),
			SourceName:    "source",
			DestIP:        util.Sptr("2.3.4.5"),
			DestPort:      util.I64ptr(333),
			DestNamespace: "default",
			DestName:      "dest",
			DestType:      "wep",
		},
		{
			SourceIP:        util.Sptr("5.6.7.8"),
			SourcePort:      util.I64ptr(333),
			SourceName:      "source",
			SourceNamespace: "default",
			SourceType:      "wep",
			DestIP:          util.Sptr("2.3.4.5"),
			DestPort:        util.I64ptr(333),
			DestName:        "dest",
		},
	}
	i := &storage.MockIterator[v1.FlowLog]{
		ErrorIndex: -1,
		Values:     logs,
		Keys:       []storage.QueryKey{storage.QueryKeyFlowLogSourceIP, storage.QueryKeyFlowLogDestIP},
	}
	q := &storage.MockSetQuerier{IteratorFlow: i}
	uut := NewSuspiciousIP(q)

	expected := []v1.Event{
		{
			ID:            "test_0__1.2.3.4_333_2.3.4.5_333",
			Time:          v1.NewEventTimestamp(0),
			Description:   "suspicious IP 1.2.3.4, listed in Global Threat Feed test, connected to default/dest",
			Type:          SuspiciousFlow,
			Severity:      Severity,
			Origin:        "Suspicious Flow",
			SourceIP:      util.Sptr("1.2.3.4"),
			SourceName:    "source",
			DestIP:        util.Sptr("2.3.4.5"),
			DestName:      "dest",
			DestNamespace: "default",
			Record: v1.SuspiciousIPEventRecord{
				Feeds: []string{"test"},
			},
			GeoInfo: v1.IPGeoInfo{
				CityName:    "Naucelles",
				CountryName: "France",
				ISO:         "FR",
				ASN:         "3215",
			},
			DestPort:     util.I64ptr(333),
			SourcePort:   util.I64ptr(333),
			Name:         "Suspicious Flow",
			AttackVector: "Network",
			MitreIDs:     &[]string{"T1041"},
			Mitigations:  &[]string{"Create a global network policy to prevent traffic from this IP address"},
			MitreTactic:  "Exfiltration",
		},
		{
			ID:              "test_0__5.6.7.8_333_2.3.4.5_333",
			Time:            v1.NewEventTimestamp(0),
			Description:     "pod default/source connected to suspicious IP 2.3.4.5 which is listed in Global Threat Feed test",
			Type:            SuspiciousFlow,
			Severity:        Severity,
			Origin:          "Suspicious Flow",
			SourceIP:        util.Sptr("5.6.7.8"),
			SourceName:      "source",
			SourceNamespace: "default",
			SourcePort:      util.I64ptr(333),
			DestIP:          util.Sptr("2.3.4.5"),
			DestPort:        util.I64ptr(333),
			DestName:        "dest",
			Record: v1.SuspiciousIPEventRecord{
				Feeds: []string{"test"},
			},
			GeoInfo: v1.IPGeoInfo{
				CityName:    "Naucelles",
				CountryName: "France",
				ISO:         "FR",
				ASN:         "3215",
			},
			Name:         "Suspicious Flow",
			AttackVector: "Network",
			MitreIDs:     &[]string{"T1041"},
			Mitigations:  &[]string{"Create a global network policy to prevent traffic from this IP address"},
			MitreTactic:  "Exfiltration",
		},
	}

	ctx := t.Context()

	results, _, _, err := uut.QuerySet(ctx, &geodb.MockGeoDB{}, testFeed)
	g.Expect(err).ToNot(HaveOccurred())
	// Clearing event times as we can't accurately test it
	for i, result := range results {
		result.Time = v1.NewEventTimestamp(0)
		results[i] = result
	}
	g.Expect(results).To(Equal(expected))
}

func TestSuspiciousIP_IterationFails(t *testing.T) {
	g := NewGomegaWithT(t)

	logs := []v1.FlowLog{
		{
			SourceIP:   util.Sptr("1.2.3.4"),
			SourceName: "source",
			DestIP:     util.Sptr("2.3.4.5"),
			DestName:   "dest",
		},
		{
			SourceIP:   util.Sptr("5.6.7.8"),
			SourceName: "source",
			DestIP:     util.Sptr("2.3.4.5"),
			DestName:   "dest",
		},
	}
	i := &storage.MockIterator[v1.FlowLog]{
		Error:      errors.New("test"),
		ErrorIndex: 1,
		Values:     logs,
		Keys:       []storage.QueryKey{storage.QueryKeyFlowLogSourceIP, storage.QueryKeyFlowLogDestIP},
	}
	q := &storage.MockSetQuerier{IteratorFlow: i}
	uut := NewSuspiciousIP(q)

	ctx := t.Context()

	testFeed := &apiv3.GlobalThreatFeed{}
	testFeed.Name = "test"
	_, _, _, err := uut.QuerySet(ctx, &geodb.MockGeoDB{}, testFeed)
	g.Expect(err).To(Equal(errors.New("test")))
}

func TestSuspiciousIP_QueryFails(t *testing.T) {
	g := NewGomegaWithT(t)

	q := &storage.MockSetQuerier{IteratorDNS: nil, QueryError: errors.New("query failed")}
	uut := NewSuspiciousIP(q)

	ctx := t.Context()

	testFeed := &apiv3.GlobalThreatFeed{}
	testFeed.Name = "test"
	_, _, _, err := uut.QuerySet(ctx, &geodb.MockGeoDB{}, testFeed)
	g.Expect(err).To(Equal(errors.New("query failed")))
}

func TestSuspiciousDomain_Success(t *testing.T) {
	g := NewGomegaWithT(t)

	logs := []v1.DNSLog{
		{
			ID:    "id1",
			QName: "xx.yy.zzz",
		},
		{
			ID:    "id2",
			QName: "qq.rr.sss",
		},
		{
			ID:    "id1",
			QName: "aa.bb.ccc",
		},
	}
	i := &storage.MockIterator[v1.DNSLog]{
		ErrorIndex: -1,
		Values:     logs,
		Keys:       []storage.QueryKey{storage.QueryKeyDNSLogQName, storage.QueryKeyDNSLogQName, storage.QueryKeyDNSLogQName},
	}
	domains := storage.DomainNameSetSpec{
		"xx.yy.zzz",
		"qq.rr.sss",
		"aa.bb.ccc",
	}
	q := &storage.MockSetQuerier{IteratorDNS: i, Set: domains}
	uut := NewSuspiciousDomainNameSet(q)

	ctx := t.Context()

	testFeed := &apiv3.GlobalThreatFeed{}
	testFeed.Name = "test"
	results, _, _, err := uut.QuerySet(ctx, &geodb.MockGeoDB{}, testFeed)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(results).To(HaveLen(2))
	rec1, ok := results[0].Record.(v1.SuspiciousDomainEventRecord)
	g.Expect(ok).Should(BeTrue())
	rec2, ok := results[1].Record.(v1.SuspiciousDomainEventRecord)
	g.Expect(ok).Should(BeTrue())
	g.Expect(rec1.SuspiciousDomains).To(Equal([]string{"xx.yy.zzz"}))
	g.Expect(rec2.SuspiciousDomains).To(Equal([]string{"qq.rr.sss"}))
}

func TestSuspiciousDomain_IterationFails(t *testing.T) {
	g := NewGomegaWithT(t)

	logs := []v1.DNSLog{
		{
			ID:    "id1",
			QName: "xx.yy.zzz",
		},
	}
	i := &storage.MockIterator[v1.DNSLog]{
		Error:      errors.New("iteration failed"),
		ErrorIndex: 0,
		Values:     logs,
		Keys:       []storage.QueryKey{storage.QueryKeyDNSLogQName},
	}
	domains := storage.DomainNameSetSpec{
		"xx.yy.zzz",
		"qq.rr.sss",
		"aa.bb.ccc",
	}
	q := &storage.MockSetQuerier{IteratorDNS: i, Set: domains}
	uut := NewSuspiciousDomainNameSet(q)

	ctx := t.Context()

	testFeed := &apiv3.GlobalThreatFeed{}
	testFeed.Name = "test"
	results, _, _, err := uut.QuerySet(ctx, &geodb.MockGeoDB{}, testFeed)
	g.Expect(err).To(Equal(errors.New("iteration failed")))
	g.Expect(results).To(HaveLen(0))
}

func TestSuspiciousDomain_GetFails(t *testing.T) {
	g := NewGomegaWithT(t)

	q := &storage.MockSetQuerier{GetError: errors.New("get failed")}
	uut := NewSuspiciousDomainNameSet(q)

	ctx := t.Context()

	testFeed := &apiv3.GlobalThreatFeed{}
	testFeed.Name = "test"
	results, _, _, err := uut.QuerySet(ctx, &geodb.MockGeoDB{}, testFeed)
	g.Expect(err).To(Equal(errors.New("get failed")))
	g.Expect(results).To(HaveLen(0))
}

func TestSuspiciousDomain_QueryFails(t *testing.T) {
	g := NewGomegaWithT(t)

	domains := storage.DomainNameSetSpec{
		"xx.yy.zzz",
		"qq.rr.sss",
		"aa.bb.ccc",
	}
	q := &storage.MockSetQuerier{Set: domains, QueryError: errors.New("query failed")}
	uut := NewSuspiciousDomainNameSet(q)

	ctx := t.Context()

	testFeed := &apiv3.GlobalThreatFeed{}
	testFeed.Name = "test"
	results, _, _, err := uut.QuerySet(ctx, &geodb.MockGeoDB{}, testFeed)
	g.Expect(err).To(Equal(errors.New("query failed")))
	g.Expect(results).To(HaveLen(0))
}
