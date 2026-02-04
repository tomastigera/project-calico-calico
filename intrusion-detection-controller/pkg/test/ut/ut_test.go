// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//

package ut

import (
	"context"
	"fmt"
	"time"

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/events"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
	v1scheme "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

var _ = Describe("DomainName Thread Feeds UT", func() {
	var uut *storage.Service
	var lsc lsclient.MockClient
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()

		lsc = lsclient.NewMockClient("")

		// mock controller runtime client.
		scheme := scheme.Scheme
		err := v1scheme.AddCalicoResourcesToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

		uut = storage.NewService(lsc, fakeClient, "cluster", time.Duration(1))
		uut.Run(ctx)
	})

	AfterEach(func() {
		uut.Close()
	})

	Context("Domain name set", func() {
		It("Get existing domain name set", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			input := storage.DomainNameSetSpec{"xx.yy.zzz"}
			lsc.SetResults(rest.MockResult{
				Body: v1.BulkResponse{
					Total:     1,
					Succeeded: 1,
				},
			})
			err := uut.PutDomainNameSet(ctx, "test", input)
			Expect(err).ToNot(HaveOccurred())

			lsc.SetResults(rest.MockResult{
				Body: v1.List[v1.DomainNameSetThreatFeed]{
					TotalHits: 1,
					Items: []v1.DomainNameSetThreatFeed{
						{
							ID: "test",
							Data: &v1.DomainNameSetThreatFeedData{
								CreatedAt: time.Now().UTC(),
								Domains:   []string{"xx.yy.zzz"},
							},
						},
					},
				},
			})
			actual, err := uut.GetDomainNameSet(ctx, "test")
			Expect(err).ToNot(HaveOccurred())
			Expect(actual).To(Equal(input))

			lsc.SetResults(rest.MockResult{
				Body: v1.List[v1.DomainNameSetThreatFeed]{
					TotalHits: 1,
					Items: []v1.DomainNameSetThreatFeed{
						{
							ID: "test",
							Data: &v1.DomainNameSetThreatFeedData{
								CreatedAt: time.Now().UTC(),
								Domains:   []string{"xx.yy.zzz"},
							},
						},
					},
				},
			})
			m, err := uut.GetDomainNameSetModified(ctx, "test")
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(BeTemporally("<", time.Now()))
			Expect(m).To(BeTemporally(">", time.Now().Add(-5*time.Second)), "modified in the last 5 seconds")
		})

		It("Get non-existing domain set", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			linseedError := fmt.Errorf("linseed error")
			lsc.SetResults(rest.MockResult{
				Err: linseedError,
			},
			)
			_, err := uut.GetDomainNameSet(ctx, "test")
			Expect(err).To(Equal(linseedError))
		})

		It("Query domain name set", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			logs := []v1.DNSLog{
				{
					StartTime:       time.Unix(123, 0),
					EndTime:         time.Unix(456, 0),
					Count:           1,
					ClientName:      "client",
					ClientNamespace: "test",
					QClass:          v1.DNSClass(layers.DNSClassIN),
					QType:           v1.DNSType(layers.DNSTypeA),
					QName:           "xx.yy.zzz",
					RCode:           v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
					RRSets: v1.DNSRRSets{
						{
							Name:  "xx.yy.zzz",
							Class: v1.DNSClass(layers.DNSClassIN),
							Type:  v1.DNSType(layers.DNSTypeA),
						}: v1.DNSRDatas{{Raw: []byte("1.2.3.4")}},
					},
				},
				{
					StartTime:       time.Unix(789, 0),
					EndTime:         time.Unix(101112, 0),
					Count:           1,
					ClientName:      "client",
					ClientNamespace: "test",
					QClass:          v1.DNSClass(layers.DNSClassIN),
					QType:           v1.DNSType(layers.DNSTypeA),
					QName:           "aa.bb.ccc",
					RCode:           v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
					RRSets: v1.DNSRRSets{
						{
							Name:  "aa.bb.ccc",
							Class: v1.DNSClass(layers.DNSClassIN),
							Type:  v1.DNSType(layers.DNSTypeCNAME),
						}: v1.DNSRDatas{
							{
								Raw: []byte("dd.ee.fff"),
							},
						},
						{
							Name:  "dd.ee.fff",
							Class: v1.DNSClass(layers.DNSClassIN),
							Type:  v1.DNSType(layers.DNSTypeA),
						}: v1.DNSRDatas{
							{
								Raw: []byte("5.6.7.8"),
							},
						},
					},
				},
				{
					StartTime:       time.Unix(789, 0),
					EndTime:         time.Unix(101112, 0),
					Count:           1,
					ClientName:      "client",
					ClientNamespace: "test",
					QClass:          v1.DNSClass(layers.DNSClassIN),
					QType:           v1.DNSType(layers.DNSTypeCNAME),
					QName:           "gg.hh.iii",
					RCode:           v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
					RRSets: v1.DNSRRSets{
						{
							Name:  "gg.hh.iii",
							Class: v1.DNSClass(layers.DNSClassIN),
							Type:  v1.DNSType(layers.DNSTypeCNAME),
						}: v1.DNSRDatas{
							{
								Raw: []byte("jj.kk.lll"),
							},
						},
					},
				},
			}

			lsc.SetResults([]rest.MockResult{
				{
					// 0 -> matching xx.yy.zzz as qname
					Body: v1.List[v1.DNSLog]{
						Items: []v1.DNSLog{logs[0]},
					},
				},
				{
					// 0 -> matching xx.yy.zzz as rrset name
					// 1 -> matching dd.ee.fff as rrset name
					Body: v1.List[v1.DNSLog]{
						Items: []v1.DNSLog{logs[0], logs[1]},
					},
				},
				{
					// 1 -> matching dd.ee.fff as rrset data
					// 2 -> matching jj.kk.lll as rrset data
					Body: v1.List[v1.DNSLog]{
						Items: []v1.DNSLog{logs[1], logs[2]},
					},
				},
			}...)

			// Run the search
			domains := storage.DomainNameSetSpec{"xx.yy.zzz", "dd.ee.fff", "jj.kk.lll"}
			testFeed := &apiv3.GlobalThreatFeed{}
			testFeed.Name = "test-feed"
			iter, _, err := uut.QueryDomainNameSet(ctx, domains, testFeed)
			Expect(err).ToNot(HaveOccurred())

			var actual []v1.DNSLog
			var keys []storage.QueryKey
			for iter.Next() {
				k, h := iter.Value()
				keys = append(keys, k)
				actual = append(actual, h)
			}
			Expect(keys).To(Equal([]storage.QueryKey{
				storage.QueryKeyDNSLogQName,
				storage.QueryKeyDNSLogRRSetsName, storage.QueryKeyDNSLogRRSetsName,
				storage.QueryKeyDNSLogRRSetsRData, storage.QueryKeyDNSLogRRSetsRData,
			}))

			// Qname query
			Expect(string(actual[0].QName)).To(Equal("xx.yy.zzz"))

			// rrsets.name query
			// We identify the results by the QName, which is unique for each log.
			qnames := []string{string(actual[1].QName), string(actual[2].QName)}
			// Query for xx.yy.zzz has the name xx.yy.zzz in the first RRSet
			Expect(qnames).To(ContainElement("xx.yy.zzz"))
			// Query for aa.bb.ccc has the name dd.ee.fff in the second RRSet
			Expect(qnames).To(ContainElement("aa.bb.ccc"))

			// rrsets.rdata query
			// We identify the results by the QName, which is unique for each log.
			qnames = []string{string(actual[3].QName), string(actual[4].QName)}
			// Query for aa.bb.ccc has the data dd.ee.fff in the first rrset
			Expect(qnames).To(ContainElement("aa.bb.ccc"))
			// Query for gg.hh.iii has the data jj.kk.lll in the first rrset
			Expect(qnames).To(ContainElement("gg.hh.iii"))
		})

		It("Add security events for domain names", func() {
			l := v1.DNSLog{
				StartTime:       time.Unix(123, 0),
				EndTime:         time.Unix(456, 0),
				Count:           1,
				ClientName:      "client",
				ClientNamespace: "test",
				QClass:          v1.DNSClass(layers.DNSClassIN),
				QType:           v1.DNSType(layers.DNSTypeA),
				QName:           "xx.yy.zzz",
				RCode:           v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
				RRSets: v1.DNSRRSets{
					{
						Name:  "xx.yy.zzz",
						Class: v1.DNSClass(layers.DNSClassIN),
						Type:  v1.DNSType(layers.DNSTypeA),
					}: v1.DNSRDatas{{Raw: []byte("1.2.3.4")}},
				},
			}
			domains := map[string]struct{}{
				"xx.yy.zzz": {},
			}
			e := events.ConvertDNSLog(l, storage.QueryKeyDNSLogQName, domains, "my-feed", "my-other-feed")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			lsc.SetResults([]rest.MockResult{
				{
					Body: v1.BulkResponse{
						Total:     1,
						Succeeded: 1,
						Failed:    0,
					},
				},
			}...)

			err := uut.PutSecurityEventWithID(ctx, []v1.Event{e})
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
