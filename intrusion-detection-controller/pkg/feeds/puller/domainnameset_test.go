// Copyright 2019 Tigera Inc. All rights reserved.

package puller

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/sync"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/util"
)

func TestQueryDomainNameSet(t *testing.T) {
	g := NewGomegaWithT(t)

	input := storage.DomainNameSetSpec{
		"www.badguys.co.uk",
		"we-love-malware.io ",
		"z.f.com # a comment after a valid address",
		"  hax4u.ru",
		"com # a top-level-domain is technically a valid domain name",
		"wWw.bOTnET..qQ. # should normalize case and dots",
		"junk&stuff # not a valid domain name, but still possible to query for",
		"-junk.com # also not a valid name, but still possible to query for",
		"mølmer-sørensen.gate",
		"xn--mlmer-srensen-bnbg.gate",
	}
	expected := storage.IPSetSpec{
		"www.badguys.co.uk",
		"we-love-malware.io",
		"z.f.com",
		"hax4u.ru",
		"com",
		"www.botnet.qq",
		"junk&stuff",
		"-junk.com",
		"mølmer-sørensen.gate",
		"mølmer-sørensen.gate",
	}

	client := &http.Client{}
	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(strings.Join(append(input, "# comment", "", " "), "\n"))),
	}
	client.Transport = &util.MockRoundTripper{
		Response: resp,
	}
	feedCacher := &cacher.MockGlobalThreatFeedCache{}
	edn := sync.NewMockDomainNameSetsController()

	ctx := t.Context()

	puller := NewDomainNameSetHTTPPuller(&testGTFDomainNameSet, &storage.MockSets{}, &MockConfigMap{}, &MockSecrets{}, client, edn).(*httpPuller)

	go func() {
		err := puller.queryURL(ctx, feedCacher, 1, 0)
		g.Expect(err).ShouldNot(HaveOccurred())
	}()

	g.Eventually(edn.Sets).Should(HaveKey(testGTFDomainNameSet.Name))
	dset, ok := edn.Sets()[testGlobalThreatFeed.Name]
	g.Expect(ok).Should(BeTrue(), "Received a snapshot")
	g.Expect(dset).Should(HaveLen(len(expected)))
	for idx, actual := range dset {
		g.Expect(actual).Should(Equal(expected[idx]))
	}

	status := feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Status
	g.Expect(status.LastSuccessfulSync.Time).ShouldNot(Equal(time.Time{}), "Sync time was set")
	g.Expect(status.LastSuccessfulSearch).Should(BeNil(), "Search time was not set")
	g.Expect(status.ErrorConditions).Should(HaveLen(0), "FeedCacher errors were not reported")
}

func TestQueryDomainNameSet_WithGNS(t *testing.T) {
	g := NewGomegaWithT(t)

	input := storage.DomainNameSetSpec{
		"www.badguys.co.uk",
		"we-love-malware.io ",
	}
	expected := storage.IPSetSpec{
		"www.badguys.co.uk",
		"we-love-malware.io",
	}

	client := &http.Client{}
	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(strings.Join(input, "\n"))),
	}
	client.Transport = &util.MockRoundTripper{
		Response: resp,
	}
	feedCacher := &cacher.MockGlobalThreatFeedCache{}
	edn := sync.NewMockDomainNameSetsController()

	ctx := t.Context()

	f := testGTFDomainNameSet.DeepCopy()
	f.Spec.GlobalNetworkSet = &v3.GlobalNetworkSetSync{Labels: map[string]string{"key": "value"}}
	puller := NewDomainNameSetHTTPPuller(f, &storage.MockSets{}, &MockConfigMap{}, &MockSecrets{}, client, edn).(*httpPuller)

	go func() {
		err := puller.queryURL(ctx, feedCacher, 1, 0)
		g.Expect(err).ShouldNot(HaveOccurred())
	}()

	g.Eventually(edn.Sets).Should(HaveKey(testGTFDomainNameSet.Name))
	dset, ok := edn.Sets()[testGTFDomainNameSet.Name]
	g.Expect(ok).Should(BeTrue(), "Received a snapshot")
	g.Expect(dset).Should(HaveLen(len(expected)))
	for idx, actual := range dset {
		g.Expect(actual).Should(Equal(expected[idx]))
	}

	status := feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Status
	// Pull should work as expected, but drop an error about GlobalNetworkSetSync
	g.Expect(status.LastSuccessfulSync.Time).ShouldNot(Equal(time.Time{}), "Sync time was set")
	g.Expect(status.LastSuccessfulSearch).Should(BeNil(), "Search time was not set")
	g.Expect(status.ErrorConditions).
		Should(ConsistOf([]v3.ErrorCondition{{Type: cacher.GlobalNetworkSetSyncFailed, Message: "[Global Threat Feeds] sync not supported for domain name set"}}))
}

func TestGetStartupDelayDomainNameSet(t *testing.T) {
	g := NewGomegaWithT(t)

	ctx := t.Context()

	edn := sync.NewMockDomainNameSetsController()
	puller := NewDomainNameSetHTTPPuller(&testGTFDomainNameSet, &storage.MockSets{
		Time: time.Now().Add(-time.Hour),
	}, &MockConfigMap{ConfigMapData: configMapData}, &MockSecrets{SecretsData: secretsData}, nil, edn).(*httpPuller)

	delay := puller.getStartupDelay(ctx)

	g.Expect(delay).Should(BeNumerically("~", puller.period-time.Hour, time.Minute))
}

func TestCanonicalizeDNSName(t *testing.T) {
	g := NewGomegaWithT(t)

	g.Expect(canonicalizeDNSName("tigera.io")).Should(Equal("tigera.io"))
	g.Expect(canonicalizeDNSName(".tigera.io.")).Should(Equal("tigera.io"))
	g.Expect(canonicalizeDNSName("..tigera..io..")).Should(Equal("tigera.io"))
	g.Expect(canonicalizeDNSName("tIgeRa.Io")).Should(Equal("tigera.io"))
	g.Expect(canonicalizeDNSName("xn--Mlmer-Srensen-bnbg.gate")).Should(Equal("mølmer-sørensen.gate"))
	g.Expect(canonicalizeDNSName("mølmer-sørensen.gate")).Should(Equal("mølmer-sørensen.gate"))

	// www.Æther.com --- with capital, should be normalized to lowercase
	g.Expect(canonicalizeDNSName("www.xn--ther-9ja.com")).Should(Equal("www.æther.com"))

	// Names already in unicode should be normalized to lowercase
	g.Expect(canonicalizeDNSName("www.Æther.com")).Should(Equal("www.æther.com"))

	// Names with corrupted punycode should just be normalized with case and dots
	g.Expect(canonicalizeDNSName("xn--Mlmer-Srensen-bnb&..gate")).Should(Equal("xn--mlmer-srensen-bnb&.gate"))
}

func TestSyncGNSFromDB_DomainNameSet(t *testing.T) {
	g := NewGomegaWithT(t)

	ctx := t.Context()

	feed := testGTFDomainNameSet.DeepCopy()
	feed.Spec.GlobalNetworkSet = &v3.GlobalNetworkSetSync{Labels: map[string]string{"key": "value"}}
	dnSet := &storage.MockSets{
		Value: storage.DomainNameSetSpec{"baddos.ooo"},
	}
	feedCacher := &cacher.MockGlobalThreatFeedCache{}

	puller := NewDomainNameSetHTTPPuller(feed, dnSet, &MockConfigMap{ConfigMapData: configMapData}, &MockSecrets{SecretsData: secretsData}, nil, nil).(*httpPuller)

	puller.setHandler.syncFromDB(ctx, feedCacher)

	g.Expect(feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Status.ErrorConditions).
		Should(ConsistOf([]v3.ErrorCondition{{Type: cacher.GlobalNetworkSetSyncFailed, Message: "[Global Threat Feeds] sync not supported for domain name set"}}))
}
