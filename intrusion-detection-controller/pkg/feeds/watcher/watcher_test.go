// Copyright 2019 Tigera Inc. All rights reserved.

package watcher

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/calico"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	geodb "github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/geodb"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/sync"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/sync/globalnetworksets"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/util"
)

var testClient = &http.Client{Transport: &util.MockRoundTripper{Error: errors.New("mock error")}}

func TestWatcher_processQueue(t *testing.T) {
	g := NewGomegaWithT(t)

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	edn := sync.NewMockDomainNameSetsController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, edn, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	g.Expect(w).ShouldNot(BeNil())

	ctx := t.Context()
	w.ctx = ctx

	// a non-existing feed is deleted.
	err := w.processQueue(cache.Deltas{
		{
			Type: cache.Deleted,
			Object: &v3.GlobalThreatFeed{
				ObjectMeta: v1.ObjectMeta{
					Name: "nonexisting",
				},
			},
		},
	}, true)
	g.Expect(err).NotTo(HaveOccurred())

	// a feed is added
	err = w.processQueue(cache.Deltas{
		{
			Type: cache.Added,
			Object: &v3.GlobalThreatFeed{
				ObjectMeta: v1.ObjectMeta{
					Name: "feed1",
				},
			},
		},
	}, true)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(w.listFeedWatchers()).Should(HaveLen(1))

	// a non-existing feed is updated (should never happen)
	err = w.processQueue(cache.Deltas{
		{
			Type: cache.Updated,
			Object: &v3.GlobalThreatFeed{
				ObjectMeta: v1.ObjectMeta{
					Name: "feed2",
				},
			},
		},
	}, true)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(w.listFeedWatchers()).Should(HaveLen(2))

	// an existing feed is added again
	err = w.processQueue(cache.Deltas{
		{
			Type: cache.Added,
			Object: &v3.GlobalThreatFeed{
				ObjectMeta: v1.ObjectMeta{
					Name:            "feed1",
					ResourceVersion: "test",
				},
			},
		},
	}, true)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(w.listFeedWatchers()).Should(HaveLen(2))
	fw, ok := w.getFeedWatcher("feed1")
	g.Expect(ok).Should(BeTrue())
	g.Expect(fw.feed.ResourceVersion).Should(Equal("test"))

	// an existing feed is modified
	err = w.processQueue(cache.Deltas{
		{
			Type: cache.Added,
			Object: &v3.GlobalThreatFeed{
				ObjectMeta: v1.ObjectMeta{
					Name:            "feed1",
					ResourceVersion: "test2",
				},
			},
		},
	}, true)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(w.listFeedWatchers()).Should(HaveLen(2))
	fw, ok = w.getFeedWatcher("feed1")
	g.Expect(ok).Should(BeTrue())
	g.Expect(fw.feed.ResourceVersion).Should(Equal("test2"))

	// an existing feed is deleted
	err = w.processQueue(cache.Deltas{
		{
			Type: cache.Deleted,
			Object: &v3.GlobalThreatFeed{
				ObjectMeta: v1.ObjectMeta{
					Name: "feed1",
				},
			},
		},
	}, true)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(w.listFeedWatchers()).Should(HaveLen(1))
	_, ok = w.getFeedWatcher("feed1")
	g.Expect(ok).Should(BeFalse())
}

func TestWatcher_startFeed_stopFeed_IPSet(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	edn := sync.NewMockDomainNameSetsController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, edn, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")

	g.Expect(fw.feed).Should(Equal(f))
	g.Expect(fw.puller).ShouldNot(BeNil())
	g.Expect(gns.NotGCable()).Should(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(fw.feedCacher).ShouldNot(BeNil())
	g.Expect(fw.searcher).ShouldNot(BeNil())

	w.stopFeedWatcher(ctx, f.Name)
	_, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeFalse(), "FeedWatchers map does not contain feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(0), "No FeedWatchers")
	g.Expect(gns.NotGCable()).ShouldNot(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).ShouldNot(HaveKey(f.Name))
}

func TestWatcher_startFeed_stopFeed_DomainNameSet(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "DomainNameSet",
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	dnSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	edn := sync.NewMockDomainNameSetsController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, edn, testClient, nil, dnSet, nil, &storage.MockSuspicious{}, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")

	g.Expect(fw.feed).Should(Equal(f))
	g.Expect(fw.puller).ShouldNot(BeNil())
	g.Expect(gns.NotGCable()).ShouldNot(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(edn.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(fw.feedCacher).ShouldNot(BeNil())
	g.Expect(fw.searcher).ShouldNot(BeNil())

	w.stopFeedWatcher(ctx, f.Name)
	_, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeFalse(), "FeedWatchers map does not contain feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(0), "No FeedWatchers")
	g.Expect(gns.NotGCable()).ShouldNot(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(edn.NotGCable()).ShouldNot(HaveKey(f.Name))
}

func TestWatcher_startFeed_defaultcontent(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	edn := sync.NewMockDomainNameSetsController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, edn, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")

	g.Expect(fw.feed).Should(Equal(f))
	g.Expect(fw.puller).ShouldNot(BeNil())
	g.Expect(gns.NotGCable()).Should(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(edn.NotGCable()).ShouldNot(HaveKey(f.Name))
	g.Expect(fw.feedCacher).ShouldNot(BeNil())
	g.Expect(fw.searcher).ShouldNot(BeNil())
}

func TestWatcher_startFeed_NoPull_IPSet(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).Should(HaveLen(1), "No FeedWatchers")
	g.Expect(fw.puller).Should(BeNil(), "MockPuller is nil")
	g.Expect(gns.NotGCable()).Should(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(fw.feedCacher).ShouldNot(BeNil(), "FeedCacher is not nil")
}

func TestWatcher_startFeed_NoPullHTTP_IPSet(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).Should(HaveLen(1), "No FeedWatchers")
	g.Expect(fw.puller).Should(BeNil(), "MockPuller is nil")
	g.Expect(gns.NotGCable()).Should(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(fw.feedCacher).ShouldNot(BeNil(), "FeedCacher is not nil")
}

func TestWatcher_startFeed_NoPull_DomainNameSet(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "DomainNameSet",
		},
	}

	dnSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	edn := sync.NewMockDomainNameSetsController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, nil, edn, testClient, nil, dnSet, nil, &storage.MockSuspicious{}, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).Should(HaveLen(1), "No FeedWatchers")
	g.Expect(fw.puller).Should(BeNil(), "MockPuller is nil")
	g.Expect(gns.NotGCable()).ShouldNot(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(edn.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(fw.feedCacher).ShouldNot(BeNil(), "FeedCacher is not nil")
}

func TestWatcher_startFeed_NoPullHTTP_DomainNameSet(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "DomainNameSet",
			Pull:    &v3.Pull{},
		},
	}

	dnSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	edn := sync.NewMockDomainNameSetsController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, nil, edn, testClient, nil, dnSet, nil, &storage.MockSuspicious{}, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).Should(HaveLen(1), "No FeedWatchers")
	g.Expect(fw.puller).Should(BeNil(), "MockPuller is nil")
	g.Expect(gns.NotGCable()).ShouldNot(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(edn.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(fw.feedCacher).ShouldNot(BeNil(), "FeedCacher is not nil")
}

func TestWatcher_startFeed_Exists(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	_, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")

	g.Expect(func() { w.startFeedWatcher(ctx, f) }).Should(Panic())
}

func TestWatcher_startFeed_DomainNameSetWithGNS(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "DomainNameSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	dnSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	edn := sync.NewMockDomainNameSetsController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, nil, edn, testClient, nil, dnSet, nil, &storage.MockSuspicious{}, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).Should(HaveLen(1))
	g.Expect(fw.feedCacher).ShouldNot(BeNil(), "FeedCacher is not nil")
}

func TestWatcher_stopFeed_notExists(t *testing.T) {
	g := NewGomegaWithT(t)

	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, nil, nil, nil, testClient, nil, nil, nil, nil, nil, &geodb.MockGeoDB{}, 1).(*watcher)
	ctx := t.Context()

	g.Expect(func() { w.stopFeedWatcher(ctx, "mock") }).Should(Panic())
}

func TestWatcher_updateFeed_NotStarted(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	g.Expect(func() { w.updateFeedWatcher(ctx, f, f.DeepCopy()) }).Should(Panic())
}

func TestWatcher_updateFeed_PullToPull(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")
	g.Expect(gns.NotGCable()).Should(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))

	// hack in some mocks so we can verify that SetFeed was called
	mockPuller := &MockPuller{}
	mockSearcher := &MockSearcher{}
	fw.puller = mockPuller
	fw.searcher = mockSearcher

	w.updateFeedWatcher(ctx, f, f.DeepCopy())

	fw, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")
	g.Expect(mockPuller.Feed).ShouldNot(BeNil())
	g.Expect(mockPuller.CloseCalled).Should(BeFalse())
	g.Expect(fw.puller).Should(BeIdenticalTo(mockPuller))
	g.Expect(gns.NotGCable()).Should(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(mockSearcher.Feed).ShouldNot(BeNil(), "SetFeed was called")
}

func TestWatcher_updateFeed_PullToPush(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")
	g.Expect(gns.NotGCable()).Should(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))

	// hack in some mocks so we can verify that SetFeed was called
	mockPuller := &MockPuller{}
	mockSearcher := &MockSearcher{}
	fw.puller = mockPuller
	fw.searcher = mockSearcher

	f2 := f.DeepCopy()
	f2.Spec.Pull = nil

	w.updateFeedWatcher(ctx, f, f2)

	fw, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")
	g.Expect(fw.puller).Should(BeNil())
	g.Expect(gns.NotGCable()).Should(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(mockPuller.Feed).Should(BeNil())
	g.Expect(mockPuller.CloseCalled).Should(BeTrue())
	g.Expect(mockSearcher.Feed).ShouldNot(BeNil(), "SetFeed was called")
}

func TestWatcher_updateFeed_PushToPull(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")
	g.Expect(gns.NotGCable()).ShouldNot(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))

	// hack in some mocks so we can verify that SetFeed was called
	searcher := &MockSearcher{}
	fw.searcher = searcher

	f2 := f.DeepCopy()
	f2.Spec.Pull = &v3.Pull{
		Period: "12h",
		HTTP: &v3.HTTPPull{
			Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
			URL:     "http://mock.feed/v1",
			Headers: []v3.HTTPHeader{},
		},
	}
	f2.Spec.GlobalNetworkSet = &v3.GlobalNetworkSetSync{
		Labels: map[string]string{"level": "high"},
	}

	w.updateFeedWatcher(ctx, f, f2)

	fw, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")
	g.Expect(fw.puller).ShouldNot(BeNil())
	g.Expect(gns.NotGCable()).Should(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(searcher.Feed).ShouldNot(BeNil(), "SetFeed was called")
}

func TestWatcher_updateFeed_PushToPush(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")
	g.Expect(gns.NotGCable()).ShouldNot(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))

	searcher := &MockSearcher{}
	fw.searcher = searcher

	w.updateFeedWatcher(ctx, f, f.DeepCopy())

	fw, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")
	g.Expect(fw.puller).Should(BeNil())
	g.Expect(gns.NotGCable()).ShouldNot(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))
	g.Expect(searcher.Feed).ShouldNot(BeNil(), "SetFeed was called")
}

func TestWatcher_updateFeed_IPSetToDomainNameSet(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	mockSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	edn := sync.NewMockDomainNameSetsController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, edn, testClient, mockSet, mockSet, &storage.MockSuspicious{}, &storage.MockSuspicious{}, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")
	g.Expect(gns.NotGCable()).Should(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)))
	g.Expect(eip.NotGCable()).Should(HaveKey(f.Name))

	// hack in some mocks so we can verify that the old puller/searcher are cleaned up
	mockPuller := &MockPuller{}
	mockSearcher := &MockSearcher{}
	fw.puller = mockPuller
	fw.searcher = mockSearcher

	uf := f.DeepCopy()
	uf.Spec.GlobalNetworkSet = nil
	uf.Spec.Content = "DomainNameSet"
	w.updateFeedWatcher(ctx, f, uf)

	fw, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")
	g.Expect(mockPuller.CloseCalled).Should(BeTrue(), "closed the old puller")
	g.Expect(fw.puller).ShouldNot(BeIdenticalTo(mockPuller), "removed old puller")
	g.Expect(gns.NotGCable()).ShouldNot(HaveKey(util.GlobalNetworkSetNameFromThreatFeed(f.Name)), "GC old GNS")
	g.Expect(eip.NotGCable()).ShouldNot(HaveKey(f.Name), "GC old ipset")
	g.Expect(mockSearcher.CloseCalled).Should((BeTrue()), "closed the old searcher")
	g.Expect(fw.searcher).ShouldNot(BeIdenticalTo(mockSearcher), "removed old searcher")

	g.Expect(edn.NotGCable()).Should(HaveKey(uf.Name))
	g.Expect(fw.puller).ShouldNot(BeNil())
	g.Expect(fw.searcher).ShouldNot(BeNil())
}

func TestWatcher_restartPuller_IPSet(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")

	g.Expect(fw.feed).Should(Equal(f))
	g.Expect(fw.puller).ShouldNot(BeNil())
	g.Expect(fw.feedCacher).ShouldNot(BeNil())
	g.Expect(fw.searcher).ShouldNot(BeNil())

	oldPuller := fw.puller

	w.restartPuller(ctx, f)
	fw, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue())
	g.Expect(fw.puller).ShouldNot(Equal(oldPuller))
}

func TestWatcher_restartPuller_DomainNameSet(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "DomainNameSet",
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	dnSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	edn := sync.NewMockDomainNameSetsController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, nil, edn, testClient, nil, dnSet, nil, &storage.MockSuspicious{}, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")

	g.Expect(fw.feed).Should(Equal(f))
	g.Expect(fw.puller).ShouldNot(BeNil())
	g.Expect(fw.feedCacher).ShouldNot(BeNil())
	g.Expect(fw.searcher).ShouldNot(BeNil())

	oldPuller := fw.puller

	w.restartPuller(ctx, f)
	fw, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue())
	g.Expect(fw.puller).ShouldNot(Equal(oldPuller))
}

func TestWatcher_restartPuller_defaultcontent(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")

	g.Expect(fw.feed).Should(Equal(f))
	g.Expect(fw.puller).ShouldNot(BeNil())
	g.Expect(fw.feedCacher).ShouldNot(BeNil())
	g.Expect(fw.searcher).ShouldNot(BeNil())

	oldPuller := fw.puller

	w.restartPuller(ctx, f)
	fw, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue())
	g.Expect(fw.puller).ShouldNot(Equal(oldPuller))
}

func TestWatcher_restartPuller_NoPull(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")

	g.Expect(fw.feed).Should(Equal(f))
	g.Expect(fw.puller).ShouldNot(BeNil())
	g.Expect(fw.feedCacher).ShouldNot(BeNil())
	g.Expect(fw.searcher).ShouldNot(BeNil())

	f.Spec.Pull = nil

	w.restartPuller(ctx, f)
	fw, ok = w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue())
	g.Expect(fw.puller).Should(BeNil())
}

func TestWatcher_restartPuller_NoPullHTTP(t *testing.T) {
	g := NewGomegaWithT(t)

	f := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}

	ipSet := &storage.MockSets{}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: &v3.GlobalThreatFeed{},
	}

	w := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, ipSet, nil, &storage.MockSuspicious{}, nil, &storage.MockEvents{}, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	w.startFeedWatcher(ctx, f)

	fw, ok := w.getFeedWatcher(f.Name)
	g.Expect(ok).Should(BeTrue(), "FeedWatchers map contains feed")
	g.Expect(w.listFeedWatchers()).To(HaveLen(1), "Only one FeedWatcher")

	g.Expect(fw.feed).Should(Equal(f))
	g.Expect(fw.puller).ShouldNot(BeNil())
	g.Expect(fw.feedCacher).ShouldNot(BeNil())
	g.Expect(fw.searcher).ShouldNot(BeNil())

	f.Spec.Pull.HTTP = nil

	w.restartPuller(ctx, f)
	fw, _ = w.getFeedWatcher(f.Name)
	g.Expect(fw.puller).Should(BeNil())
}

func TestWatcher_restartPuller_notExists(t *testing.T) {
	g := NewGomegaWithT(t)

	globalThreatFeed := &v3.GlobalThreatFeed{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mock",
			Namespace: util.FeedsNamespace,
		},
		Spec: v3.GlobalThreatFeedSpec{
			Content: "IPSet",
			GlobalNetworkSet: &v3.GlobalNetworkSetSync{
				Labels: map[string]string{
					"level": "high",
				},
			},
			Pull: &v3.Pull{
				Period: "12h",
				HTTP: &v3.HTTPPull{
					Format:  v3.ThreatFeedFormat{NewlineDelimited: &v3.ThreatFeedFormatNewlineDelimited{}},
					URL:     "http://mock.feed/v1",
					Headers: []v3.HTTPHeader{},
				},
			},
		},
	}
	gtf := &calico.MockGlobalThreatFeedInterface{
		GlobalThreatFeed: globalThreatFeed,
	}

	w := NewWatcher(nil, nil, gtf, nil, nil, nil, testClient, nil, nil, nil, nil, nil, &geodb.MockGeoDB{}, 1).(*watcher)

	ctx := t.Context()

	g.Expect(func() { w.restartPuller(ctx, globalThreatFeed) }).Should(Panic())
}

func TestWatcher_Ping(t *testing.T) {
	g := NewWithT(t)

	// Include an empty list so that the controller doesn't complain
	gtf := &calico.MockGlobalThreatFeedInterface{GlobalThreatFeedList: &v3.GlobalThreatFeedList{}}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	edn := sync.NewMockDomainNameSetsController()
	uut := NewWatcher(nil, nil, gtf, gns, eip, edn, testClient, nil, nil, nil, nil, nil, &geodb.MockGeoDB{}, 1)

	ch := make(chan struct{})
	defer func() {
		g.Eventually(ch).Should(BeClosed(), "Test cleans up correctly")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	go func() {
		defer close(ch)
		err := uut.Ping(ctx)
		g.Expect(err).ToNot(HaveOccurred())
	}()
	g.Consistently(ch).ShouldNot(BeClosed(), "Ping does not complete before Run is called")

	uut.Run(ctx)

	g.Eventually(ch).Should(BeClosed(), "Ping completes after Run is called")
}

func TestWatcher_PingFail(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Millisecond)
	defer cancel()

	// Include an empty list so that the controller doesn't complain
	gtf := &calico.MockGlobalThreatFeedInterface{GlobalThreatFeedList: &v3.GlobalThreatFeedList{}}
	gns := globalnetworksets.NewMockGlobalNetworkSetController()
	eip := sync.NewMockIPSetController()
	uut := NewWatcher(nil, nil, gtf, gns, eip, nil, testClient, nil, nil, nil, nil, nil, &geodb.MockGeoDB{}, 1)

	err := uut.Ping(ctx)
	g.Expect(err).Should(MatchError(context.DeadlineExceeded), "Ping times out")
}

type MockPuller struct {
	Feed        *v3.GlobalThreatFeed
	CloseCalled bool
}

func (p *MockPuller) Close() {
	p.CloseCalled = true
}

func (*MockPuller) Run(context.Context, cacher.GlobalThreatFeedCacher) {
	panic("implement me")
}

func (p *MockPuller) SetFeed(f *v3.GlobalThreatFeed) {
	p.Feed = f
}

type MockSearcher struct {
	Feed        *v3.GlobalThreatFeed
	CloseCalled bool
}

func (s *MockSearcher) Close() {
	s.CloseCalled = true
}

func (*MockSearcher) Run(context.Context, cacher.GlobalThreatFeedCacher) {
	panic("implement me")
}

func (m *MockSearcher) SetFeed(f *v3.GlobalThreatFeed) {
	m.Feed = f
}
