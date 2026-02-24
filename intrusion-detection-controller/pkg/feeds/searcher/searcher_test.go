// Copyright 2019-2024 Tigera Inc. All rights reserved.

package searcher

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	geodb "github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/geodb"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/util"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

// TestDoIPSet tests the case where everything is working
func TestDoIPSet(t *testing.T) {
	expected := []v1.Event{
		{
			ID:         "1234",
			SourceIP:   util.Sptr("1.2.3.4"),
			SourceName: "source",
			DestIP:     util.Sptr("2.3.4.5"),
			DestName:   "dest",
		},
		{
			ID:         "2345",
			SourceIP:   util.Sptr("5.6.7.8"),
			SourceName: "source",
			DestIP:     util.Sptr("2.3.4.5"),
			DestName:   "dest",
		},
	}
	runTest(t, true, expected, time.Now(), "", nil, -1)
}

// TestCacheEvents tests the caching of events is working
func TestCacheEvents(t *testing.T) {
	g := NewGomegaWithT(t)

	e1 := v1.Event{
		ID: "1234",
	}

	e2 := v1.Event{
		ID: "2345",
	}

	e3 := v1.Event{
		ID: "3456",
	}

	processEvents := []v1.Event{e1, e2, e3}

	cachedEvents := []v1.Event{e1, e2}

	f := util.NewGlobalThreatFeedFromName("mock")
	suspiciousIP := &storage.MockSuspicious{
		Error:                nil,
		LastSuccessfulSearch: time.Now(),
		SetHash:              "",
	}
	suspiciousIP.Events = append(suspiciousIP.Events, processEvents...)
	eventsDB := &storage.MockEvents{ErrorIndex: -1, Events: []v1.Event{}}
	uut := NewSearcher(f, 0, suspiciousIP, eventsDB, &geodb.MockGeoDB{}, time.Duration(5*time.Minute)).(*searcher)

	for _, e := range cachedEvents {
		uut.cachedEvents.Add(&e)
	}
	feedCacher := cacher.NewMockGlobalThreatFeedCache()
	ctx := t.Context()
	uut.doSearch(ctx, feedCacher)

	g.Expect(eventsDB.Events).Should(ConsistOf([]v1.Event{e3}), "1 Event should be in DB")
}

// TestDoIPSetNoResults tests the case where no results are returned
func TestDoIPSetNoResults(t *testing.T) {
	expected := []v1.Event{}
	runTest(t, true, expected, time.Now(), "", nil, -1)
}

// TestDoIPSetSuspiciousIPFails tests the case where suspiciousIP fails after the first result
func TestDoIPSetSuspiciousIPFails(t *testing.T) {
	expected := []v1.Event{}
	runTest(t, false, expected, time.Time{}, "", errors.New("fail"), -1)
}

// TestDoIPSetEventsFails tests the case where the first call to events.PutSecurityEventWithID fails but the second does not
func TestDoIPSetEventsFails(t *testing.T) {
	expected := []v1.Event{
		{
			ID:         "1234",
			SourceIP:   util.Sptr("1.2.3.4"),
			SourceName: "source",
			DestIP:     util.Sptr("2.3.4.5"),
			DestName:   "dest",
		},
		{
			ID:         "2345",
			SourceIP:   util.Sptr("5.6.7.8"),
			SourceName: "source",
			DestIP:     util.Sptr("2.3.4.5"),
			DestName:   "dest",
		},
	}

	runTest(t, false, expected, time.Time{}, "", nil, 0)
}

func runTest(t *testing.T, successful bool, expectedSecurityEvents []v1.Event,
	lastSuccessfulSearch time.Time, setHash string, err error, eventsErrorIdx int,
) {
	g := NewGomegaWithT(t)

	f := util.NewGlobalThreatFeedFromName("mock")
	suspiciousIP := &storage.MockSuspicious{
		Error:                err,
		LastSuccessfulSearch: lastSuccessfulSearch,
		SetHash:              setHash,
	}
	suspiciousIP.Events = append(suspiciousIP.Events, expectedSecurityEvents...)
	eventsDB := &storage.MockEvents{ErrorIndex: eventsErrorIdx, Events: []v1.Event{}}
	uut := NewSearcher(f, 0, suspiciousIP, eventsDB, &geodb.MockGeoDB{}, 1).(*searcher)
	feedCacher := cacher.NewMockGlobalThreatFeedCache()

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	uut.doSearch(ctx, feedCacher)

	if successful {
		g.Expect(eventsDB.Events).Should(ConsistOf(expectedSecurityEvents), "Logs in DB should match expectedSecurityEvents")
	} else {
		if eventsErrorIdx >= 0 {
			g.Expect(eventsDB.Events).Should(HaveLen(len(expectedSecurityEvents)-1), "Logs in DB should have skipped 1 from input")
		} else {
			g.Expect(eventsDB.Events).Should(HaveLen(len(expectedSecurityEvents)), "DB should have all inputs")
		}
	}

	status := feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Status
	g.Expect(status.LastSuccessfulSync).Should(BeNil(), "Sync should not be marked as successful")
	if successful {
		g.Expect(status.LastSuccessfulSearch.Time).ShouldNot(Equal(time.Time{}), "Search should be marked as successful")
		g.Expect(status.ErrorConditions).Should(HaveLen(0), "No errors should be reported")
	} else {
		g.Expect(status.LastSuccessfulSearch).Should(BeNil(), "Search should be not marked as successful")
		g.Expect(status.ErrorConditions).ShouldNot(HaveLen(0), "Errors should be reported")
	}
}

func TestFlowSearcher_SetFeed(t *testing.T) {
	g := NewGomegaWithT(t)

	f := util.NewGlobalThreatFeedFromName("mock")
	f2 := util.NewGlobalThreatFeedFromName("swap")
	suspiciousIP := &storage.MockSuspicious{}
	eventsDB := &storage.MockEvents{}
	searcher := NewSearcher(f, 0, suspiciousIP, eventsDB, &geodb.MockGeoDB{}, 1).(*searcher)

	searcher.SetFeed(f2)
	g.Expect(searcher.feed).Should(Equal(f2))
	g.Expect(searcher.feed).ShouldNot(BeIdenticalTo(f2))
}
