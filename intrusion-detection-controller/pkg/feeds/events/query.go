// Copyright 2019 Tigera Inc. All rights reserved.

package events

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	geodb "github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/geodb"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

type ipSetQuerier struct {
	storage.SetQuerier
}

func (i ipSetQuerier) QuerySet(ctx context.Context, geoDB geodb.GeoDatabase, feed *apiv3.GlobalThreatFeed) ([]v1.Event, time.Time, string, error) {
	var results []v1.Event
	lastSuccessfulSearch := time.Now()
	iter, ipSetHash, err := i.QueryIPSet(ctx, geoDB, feed)
	if err != nil {
		return nil, time.Time{}, ipSetHash, err
	}
	c := 0
	for iter.Next() {
		c++
		key, val := iter.Value()
		sEvent := ConvertFlowLog(val, key, geoDB, feed.Name)
		results = append(results, sEvent)
	}
	log.WithField("num", c).Debugf("[Global Threat Feeds] got events for %v", feed.Name)
	return results, lastSuccessfulSearch, ipSetHash, iter.Err()
}

func NewSuspiciousIP(q storage.SetQuerier) storage.SuspiciousSet {
	return ipSetQuerier{q}
}

type domainNameSetQuerier struct {
	storage.SetQuerier
}

func (d domainNameSetQuerier) QuerySet(ctx context.Context, geoDB geodb.GeoDatabase, feed *apiv3.GlobalThreatFeed) ([]v1.Event, time.Time, string, error) {
	set, err := d.GetDomainNameSet(ctx, feed.Name)
	if err != nil {
		return nil, time.Time{}, "", err
	}
	var results []v1.Event
	lastSuccessfulSearch := time.Now()
	iter, domainNameSetHash, err := d.QueryDomainNameSet(ctx, set, feed)
	if err != nil {
		return nil, time.Time{}, domainNameSetHash, err
	}
	// Hash the domain name set for use in conversion
	domains := make(map[string]struct{})
	for _, dn := range set {
		domains[dn] = struct{}{}
	}

	c := 0
	filt := newDNSFilter()
	for iter.Next() {
		c++
		key, val := iter.Value()
		if filt.pass(val.ID) {
			sEvent := ConvertDNSLog(val, key, domains, feed.Name)
			results = append(results, sEvent)
		}
	}
	log.WithField("num", c).Debugf("[Global Threat Feeds] got events for %v", feed.Name)
	return results, lastSuccessfulSearch, domainNameSetHash, iter.Err()
}

func NewSuspiciousDomainNameSet(q storage.SetQuerier) storage.SuspiciousSet {
	return domainNameSetQuerier{q}
}

// DNS logs contain the domain queried for as well as the results, and a suspicious name might appear in multiple
// locations in a single DNS query event. We don't want to create multiple security events for a single DNS query,
// so just take the first one, which we track using a hashmap.
type dnsFilter struct {
	seen map[string]struct{}
}

// pass returns true only if this is the first log we've seen with a particular index/id.
func (d *dnsFilter) pass(id string) bool {
	_, ok := d.seen[id]
	d.seen[id] = struct{}{}
	return !ok
}

func newDNSFilter() *dnsFilter {
	return &dnsFilter{seen: make(map[string]struct{})}
}
