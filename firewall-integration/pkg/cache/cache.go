// Copyright 2019 Tigera Inc. All rights reserved.

package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jpillora/backoff"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/firewall-integration/pkg/config"
)

type gnpCacheEntry struct {
	value any
}

type GnpCache struct {
	datastore datastore.ClientSet
	cache     map[string]gnpCacheEntry
}

func NewGnpCache(ds datastore.ClientSet) *GnpCache {
	// Setup GNP cache
	return &GnpCache{datastore: ds}
}

// entriesFromDatastore queries the datastore for the current set of global network policies,
// converts them to the appropriate cache entries, and returns them.
func (c *GnpCache) entriesFromDatastore() (map[string]gnpCacheEntry, error) {
	entries := make(map[string]gnpCacheEntry)

	// XXX: Avoid reading config again.
	cfg, _ := config.LoadConfig()
	selector := fmt.Sprintf("projectcalico.org/tier = %s", cfg.TSTierPrefix)

	// Query all GNPs matching given tier-name.
	gnps, err := c.datastore.GlobalNetworkPolicies().List(context.Background(), metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		log.Error("error getting GNPs")
		return nil, err
	}

	for _, gnp := range gnps.Items {
		// Overwrite meta information for appropriate comparison.
		gnp.TypeMeta = metav1.TypeMeta{}
		gnp.ObjectMeta = metav1.ObjectMeta{Name: gnp.Name}
		e := gnpCacheEntry{
			value: gnp,
		}
		entries[gnp.Name] = e
	}

	return entries, nil
}

// Copied from anx-controller:
//
//	syncDatastoreBackoff syncs with the datastore and populates the cache with
//	entries, retrying with an exponential backoff.
func (c *GnpCache) SyncDatastoreBackoff() {
	b := &backoff.Backoff{
		Min:    1 * time.Second,
		Max:    60 * time.Second,
		Factor: 2,
	}

	entries, err := c.entriesFromDatastore()
	for err != nil {
		d := b.Duration()
		log.WithError(err).Errorf("Failed to sync with datastore, retry in %s", d)
		time.Sleep(d)
		entries, err = c.entriesFromDatastore()
	}

	c.cache = entries
}

func (c *GnpCache) PolicyNotChanged(name string, read any) bool {
	return cmp.Equal(c.cache[name].value, read)
}
