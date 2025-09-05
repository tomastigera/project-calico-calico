// Copyright 2019 Tigera Inc. All rights reserved.

package puller

import (
	"context"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	calico "github.com/tigera/api/pkg/apis/projectcalico/v3"
	core "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/controller"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/sync/globalnetworksets"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/utils"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/util"
)

var wrappedInBracketsRegexp = regexp.MustCompile(`^\[.*\]$`)

type ipSetHandler struct {
	database        storage.IPSet
	ipSetController controller.Controller
	name            string
	gnsLabels       map[string]string
	gnsEnabled      bool
	gnsController   globalnetworksets.Controller
	gtfParser       parser
}

func (i ipSetHandler) snapshot(r io.Reader) (interface{}, error) {
	var snapshot storage.IPSetSpec
	var once sync.Once

	// entry handler
	h := func(n int, entry string) {
		snapshot = append(snapshot, parseIP(entry, log.WithField("name", i.name), n, &once)...)
	}

	err := i.gtfParser(r, h)
	return snapshot, err
}

func parseIP(entry string, logContext *log.Entry, n int, once *sync.Once) storage.IPSetSpec {
	if wrappedInBracketsRegexp.MatchString(entry) {
		entry = entry[1 : len(entry)-1]
	}
	if strings.Contains(entry, "/") {
		// filter invalid IP addresses, dropping warning
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			once.Do(func() {
				logContext.WithError(err).WithFields(log.Fields{
					"entry_num": n,
					"entry":     entry,
				}).Warn("[Global Threat Feeds] could not parse IP network")
			})
			return nil
		} else {
			return storage.IPSetSpec{ipNet.String()}
		}
	} else {
		ip := net.ParseIP(entry)
		if ip == nil {
			once.Do(func() {
				log.WithFields(log.Fields{
					"entry_num": n,
					"entry":     entry,
				}).Warn("[Global Threat Feeds] could not parse IP address")
			})
			return nil
		} else {
			// Elastic ip_range requires all addresses to be in CIDR notation
			var ipStr string
			if len(ip.To4()) == net.IPv4len {
				ipStr = ip.String() + "/32"
			} else {
				ipStr = ip.String() + "/128"
			}
			return storage.IPSetSpec{ipStr}
		}
	}
}

func (i ipSetHandler) lastModified(ctx context.Context, name string) (time.Time, error) {
	return i.database.GetIPSetModified(ctx, name)
}

func (i ipSetHandler) updateDataStore(ctx context.Context, name string, snapshot interface{}, f func(error), feedCacher cacher.GlobalThreatFeedCacher) {
	i.ipSetController.Add(ctx, name, snapshot.(storage.IPSetSpec), f, feedCacher)
}

func (h ipSetHandler) getIPSet(ctx context.Context) (interface{}, error) {
	return h.database.GetIPSet(ctx, h.name)
}

func (h ipSetHandler) syncFromDB(ctx context.Context, feedCacher cacher.GlobalThreatFeedCacher) {
	if h.gnsEnabled {
		log.WithField("feed", h.name).Infof("[Global Threat Feeds] synchronizing GlobalNetworkSet from cached feed %v contents", feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name)
		ipSet, err := h.getIPSet(ctx)
		if err != nil {
			log.WithError(err).WithField("feed", h.name).Errorf("[Global Threat Feeds] failed to load cached feed %v contents", feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name)
			utils.AddErrorToFeedStatus(feedCacher, cacher.GlobalNetworkSetSyncFailed, err)
		} else {
			g := h.makeGNS(ipSet)
			h.gnsController.Add(g, func(error) {}, feedCacher)
		}
	} else {
		utils.ClearErrorFromFeedStatus(feedCacher, cacher.GlobalNetworkSetSyncFailed)
	}
}

func (h *ipSetHandler) makeGNS(snapshot interface{}) *calico.GlobalNetworkSet {
	nets := snapshot.(storage.IPSetSpec)
	gns := util.NewGlobalNetworkSet(h.name)
	gns.Labels = make(map[string]string)
	for k, v := range h.gnsLabels {
		gns.Labels[k] = v
	}
	gns.Spec.Nets = append([]string{}, nets...)
	return gns
}

func (h ipSetHandler) handleSnapshot(ctx context.Context, snapshot interface{}, feedCacher cacher.GlobalThreatFeedCacher, f SyncFailFunction) {
	if h.gnsEnabled {
		g := h.makeGNS(snapshot)
		h.gnsController.Add(g, f, feedCacher)
	} else {
		utils.ClearErrorFromFeedStatus(feedCacher, cacher.GlobalNetworkSetSyncFailed)
	}
}

func NewIPSetHTTPPuller(
	f *calico.GlobalThreatFeed,
	ipSet storage.IPSet,
	configMapClient core.ConfigMapInterface,
	secretsClient core.SecretInterface,
	client *http.Client,
	gnsController globalnetworksets.Controller,
	controllerIPSet controller.Controller,
) Puller {

	ip := ipSetHandler{
		database:        ipSet,
		name:            f.Name,
		gtfParser:       getParserForFormat(f.Spec.Pull.HTTP.Format),
		gnsController:   gnsController,
		ipSetController: controllerIPSet,
	}

	if f.Spec.GlobalNetworkSet != nil {
		ip.gnsEnabled = true
		ip.gnsLabels = make(map[string]string)
		for k, v := range f.Spec.GlobalNetworkSet.Labels {
			ip.gnsLabels[k] = v
		}
	}

	p := NewHttpPuller(configMapClient, secretsClient, client, f.DeepCopy(), true, ip)

	return p
}
