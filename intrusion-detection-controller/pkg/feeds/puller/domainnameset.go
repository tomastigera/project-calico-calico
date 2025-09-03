// Copyright 2019 Tigera Inc. All rights reserved.

package puller

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	calico "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"golang.org/x/net/idna"
	core "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/controller"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/utils"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
)

var (
	redundantDots = regexp.MustCompile(`\.\.+`)

	idnaProfile = idna.New()
)

type dnSetHandler struct {
	parser          parser
	database        storage.DomainNameSet
	dnSetController controller.Controller
	gnsEnabled      bool
}

func (d dnSetHandler) snapshot(r io.Reader) (interface{}, error) {
	var snapshot storage.DomainNameSetSpec

	// line handler
	h := func(n int, entry string) {
		if len(entry) == 0 {
			return
		}
		entry = canonicalizeDNSName(entry)
		// We could check here whether the entry represents a valid domain name, but we won't
		// because although a properly configured DNS server will not successfully resolve an
		// invalid name, that doesn't stop an attacker from actually querying for an invalid name.
		// For example, the attacker could direct the query to a DNS server under their control and
		// we want to be able to detect such an action.
		snapshot = append(snapshot, entry)
	}

	err := d.parser(r, h)
	return snapshot, err
}

func (p dnSetHandler) lastModified(ctx context.Context, name string) (time.Time, error) {
	return p.database.GetDomainNameSetModified(ctx, name)
}

func (p dnSetHandler) updateDataStore(ctx context.Context, name string, snapshot interface{}, f func(error), feedCacher cacher.GlobalThreatFeedCacher) {
	p.dnSetController.Add(ctx, name, snapshot.(storage.DomainNameSetSpec), f, feedCacher)
}

func (d dnSetHandler) handleSnapshot(ctx context.Context, snapshot interface{}, feedCacher cacher.GlobalThreatFeedCacher, f SyncFailFunction) {
	if d.gnsEnabled {
		utils.AddErrorToFeedStatus(feedCacher, cacher.GlobalNetworkSetSyncFailed, errors.New("[Global Threat Feeds] sync not supported for domain name set"))
	} else {
		utils.ClearErrorFromFeedStatus(feedCacher, cacher.GlobalNetworkSetSyncFailed)
	}
}

func (d dnSetHandler) syncFromDB(ctx context.Context, feedCacher cacher.GlobalThreatFeedCacher) {
	if d.gnsEnabled {
		utils.AddErrorToFeedStatus(feedCacher, cacher.GlobalNetworkSetSyncFailed, errors.New("[Global Threat Feeds] sync not supported for domain name set"))
	} else {
		utils.ClearErrorFromFeedStatus(feedCacher, cacher.GlobalNetworkSetSyncFailed)
	}
}

func NewDomainNameSetHTTPPuller(
	f *calico.GlobalThreatFeed,
	ddb storage.DomainNameSet,
	configMapClient core.ConfigMapInterface,
	secretsClient core.SecretInterface,
	client *http.Client,
	e controller.Controller,
) Puller {

	dn := dnSetHandler{
		parser:          getParserForFormat(f.Spec.Pull.HTTP.Format),
		database:        ddb,
		dnSetController: e,
	}

	if f.Spec.GlobalNetworkSet != nil {
		dn.gnsEnabled = true
	}
	p := NewHttpPuller(configMapClient, secretsClient, client, f.DeepCopy(), true, dn)

	return p
}

func canonicalizeDNSName(name string) string {
	uname, err := idnaProfile.ToUnicode(name)
	if err != nil {
		return redundantDots.ReplaceAllString(strings.ToLower(strings.Trim(name, ".")), ".")
	}
	return redundantDots.ReplaceAllString(strings.ToLower(strings.Trim(uname, ".")), ".")
}
