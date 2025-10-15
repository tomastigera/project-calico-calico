// Package data is responsible for aggregating Felix updates, and ensuring
// that the consumers of the data receive it only when it is safe. This
// is done using *roughly* the observer pattern.
package data

import (
	"context"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	protoutil "github.com/projectcalico/calico/egress-gateway/util/proto"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

// RouteObserver allows a module to be notified of updates regarding routes
type RouteObserver interface {
	// NotifyResync notifies an observer of a full datastore refresh
	NotifyResync(RouteStore)
}

// RouteStore encapsulates data access with a Subscriber-based API
type RouteStore interface {
	// Routes returns all data aggregated by the store, grouped by node where relevant
	Routes() (
		thisWorkload *proto.RouteUpdate,
		workloadsByNodeName map[string][]*proto.RouteUpdate,
		tunnelsByNodeName map[string][]*proto.RouteUpdate,
	)
	// Subscribe allows Observers to subscribe to store updates
	Subscribe(RouteObserver)
}

// routeStore stores all information needed to program the Egress Gateway's return routes to workloads
type routeStore struct {
	healthAgg      *health.HealthAggregator
	healthInterval time.Duration

	// will be notified of updates
	observers []RouteObserver

	// RWMutex should be used when reading/writing store data
	sync.RWMutex

	// RouteUpdates describing workloads on other nodes (local workloads do not require tunneling and should use default routing)
	remoteWorkloadUpdatesByDst map[string]*proto.RouteUpdate

	// RouteUpdates describing host-ns tunnel devices per-node. It's important we recongise these IP's as they may
	// be used instead of a node's default IP by outbound egress packets.
	tunnelUpdatesByDst map[string]*proto.RouteUpdate

	// the latest RouteUpdate describing this gateway - can contain information about what encap is being used for the gateway's ippool
	latestGatewayUpdate *proto.RouteUpdate

	// this gateway's own IP
	gatewayIP net.IP

	// observers of this store will not be notified of updates until the store is inSync
	inSync bool

	// getUpdatesPipeline is a means of getting a new updates pipeline if one is closed for any reason
	getUpdatesPipeline func() <-chan *proto.ToDataplane
}

// NewRouteStore instantiates a new store for route updates
const healthName = "DatastoreConnection"

func NewRouteStore(getUpdatesPipeline func() <-chan *proto.ToDataplane, egressPodIP net.IP, healthAgg *health.HealthAggregator, healthTimeout time.Duration) *routeStore {
	healthAgg.RegisterReporter(healthName, &health.HealthReport{Ready: true}, healthTimeout)
	healthAgg.Report(healthName, &health.HealthReport{Ready: false})
	return &routeStore{
		observers:                  make([]RouteObserver, 0),
		RWMutex:                    sync.RWMutex{},
		remoteWorkloadUpdatesByDst: make(map[string]*proto.RouteUpdate),
		tunnelUpdatesByDst:         make(map[string]*proto.RouteUpdate),
		gatewayIP:                  egressPodIP,
		inSync:                     false,
		getUpdatesPipeline:         getUpdatesPipeline,
		healthAgg:                  healthAgg,
		healthInterval:             healthTimeout / 10,
	}
}

// Routes returns all data aggregated by the store, grouped by node where relevant
func (s *routeStore) Routes() (
	thisWorkload *proto.RouteUpdate,
	workloadsByNodeName map[string][]*proto.RouteUpdate,
	tunnelsByNodeName map[string][]*proto.RouteUpdate,
) {
	workloadsByNodeName = make(map[string][]*proto.RouteUpdate)
	tunnelsByNodeName = make(map[string][]*proto.RouteUpdate)
	s.read(func(s *routeStore) {
		// group all remote workloads
		for _, workload := range s.remoteWorkloadUpdatesByDst {
			nodeName := workload.DstNodeName
			if _, ok := workloadsByNodeName[nodeName]; !ok {
				workloadsByNodeName[nodeName] = make([]*proto.RouteUpdate, 0)
			}
			workloadsByNodeName[nodeName] = append(workloadsByNodeName[nodeName], workload)
		}

		// group all tunnels
		for _, tunnel := range s.tunnelUpdatesByDst {
			nodeName := tunnel.DstNodeName
			if _, ok := tunnelsByNodeName[nodeName]; !ok {
				tunnelsByNodeName[nodeName] = make([]*proto.RouteUpdate, 0)
			}
			tunnelsByNodeName[nodeName] = append(tunnelsByNodeName[nodeName], tunnel)
		}

		thisWorkload = s.latestGatewayUpdate
	})
	return thisWorkload, workloadsByNodeName, tunnelsByNodeName
}

// Subscribe allows datastore consumers to subscribe to store updates
func (s *routeStore) Subscribe(o RouteObserver) {
	s.observers = append(s.observers, o)
}

// SyncForever aggregates payloads from the sync client into safe, condensed 'notifications' for store observers to program
func (s *routeStore) SyncForever(ctx context.Context) {
	s.inSync = false
	updates := s.getUpdatesPipeline()

	healthTicker := time.NewTicker(s.healthInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-healthTicker.C:
			if s.inSync {
				s.healthAgg.Report(healthName, &health.HealthReport{Ready: true})
			}
		case update, ok := <-updates:
			if !ok {
				// if the updates pipeline closes, get a fresh pipeline and start resyncing from scratch
				log.Debug("updates channel closed by upstream, fetching new channel...")
				updates = s.getUpdatesPipeline()
				s.inSync = false
				s.clear()
			} else if update != nil {
				// begin parsing pipeline updates
				log.WithField("update", update).Debug("parsing new update from upstream...")

				switch payload := update.Payload.(type) {
				case *proto.ToDataplane_RouteUpdate:
					ru := payload.RouteUpdate
					if protoutil.IsHostTunnel(ru) {
						log.Debugf("received RouteUpdate for host tunnel: %+v", ru)
						s.write(func(rs *routeStore) {
							rs.tunnelUpdatesByDst[ru.Dst] = ru
						})
						s.maybeNotifyResync()
					} else if protoutil.IsRouteType(ru, proto.RouteType_LOCAL_WORKLOAD) {
						// we only care about local workloads describing this gateway, check if that's what we have
						_, dstCIDR, err := net.ParseCIDR(ru.Dst)
						if err != nil {
							log.WithError(err).Warnf("could not parse dst CIDR of RouteUpdate: %+v", ru)
							continue
						} else {
							if dstCIDR.Contains(s.gatewayIP) {
								log.Debugf("received RouteUpdate describing this gateway: %+v", ru)
								s.write(func(rs *routeStore) {
									rs.latestGatewayUpdate = ru
								})
								s.maybeNotifyResync()
							}
						}
					} else if protoutil.IsRouteType(ru, proto.RouteType_REMOTE_WORKLOAD) {
						log.Debugf("received RouteUpdate for a remote workload: %+v", ru)
						s.write(func(rs *routeStore) {
							rs.remoteWorkloadUpdatesByDst[ru.Dst] = ru
							s.maybeNotifyResync()
						})
					}

				case *proto.ToDataplane_RouteRemove:
					log.Debugf("received RouteRemove: %+v", update.Payload.(*proto.ToDataplane_RouteRemove))

					rm := payload.RouteRemove
					s.write(func(rs *routeStore) {
						delete(rs.remoteWorkloadUpdatesByDst, rm.Dst)
						delete(rs.tunnelUpdatesByDst, rm.Dst)
					})
					s.maybeNotifyResync()

				case *proto.ToDataplane_InSync:
					log.Debugf("received InSync, notifying observers...")
					// After receiving an `inSync`, all future updates over this channel will immediately notify observers
					s.inSync = true
					s.maybeNotifyResync()
				default:
					log.Debugf("Unexpected update received: %+v", update)
				}
				if s.inSync {
					s.healthAgg.Report(healthName, &health.HealthReport{Ready: true})
				}
			}
		}
	}
}

// write allows for thread-safe writes to the store via a write-callback
func (s *routeStore) write(writeFn func(*routeStore)) {
	log.Debug("Acquiring write lock for egress-gateway store")
	s.Lock()
	defer func() {
		s.Unlock()
		log.Debug("Released write lock for egress-gateway store")
	}()
	log.Debug("Acquired write lock for egress-gateway store")
	writeFn(s)
}

// read allows for thread-safe reads from the store via a read-callback
func (s *routeStore) read(readFn func(*routeStore)) {
	log.Debug("Acquiring read lock for the datastore")
	s.RLock()
	defer func() {
		s.RUnlock()
		log.Debug("Released read lock for the datastore")
	}()
	log.Debug("Acquired read lock for the datastore")
	readFn(s)
}

// clear drops all data in the routeStore
func (s *routeStore) clear() {
	s.write(func(rs *routeStore) {
		rs.remoteWorkloadUpdatesByDst = make(map[string]*proto.RouteUpdate)
		rs.tunnelUpdatesByDst = make(map[string]*proto.RouteUpdate)
		rs.latestGatewayUpdate = nil
	})
}

// notify datastore Observers of a full resync
func (s *routeStore) maybeNotifyResync() {
	if s.inSync {
		for _, o := range s.observers {
			// use a goroutine so as not to be blocked by potentially long downstream operations
			go o.NotifyResync(s)
		}
	}
}
