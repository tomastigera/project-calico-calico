// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"net"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/cachingmap"
)

func init() {
	// Alpha since 1.21 Beta since 1.22 default true - no harm in supporting it by default.
	_ = utilfeature.DefaultMutableFeatureGate.Set("ServiceInternalTrafficPolicy=true")
}

// KubeProxy is a wrapper of Proxy that deals with higher level issue like
// configuration, restarting etc.
type KubeProxy struct {
	proxy  Proxy
	syncer DPSyncer

	ipFamily      int
	hostIPUpdates chan []net.IP
	stopOnce      sync.Once
	lock          sync.RWMutex
	exiting       chan struct{}
	wg            sync.WaitGroup

	k8s         kubernetes.Interface
	hostname    string
	frontendMap maps.MapWithExistsCheck
	backendMap  maps.MapWithExistsCheck
	affinityMap maps.Map
	ctMap       maps.Map
	rt          *RTCache
	opts        []Option

	dsrEnabled bool
}

// StartKubeProxy start a new kube-proxy if there was no error
func StartKubeProxy(k8s kubernetes.Interface, hostname string,
	bpfMaps *bpfmap.Maps, opts ...Option) (*KubeProxy, error) {

	kp := &KubeProxy{
		k8s:         k8s,
		ipFamily:    4,
		hostname:    hostname,
		frontendMap: bpfMaps.FrontendMap.(maps.MapWithExistsCheck),
		backendMap:  bpfMaps.BackendMap.(maps.MapWithExistsCheck),
		affinityMap: bpfMaps.AffinityMap,
		ctMap:       bpfMaps.CtMap,
		opts:        opts,
		rt:          NewRTCache(),

		hostIPUpdates: make(chan []net.IP, 1),
		exiting:       make(chan struct{}),
	}

	for _, o := range opts {
		if err := o(kp); err != nil {
			return nil, errors.WithMessage(err, "applying option to kube-proxy")
		}
	}

	go func() {
		err := kp.start()
		if err != nil {
			log.WithError(err).Panic("kube-proxy failed to start")
		}
	}()

	return kp, nil
}

func (kp *KubeProxy) setIpFamily(ipFamily int) {
	kp.ipFamily = ipFamily
}

// Stop stops KubeProxy and waits for it to exit
func (kp *KubeProxy) Stop() {
	kp.stopOnce.Do(func() {
		kp.lock.Lock()
		defer kp.lock.Unlock()

		close(kp.exiting)
		close(kp.hostIPUpdates)
		kp.proxy.Stop()
		kp.wg.Wait()
	})
}

func (kp *KubeProxy) run(hostIPs []net.IP) error {

	kp.lock.Lock()
	defer kp.lock.Unlock()

	withLocalNP := make([]net.IP, len(hostIPs), len(hostIPs)+1)
	copy(withLocalNP, hostIPs)
	withLocalNP = append(withLocalNP, podNPIP)

	var syncer DPSyncer

	if kp.ipFamily == 4 {
		feCache := cachingmap.New[nat.FrontendKeyInterface, nat.FrontendValue](nat.FrontendMapParameters.Name,
			maps.NewTypedMap[nat.FrontendKeyInterface, nat.FrontendValue](
				kp.frontendMap, nat.FrontendKeyFromBytes, nat.FrontendValueFromBytes,
			))
		beCache := cachingmap.New[nat.BackendKey, nat.BackendValueInterface](nat.BackendMapParameters.Name,
			maps.NewTypedMap[nat.BackendKey, nat.BackendValueInterface](
				kp.backendMap, nat.BackendKeyFromBytes, nat.BackendValueFromBytes,
			))

		var err error
		syncer, err = NewSyncer(
			withLocalNP, feCache, beCache, kp.affinityMap, kp.rt,
			nat.NewNATKeyIntf, nat.NewNATKeySrcIntf, nat.NewNATBackendValueIntf,
			nat.AffinityKeyIntfFromBytes, nat.AffinityValueIntfFromBytes)
		if err != nil {
			return errors.WithMessage(err, "new bpf syncer")
		}
	} else {
		feCache := cachingmap.New[nat.FrontendKeyInterface, nat.FrontendValue](nat.FrontendMapParameters.Name,
			maps.NewTypedMap[nat.FrontendKeyInterface, nat.FrontendValue](
				kp.frontendMap, nat.FrontendKeyV6FromBytes, nat.FrontendValueFromBytes,
			))
		beCache := cachingmap.New[nat.BackendKey, nat.BackendValueInterface](nat.BackendMapParameters.Name,
			maps.NewTypedMap[nat.BackendKey, nat.BackendValueInterface](
				kp.backendMap, nat.BackendKeyFromBytes, nat.BackendValueV6FromBytes,
			))

		var err error
		syncer, err = NewSyncer(
			withLocalNP, feCache, beCache, kp.affinityMap, kp.rt,
			nat.NewNATKeyV6Intf, nat.NewNATKeyV6SrcIntf,
			nat.NewNATBackendValueV6Intf, nat.AffinityKeyV6IntfFromBytes, nat.AffinityValueV6IntfFromBytes)
		if err != nil {
			return errors.WithMessage(err, "new bpf syncer")
		}
	}

	proxy, err := New(kp.k8s, syncer, kp.hostname, kp.opts...)
	if err != nil {
		return errors.WithMessage(err, "new proxy")
	}

	log.Infof("kube-proxy started, hostname=%q hostIPs=%+v", kp.hostname, hostIPs)

	kp.proxy = proxy
	kp.syncer = syncer

	return nil
}

func (kp *KubeProxy) start() error {

	// wait for the initial update
	hostIPs := <-kp.hostIPUpdates

	err := kp.run(hostIPs)
	if err != nil {
		return err
	}

	kp.wg.Add(1)
	go func() {
		defer kp.wg.Done()
		for {
			hostIPs, ok := <-kp.hostIPUpdates
			if !ok {
				defer log.Error("kube-proxy stopped since hostIPUpdates closed")
				kp.proxy.Stop()
				return
			}

			stopped := make(chan struct{})

			go func() {
				defer close(stopped)
				defer log.Info("kube-proxy stopped to restart with updated host IPs")
				kp.proxy.Stop()
			}()

		waitforstop:
			for {
				select {
				case hostIPs, ok = <-kp.hostIPUpdates:
					if !ok {
						log.Error("kube-proxy: hostIPUpdates closed")
						return
					}
				case <-kp.exiting:
					log.Info("kube-proxy: exiting")
					return
				case <-stopped:
					err = kp.run(hostIPs)
					if err != nil {
						log.Panic("kube-proxy failed to start after host IPs update")
					}
					break waitforstop
				}
			}
		}
	}()

	return nil
}

// OnHostIPsUpdate should be used by an external user to update the proxy's list
// of host IPs
func (kp *KubeProxy) OnHostIPsUpdate(IPs []net.IP) {
	select {
	case kp.hostIPUpdates <- IPs:
		// nothing
	default:
		// in case we would block, drop the now stale update and replace it
		// with a new one. Do it non-blocking way in case it was just consumed.
		select {
		case <-kp.hostIPUpdates:
		default:
		}
		kp.hostIPUpdates <- IPs
	}
	log.Debugf("kube-proxy OnHostIPsUpdate: %+v", IPs)
}

// OnRouteUpdate should be used to update the internal state of routing tables
func (kp *KubeProxy) OnRouteUpdate(k routes.KeyInterface, v routes.ValueInterface) {
	kp.rt.Update(k, v)
	log.WithFields(log.Fields{"key": k, "value": v}).Debug("kube-proxy: OnRouteUpdate")
}

// OnRouteDelete should be used to update the internal state of routing tables
func (kp *KubeProxy) OnRouteDelete(k routes.KeyInterface) {
	kp.rt.Delete(k)
	log.WithField("key", k).Debug("kube-proxy: OnRouteDelete")
}

// ConntrackScanStart to satisfy conntrack.NATChecker - forwards to syncer.
func (kp *KubeProxy) ConntrackScanStart() {
	kp.lock.RLock()
	if kp.syncer != nil {
		kp.syncer.ConntrackScanStart()
	}
}

// ConntrackScanEnd to satisfy conntrack.NATChecker - forwards to syncer.
func (kp *KubeProxy) ConntrackScanEnd() {
	if kp.syncer != nil {
		kp.syncer.ConntrackScanEnd()
	}
	kp.lock.RUnlock()
}

// ConntrackFrontendHasBackend to satisfy conntrack.NATChecker - forwards to syncer.
func (kp *KubeProxy) ConntrackFrontendHasBackend(ip net.IP, port uint16, backendIP net.IP,
	backendPort uint16, proto uint8) bool {

	// Thanks to holding the lock since ConntrackScanStart, this condition holds for the
	// whole iteration. So if we started without syncer, we willalso finish without it.
	// And if we had a syncer, we will have the same until the end.
	if kp.syncer != nil {
		return kp.syncer.ConntrackFrontendHasBackend(ip, port, backendIP, backendPort, proto)
	}

	// We cannot say yet, so do not break anything
	return true
}
