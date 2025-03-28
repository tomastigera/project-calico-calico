// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package earlynetworking

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	BIRD_CONFIG_FILE = "/etc/calico/confd/config/bird.cfg"
	BIRD_CONFIG_MAIN = `
router id %s;
listen bgp port 8179;

protocol direct {
    interface "*";
}

protocol kernel {
    learn;            # Learn all alien routes from the kernel
    scan time 5;      # Scan kernel routing table every 5 seconds
    import all;       # Default is import all
    export all;       # Default is export none
    merge paths on;
}

# This pseudo-protocol watches all interface up/down events.
protocol device {
    scan time 5;      # Scan interfaces every 5 seconds
}

filter stable_address_only {
  if ( net = %v/32 ) then { accept; }
  reject;
}

template bgp tors {
  description "Connection to ToR";
  local as %v;
  direct;
  gateway recursive;
  import all;
  export filter stable_address_only;
  add paths on;
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
  next hop self;
}
`
	BIRD_CONFIG_PER_PEER = `
protocol bgp tor%v from tors {
  neighbor %v as %v;
}
`
)

// Run does setup for a dual ToR node, then runs as the "early BGP" daemon
// until calico-node's BIRD can take over.
func Run() {
	logrus.Info("Beginning dual ToR setup for this node")

	// There must be a YAML file mapped in at $CALICO_EARLY_NETWORKING that defines addresses
	// and AS numbers for the nodes in this cluster.  Read that file.
	cfg, err := GetEarlyNetworkConfig(os.Getenv("CALICO_EARLY_NETWORKING"))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to read EarlyNetworkConfiguration")
	}

	// Find a per-interface address we can use as our BIRD router ID.
	// We will also use this to identify this node in the overall YAML config.
	var thisNode *ConfigNode
	var routerID string

	thisNode, routerID = mustDetectNodeConfig(cfg)
	logrus.WithField("cfg", *thisNode).Info("Found config for this node")

	// Configure the stable address.
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get loopback interface")
	}
	_, cidr, err := net.ParseCIDR(thisNode.StableAddress.Address + "/32")
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to parse stable address CIDR %v/32", thisNode.StableAddress.Address)
	}
	err = netlink.AddrAdd(loopback, &netlink.Addr{IPNet: cidr})
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "exists") {
			logrus.WithError(err).Fatalf("Failed to add stable address %v/32 to loopback device", thisNode.StableAddress.Address)
		}
	}

	var bootstrapIPs []string
	if strings.ToLower(cfg.Spec.Platform) == PlatformOpenShift {
		// Look up the IP of the bootstrap node.  On nodes that are directly connected to
		// the bootstrap node, we want to create a specific route to ensure that we will use
		// our stable address as the source.
		bootstrapIPs, err = net.LookupHost("bootstrap")
		logrus.WithError(err).Infof("DNS lookup for bootstrap node returned %v", bootstrapIPs)
	}

	// Change interface-specific addresses to be scope link, and create specific routes where
	// directly connected to a bootstrap IP.
	ensureNodeAddressesAndRoutes(thisNode, bootstrapIPs, cfg.Spec.Legacy.UnconditionalDefaultRouteProgramming)

	// Use multiple ECMP paths based on hashing 5-tuple.  These are not necessarily fatal, if
	// setting fails.
	err = writeProcSys("/proc/sys/net/ipv4/fib_multipath_hash_policy", "1")
	if err != nil {
		logrus.WithError(err).Warning("Failed to set fib_multipath_hash_policy")
	}
	err = writeProcSys("/proc/sys/net/ipv4/fib_multipath_use_neigh", "1")
	if err != nil {
		logrus.WithError(err).Warning("Failed to set fib_multipath_use_neigh")
	}

	// Generate BIRD config.
	birdConfig := fmt.Sprintf(BIRD_CONFIG_MAIN, routerID, thisNode.StableAddress.Address, thisNode.ASNumber)
	for index, peering := range thisNode.Peerings {
		peerAS := peering.PeerASNumber
		if peerAS == 0 {
			// Default to same AS number as this node.
			peerAS = thisNode.ASNumber
		}
		birdConfig = birdConfig + fmt.Sprintf(BIRD_CONFIG_PER_PEER, index+1, peering.PeerIP, peerAS)
	}
	err = os.WriteFile(BIRD_CONFIG_FILE, []byte(birdConfig), 0644)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to write BIRD config at %v", BIRD_CONFIG_FILE)
	}

	// Start BIRD and check its status - e.g. in case we've generated invalid config.
	out, err := exec.Command("sv", "-w", "2", "start", "bird").CombinedOutput()
	if err != nil {
		logrus.WithError(err).Fatalf("Failed sv start bird:\n%v", string(out))
	}
	logrus.Infof("sv start bird:\n%v", string(out))

	// Loop deciding whether to run early BIRD or not.
	logrus.Info("Early networking set up; now monitoring BIRD")
	monitorOngoing(thisNode, cfg.Spec.Legacy.UnconditionalDefaultRouteProgramming)
}

func mustDetectNodeConfig(cfg *EarlyNetworkConfiguration) (nodeConfig *ConfigNode, routerID string) {
	if cfg.Spec.Legacy.NodeIPFromDefaultRoute {
		// Legacy behavior: searching routes for their source addrs to identify this node.
		routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to list routes")
		}
	routeSearch:
		for _, route := range routes {
			if isDefaultCIDR(route.Dst) {
				logrus.Infof("Got default route %+v", route)
				if route.Src != nil {
					logrus.Infof("Default route has source address %v", route.Src)
					routerID = route.Src.String()
					break routeSearch
				} else if route.Gw != nil {
					logrus.Infof("Default route has gateway address %v", route.Gw)
					// Look up routes to the gateway address.
					routes, err = netlink.RouteGet(route.Gw)
					if err != nil {
						logrus.WithError(err).Fatal("Failed to get routes to gateway address")
					}
					for _, route = range routes {
						logrus.Infof("Got gateway address route %+v", route)
						if route.Src != nil {
							routerID = route.Src.String()
							break routeSearch
						}
					}
				}
			}
			logrus.Infof("Skip other route %+v", route)
		}

		if routerID == "" {
			logrus.Fatal("Failed to find default route with source address")
		}
		logrus.Infof("Router ID is %s", routerID)

		// Find the entry from the YAML config for this node.
	nodeLoop:
		for _, nodeCfg := range cfg.Spec.Nodes {
			for _, addr := range nodeCfg.InterfaceAddresses {
				if addr == routerID {
					nodeConfig = &nodeCfg
					break nodeLoop
				}
			}
		}

		if nodeConfig == nil {
			logrus.WithField("routerID", routerID).Fatal("Could not find node config for routerID")
		}

	} else {
		// First try to list all links' addresses, and correlate them to config addresses.
		ips, err := enumerateAllIPs()
		if err != nil {
			logrus.WithError(err).Fatal("Couldn't auto-detect IP")
		}

		for _, ip := range ips {
			for _, nodeCfg := range cfg.Spec.Nodes {
				for _, cfgAddr := range nodeCfg.InterfaceAddresses {
					if ip == cfgAddr {
						logrus.Infof("This node's router ID is %s", ip)
						logrus.WithField("nodeCfg", nodeCfg).Info("Config for this node")
						nodeConfig = &nodeCfg
						routerID = ip
						return
					}
				}
			}
		}

		logrus.Fatal("Could not find any IP address in common between network links and EarlyNetworkConfig interfaceAddresses")
	}

	return
}

func isDefaultCIDR(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	if ones, _ := dst.Mask.Size(); ones == 0 {
		return true
	}
	return false
}

func monitorOngoing(thisNode *ConfigNode, forceDefaultRoutes bool) {
	// Channel used to signal when early BIRD is wanted, based on the state of normal BIRD.
	earlyBirdWantedC := make(chan bool)
	go monitorNormalBird(earlyBirdWantedC)

	periodicCheckC := time.NewTicker(10 * time.Second).C
	earlyBirdRunning := true
	var (
		earlyBirdCheckTicker  *time.Ticker
		earlyBirdCheckC       <-chan time.Time
		earlyBirdCheckRetries int
	)
	startCheckingEarlyBird := func() {
		earlyBirdCheckTicker = time.NewTicker(300 * time.Millisecond)
		earlyBirdCheckC = earlyBirdCheckTicker.C
		earlyBirdCheckRetries = 10
	}
	stopCheckingEarlyBird := func() {
		earlyBirdCheckTicker.Stop()
		earlyBirdCheckC = nil
	}
	startCheckingEarlyBird()
	for {
		select {
		case earlyBirdWanted := <-earlyBirdWantedC:
			if earlyBirdWanted && !earlyBirdRunning {
				logrus.Info("Restart early BGP")
				err := exec.Command("sv", "up", "bird").Run()
				if err != nil {
					logrus.WithError(err).Fatal("Failed sv up bird")
				}
				earlyBirdRunning = true
				startCheckingEarlyBird()
			} else if earlyBirdRunning && !earlyBirdWanted {
				logrus.Info("Stop early BGP")
				err := exec.Command("sv", "down", "bird").Run()
				if err != nil {
					logrus.WithError(err).Fatal("Failed sv down bird")
				}
				earlyBirdRunning = false
				stopCheckingEarlyBird()
			}
		case <-earlyBirdCheckC:
			if earlyBirdRunning {
				// Early BIRD should be running.  Check that it really is.
				if earlyBGPRunning() {
					logrus.Info("Early BGP is really running")
					stopCheckingEarlyBird()
					// We're good, and don't need to keep checking until earlyBirdWanted changes.
				} else {
					earlyBirdCheckRetries -= 1
					if earlyBirdCheckRetries > 0 {
						logrus.Infof("Early BGP not really running yet (retries=%v)", earlyBirdCheckRetries)
						// We'll check again when earlyBirdCheckC fires again.
					} else {
						logrus.Fatal("Early BGP failed to start running")
						// Bail out, then the calico-node early container will retry.
					}
				}
			} else {
				logrus.Info("Early BIRD shouldn't be running, so stop checking for it")
				stopCheckingEarlyBird()
				// We're good, and don't need to keep checking until earlyBirdWanted changes.
			}
		case <-periodicCheckC:
			// Recheck interface addresses and routes.
			ensureNodeAddressesAndRoutes(thisNode, nil, forceDefaultRoutes)
		}
	}
}

func monitorNormalBird(earlyBirdWantedC chan<- bool) {
	periodicCheckC := time.NewTicker(10 * time.Second).C
	var gracefulTimeoutC <-chan time.Time
	normalBirdRunningRecorded := false
	for {
		select {
		case <-periodicCheckC:
			nowRunning := normalBGPRunning()
			if nowRunning {
				// Normal BIRD is up.
				if normalBirdRunningRecorded {
					// Was running, and still is: no change.
				} else if gracefulTimeoutC != nil {
					logrus.Info("Normal BGP restarted within graceful restart period")
					gracefulTimeoutC = nil
				} else {
					logrus.Info("Normal BGP has (re)started")
					earlyBirdWantedC <- false
				}
				normalBirdRunningRecorded = true
			} else {
				// Normal BIRD is not running.
				if normalBirdRunningRecorded {
					logrus.Info("Normal BGP stopped; wait for graceful restart period")
					gracefulTimeoutC = time.NewTimer(120 * time.Second).C
				}
				// Otherwise we already detected and handled that normal BIRD had
				// stopped.  Either we're now in the graceful restart period - in
				// which case the next event will be the timer firing when that
				// expires - or we're past that and normal BIRD has been stopped for
				// a long time.  Either way, there's no output event that we need to
				// generate right now.
				normalBirdRunningRecorded = false
			}
		case <-gracefulTimeoutC:
			logrus.Info("End of graceful restart period for normal BGP")
			earlyBirdWantedC <- true
			gracefulTimeoutC = nil
		}
	}
}

func ensureNodeAddressesAndRoutes(thisNode *ConfigNode, bootstrapIPs []string, forceDefaultRoutes bool) {
	nl, err := netlink.NewHandle(netlink.FAMILY_V4)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get a netlink handle. Aborting address and route config")
	}
	defer nl.Close()

	// Attempt to set strict check - this allows for route filtering at a lower level, saving some compute resources.
	err = nl.SetStrictCheck(true)
	if err != nil {
		logrus.WithError(err).Warn("Failed to set strict check. Continuing without it...")
	}

	// Analyse existing default routing and make a note of default routes relating to a ToR
	initialDefaultRoutes, err := nl.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to read kernel's initial default routes. Aborting address and route config")
	}

	peerIPToDefaultRoute := make(map[string]netlink.Route)
	for _, r := range initialDefaultRoutes {
		if !isDefaultCIDR(r.Dst) {
			logrus.WithField("route", r).Warn("Found a non-default route while attempting to scan default routes. Ignoring...")
			continue
		}
		for _, p := range thisNode.Peerings {
			if p.PeerIP == r.Gw.String() {
				logrus.WithFields(logrus.Fields{"route": r, "peer": p.PeerIP}).Debug("Found default route for peer")
				peerIPToDefaultRoute[p.PeerIP] = r
			} else {
				for _, nh := range r.MultiPath {
					if nh.Gw.String() == p.PeerIP {
						logrus.WithFields(logrus.Fields{"route": r, "peer": p.PeerIP}).Debug("Found ECMP default route with a nexthop for peer")
						peerIPToDefaultRoute[p.PeerIP] = r
					}
				}
			}
		}
	}

	links, err := netlink.LinkList()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to list all links")
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			logrus.WithError(err).Fatalf("Failed to list addresses for link %+v", link)
		}
		for _, addr := range addrs {
			for _, peering := range thisNode.Peerings {
				if SameSubnet(addr, peering.PeerIP) {
					defaultRt, ok := peerIPToDefaultRoute[peering.PeerIP]
					if !ok {
						ensureLinkAddressAndRoutes(link, addr, peering.PeerIP, forceDefaultRoutes, nil)
					} else {
						ensureLinkAddressAndRoutes(link, addr, peering.PeerIP, forceDefaultRoutes, &defaultRt)
					}
					break
				}
			}
			for _, bootstrapIP := range bootstrapIPs {
				if SameSubnet(addr, bootstrapIP) {
					_, ipNet, err := net.ParseCIDR(bootstrapIP + "/32")
					if err == nil {
						ensureRoute(&netlink.Route{
							Dst:       ipNet,
							LinkIndex: link.Attrs().Index,
							Type:      syscall.RTN_UNICAST,
							Table:     syscall.RT_TABLE_MAIN,
							Src:       net.ParseIP(thisNode.StableAddress.Address),
						}, false)
					} else {
						logrus.WithError(err).Warningf("Failed to parse OpenShift bootstrap IP (%v)", bootstrapIP)
					}
				}
			}
		}
	}
}

func SameSubnet(addr netlink.Addr, peerIP string) bool {
	maskedAddr := addr.IP.Mask(addr.Mask)
	logrus.Debugf("Masked interface address %v -> %v", addr.IPNet, maskedAddr)
	maskedPeer := net.ParseIP(peerIP).Mask(addr.Mask)
	logrus.Debugf("Masked peer address %v -> %v", peerIP, maskedPeer)
	return maskedAddr.Equal(maskedPeer)
}

// Given an address and interface in the same subnet as a ToR
// address/prefix, update the address in the ways that we need for
// dual ToR operation, and ensure that we still have the routes that
// we'd expect through that interface.
//
// `forceDefaultRoute`:
// If set to true leads to us always programming a default route
// via `peerIP`, on `link`, even if none existed in the first place.
// If set to false, won't add that route unless a similar route
// (a default route over the same link, or via the same peerIP) existed already.
//
// If `baseDefaultRoute` is not nil, we assume a default route did exist via this peer, so we will program
// the same route back, after updating the link's address.
func ensureLinkAddressAndRoutes(link netlink.Link, addr netlink.Addr, peerIP string, forceDefaultRoute bool, baseDefaultRoute *netlink.Route) {
	if addr.Scope != int(netlink.SCOPE_LINK) {
		// Delete the given address and re-add it with scope link.
		err := netlink.AddrDel(link, &addr)
		if err != nil {
			logrus.WithError(err).Fatalf("Failed to delete address %+v", addr)
		}

		addr.Scope = int(netlink.SCOPE_LINK)
		err = netlink.AddrAdd(link, &addr)
		if err != nil {
			logrus.WithError(err).Fatalf("Failed to add address %+v", addr)
		}
	}

	// Ensure that the subnet route is present.
	prefix := *addr.IPNet
	prefix.IP = prefix.IP.Mask(prefix.Mask)
	ensureRoute(&netlink.Route{
		Dst:       &prefix,
		LinkIndex: link.Attrs().Index,
		Type:      syscall.RTN_UNICAST,
		Scope:     netlink.SCOPE_LINK,
		Table:     syscall.RT_TABLE_MAIN,
	}, false)

	// No default route existed, and we are not forcing a default route, so our job is done.
	if !forceDefaultRoute && baseDefaultRoute == nil {
		return
	}

	// Try to add a default route via the ToR.
	var defaultRt netlink.Route
	if baseDefaultRoute != nil {
		defaultRt = *baseDefaultRoute
	} else {
		defaultRt = netlink.Route{
			Gw:        net.ParseIP(peerIP),
			LinkIndex: link.Attrs().Index,
			Type:      syscall.RTN_UNICAST,
			Table:     syscall.RT_TABLE_MAIN,
		}
	}

	ensureRoute(&defaultRt, true)
}

func ensureRoute(route *netlink.Route, append bool) {
	var err error
	if !append {
		err = netlink.RouteAdd(route)
	} else {
		// We sometimes want a route with the same destination going over two different routing paths, i.e, a HA default route.
		// Further, if a node was set up with two default routes prior to early-networking, then we should preserve that.
		// RouteAppend allows for the creation of many routes with the same dest, provided certain other attributes still differ.
		// This _will not_, however, lead to the exact same route being duplicated (we still get an 'already exists' error from netlink).
		err = netlink.RouteAppend(route)
	}
	if err == nil {
		logrus.Infof("Added route: %+v", *route)
	} else if strings.Contains(strings.ToLower(err.Error()), "exists") {
		logrus.Debugf("Route already exists: %+v", *route)
	} else {
		logrus.Fatalf("Failed to add route %+v", *route)
	}
}

// enumerateAllIPs gets all addresses for all interfaces.
func enumerateAllIPs() (ips []string, err error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("Failed to list links: %w", err)
	}

	for _, l := range links {
		lAddrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			logrus.WithField("link", l.Attrs().Name).Warn("Couldn't list addrs for link")
			continue
		}

		for _, a := range lAddrs {
			ips = append(ips, a.IP.String())
		}
	}

	return
}

func writeProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(value))
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

func earlyBGPRunning() bool {
	// 00000000:1FF3, if present, indicates a process listening on port 8179.  (8179 = 0x1FF3)
	return tcpListenOn("00000000:1FF3", "Early BGP")
}

func normalBGPRunning() bool {
	// 00000000:00B3, if present, indicates a process listening on port 179.  (179 = 0xB3)
	return tcpListenOn("00000000:00B3", "Normal BGP")
}

func tcpListenOn(addrPort, description string) bool {
	// /proc/net/tcp shows TCP listens and connections.
	connFile, err := os.Open("/proc/net/tcp")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to open /proc/net/tcp")
	}
	defer connFile.Close()

	scanner := bufio.NewScanner(connFile)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), addrPort) {
			logrus.Debugf("%v is running", description)
			return true
		}
	}
	err = scanner.Err()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to read /proc/net/tcp")
	}

	logrus.Debugf("%v is not running", description)
	return false
}
