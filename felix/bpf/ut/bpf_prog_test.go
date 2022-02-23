// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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

package ut_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/bpf/state"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
)

func init() {
	logutils.ConfigureEarlyLogging()
	log.SetLevel(log.DebugLevel)
}

// Constants that are shared with the UT binaries that we build.
const (
	natTunnelMTU  = uint16(700)
	testVxlanPort = uint16(5665)
)

var (
	rulesDefaultAllow = &polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name:  "allow all",
				Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Allow"}}},
			}},
		}},
	}
	node1ip   = net.IPv4(10, 10, 0, 1).To4()
	node1ip2  = net.IPv4(10, 10, 2, 1).To4()
	node2ip   = net.IPv4(10, 10, 0, 2).To4()
	intfIP    = net.IPv4(10, 10, 0, 3).To4()
	node1CIDR = net.IPNet{
		IP:   node1ip,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}
	node2CIDR = net.IPNet{
		IP:   node2ip,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}
)

// Globals that we use to configure the next test run.
var (
	hostIP       = node1ip
	skbMark      uint32
	bpfIfaceName string
)

const (
	resTC_ACT_OK int = iota
	resTC_ACT_RECLASSIFY
	resTC_ACT_SHOT
	resTC_ACT_PIPE
	resTC_ACT_STOLEN
	resTC_ACT_QUEUED
	resTC_ACT_REPEAT
	resTC_ACT_REDIRECT
	resTC_ACT_UNSPEC = (1 << 32) - 1
)

var retvalToStr = map[int]string{
	resTC_ACT_OK:         "TC_ACT_OK",
	resTC_ACT_RECLASSIFY: "TC_ACT_RECLASSIFY",
	resTC_ACT_SHOT:       "TC_ACT_SHOT",
	resTC_ACT_PIPE:       "TC_ACT_PIPE",
	resTC_ACT_STOLEN:     "TC_ACT_STOLEN",
	resTC_ACT_QUEUED:     "TC_ACT_QUEUED",
	resTC_ACT_REPEAT:     "TC_ACT_REPEAT",
	resTC_ACT_REDIRECT:   "TC_ACT_REDIRECT",
	resTC_ACT_UNSPEC:     "TC_ACT_UNSPEC",
}

const (
	resXDP_ABORTED int = iota
	resXDP_DROP
	resXDP_PASS
)

var retvalToStrXDP = map[int]string{
	resXDP_ABORTED: "XDP_ABORTED",
	resXDP_PASS:    "XDP_PASS",
	resXDP_DROP:    "XDP_DROP",
}

func TestCompileTemplateRun(t *testing.T) {
	runBpfTest(t, "calico_to_workload_ep", &polprog.Rules{}, func(bpfrun bpfProgRunFn) {
		_, _, _, _, pktBytes, err := testPacketUDPDefault()
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())

		// Implicitly denied by normal policy: DROP
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})
}

func TestLoadZeroProgram(t *testing.T) {
	RegisterTestingT(t)
	fd, err := bpf.LoadBPFProgramFromInsns(nil, "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	if err == nil {
		_ = fd.Close()
	}
	Expect(err).To(Equal(unix.E2BIG))
}

type testLogger interface {
	Log(args ...interface{})
	Logf(format string, args ...interface{})
}

func setupAndRun(logger testLogger, loglevel, section string, rules *polprog.Rules,
	runFn func(progName string), opts ...testOption) {

	topts := testOpts{
		subtests:  true,
		logLevel:  log.DebugLevel,
		psnaStart: 20000,
		psnatEnd:  30000,
	}

	for _, o := range opts {
		o(&topts)
	}

	maps := make([]bpf.Map, len(progMaps))
	copy(maps, progMaps)

outter:
	for _, m := range topts.extraMaps {
		for i := range maps {
			if maps[i].Path() == m.Path() {
				continue outter
			}
		}
		maps = append(maps, m)
	}

	tempDir, err := ioutil.TempDir("", "calico-bpf-")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tempDir)

	unique := path.Base(tempDir)
	bpfFsDir := "/sys/fs/bpf/" + unique

	err = os.Mkdir(bpfFsDir, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir)

	obj := "../../bpf-gpl/bin/test_xdp_debug"
	progLog := ""
	if !topts.xdp {
		obj = "../../bpf-gpl/bin/test_"
		if strings.Contains(section, "from") {
			obj += "from_"
		} else {
			obj += "to_"
		}

		if strings.Contains(section, "host") {
			obj += "hep_"
			progLog = "HEP"
		} else if strings.Contains(section, "nat") {
			obj += "nat_"
			progLog = "NAT"
		} else if strings.Contains(section, "wireguard") {
			obj += "wg_"
			progLog = "WG"
		} else {
			obj += "wep_"
			progLog = "WEP"
		}

		log.WithField("hostIP", hostIP).Info("Host IP")
		log.WithField("intfIP", intfIP).Info("Intf IP")
		obj += fmt.Sprintf("fib_%s", loglevel)

		if strings.Contains(section, "_dsr") {
			obj += "_dsr"
			// XXX bit of a hack, we should change the section names to contain _dsr
			section = strings.Trim(section, "_dsr")
		}
	}

	obj += ".o"
	log.Infof("Patching binary %s", obj)

	bin, err := bpf.BinaryFromFile(obj)
	Expect(err).NotTo(HaveOccurred())
	bin.PatchLogPrefix(progLog + "-" + bpfIfaceName)
	err = bin.PatchIPv4(hostIP)
	Expect(err).NotTo(HaveOccurred())
	err = bin.PatchIntfAddr(intfIP)
	Expect(err).NotTo(HaveOccurred())
	bin.PatchTunnelMTU(natTunnelMTU)
	bin.PatchVXLANPort(testVxlanPort)
	bin.PatchPSNATPorts(topts.psnaStart, topts.psnatEnd)
	bin.PatchSkbMark(skbMark)
	tempObj := tempDir + "bpf.o"
	err = bin.WriteToFile(tempObj)
	Expect(err).NotTo(HaveOccurred())

	err = bpftoolProgLoadAll(tempObj, bpfFsDir, topts.xdp, rules != nil, maps...)
	Expect(err).NotTo(HaveOccurred())

	if err != nil {
		logger.Log("Error:", string(err.(*exec.ExitError).Stderr))
	}
	Expect(err).NotTo(HaveOccurred())

	jumpMap := tcJumpMap
	if topts.xdp {
		jumpMap = xdpJumpMap
	}

	if rules != nil {
		alloc := &forceAllocator{alloc: idalloc.New()}
		pg := polprog.NewBuilder(alloc, ipsMap.MapFD(), stateMap.MapFD(), jumpMap.MapFD())
		insns, err := pg.Instructions(*rules)
		Expect(err).NotTo(HaveOccurred())
		polProgFD, err := bpf.LoadBPFProgramFromInsns(insns, "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
		if topts.xdp {
			polProgFD, err = bpf.LoadBPFProgramFromInsns(insns, "Apache-2.0", unix.BPF_PROG_TYPE_XDP)
		}
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = polProgFD.Close() }()
		progFDBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(progFDBytes, uint32(polProgFD))
		err = jumpMap.Update([]byte{0, 0, 0, 0}, progFDBytes)
		Expect(err).NotTo(HaveOccurred())
	}

	runFn(bpfFsDir + "/" + section)
}

// runBpfTest runs a specific section of the entire bpf program in isolation
func runBpfTest(t *testing.T, section string, rules *polprog.Rules, testFn func(bpfProgRunFn), opts ...testOption) {
	RegisterTestingT(t)
	if strings.Contains(section, "xdp") == false {
		section = "classifier_" + section
	}
	setupAndRun(t, "debug", section, rules, func(progName string) {
		t.Run(section, func(_ *testing.T) {
			testFn(func(dataIn []byte) (bpfRunResult, error) {
				res, err := bpftoolProgRun(progName, dataIn)
				log.Debugf("dataIn  = %+v", dataIn)
				if err == nil {
					log.Debugf("dataOut = %+v", res.dataOut)
				}
				return res, err
			})
		})
	}, opts...)
}

type forceAllocator struct {
	alloc *idalloc.IDAllocator
}

func (a *forceAllocator) GetNoAlloc(id string) uint64 {
	return a.alloc.GetOrAlloc(id)
}

func bpftool(args ...string) ([]byte, error) {
	args = append([]string{"--json", "--pretty"}, args...)
	cmd := exec.Command("bpftool", args...)
	log.WithField("cmd", cmd.String()).Debugf("executing")
	out, err := cmd.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			log.WithField("stderr", string(e.Stderr)).Errorf("bpftool %s failed: %v out=\n%v", args, err, string(out))
			// to make the output reflect the new lines, logrus ignores it
			fmt.Print(fmt.Sprint(string(e.Stderr)))
		}
	}

	return out, err
}

var (
	mapInitOnce sync.Once

	natMap, natBEMap, ctMap, rtMap, ipsMap, stateMap, testStateMap, tcJumpMap, xdpJumpMap, affinityMap, arpMap, fsafeMap bpf.Map
	allMaps, progMaps                                                                                                    []bpf.Map
)

func initMapsOnce() {
	mapInitOnce.Do(func() {
		mc := &bpf.MapContext{}

		natMap = nat.FrontendMap(mc)
		natBEMap = nat.BackendMap(mc)
		ctMap = conntrack.Map(mc)
		rtMap = routes.Map(mc)
		ipsMap = ipsets.Map(mc)
		stateMap = state.Map(mc)
		testStateMap = state.MapForTest(mc)
		tcJumpMap = jump.MapForTest(mc)
		xdpJumpMap = MapForTest(mc)
		affinityMap = nat.AffinityMap(mc)
		arpMap = arp.Map(mc)
		fsafeMap = failsafes.Map(mc)

		allMaps = []bpf.Map{natMap, natBEMap, ctMap, rtMap, ipsMap, stateMap, testStateMap, tcJumpMap, xdpJumpMap, affinityMap, arpMap, fsafeMap}
		for _, m := range allMaps {
			err := m.EnsureExists()
			if err != nil {
				log.WithError(err).Panic("Failed to initialise maps")
			}
		}

		progMaps = []bpf.Map{
			natMap,
			natBEMap,
			ctMap,
			rtMap,
			tcJumpMap,
			xdpJumpMap,
			stateMap,
			affinityMap,
			arpMap,
			fsafeMap,
		}

	})
}

func cleanUpMaps() {
	log.Info("Cleaning up all maps")

	logLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	defer log.SetLevel(logLevel)

	for _, m := range allMaps {
		if m == stateMap || m == testStateMap || m == tcJumpMap || m == xdpJumpMap {
			continue // Can't clean up array maps
		}
		log.WithField("map", m.GetName()).Info("Cleaning")
		err := m.Iter(func(_, _ []byte) bpf.IteratorAction {
			return bpf.IterDelete
		})
		if err != nil {
			log.WithError(err).Panic("Failed to walk map")
		}
	}
	log.Info("Cleaned up all maps")
}

func bpftoolProgLoadAll(fname, bpfFsDir string, forXDP bool, polProg bool, maps ...bpf.Map) error {
	args := []string{"prog", "loadall", fname, bpfFsDir, "type", "classifier"}
	if forXDP {
		args = []string{"prog", "loadall", fname, bpfFsDir, "type", "xdp"}
	}

	for _, m := range maps {
		if forXDP && m == tcJumpMap {
			log.Info("XDP program, skipping TC jump map")
			continue
		}
		if !forXDP && m == xdpJumpMap {
			log.Info("TC program, skipping XDP jump map")
			continue
		}

		args = append(args, "map", "name", m.GetName(), "pinned", m.Path())
	}

	log.WithField("program", fname).Debug("Loading BPF program")
	_, err := bpftool(args...)
	if err != nil {
		return err
	}

	jumpMap := tcJumpMap
	if forXDP {
		jumpMap = xdpJumpMap
	}

	if polProg {
		polProgPath := "1_0"
		if !forXDP {
			polProgPath = "classifier_tc_policy"
		}
		polProgPath = path.Join(bpfFsDir, polProgPath)
		_, err = os.Stat(polProgPath)
		if err == nil {
			_, err = bpftool("map", "update", "pinned", jumpMap.Path(), "key", "0", "0", "0", "0", "value", "pinned", polProgPath)
			if err != nil {
				return errors.Wrap(err, "failed to update jump map (policy program)")
			}
		}
	} else {
		_, err = bpftool("map", "delete", "pinned", jumpMap.Path(), "key", "0", "0", "0", "0")
		if err != nil {
			log.WithError(err).Info("failed to update jump map (deleting policy program)")
		}
	}
	polProgPath := "1_1"
	if !forXDP {
		polProgPath = "classifier_tc_accept"
	}
	_, err = bpftool("map", "update", "pinned", jumpMap.Path(), "key", "1", "0", "0", "0", "value", "pinned", path.Join(bpfFsDir, polProgPath))
	if err != nil {
		return errors.Wrap(err, "failed to update jump map (allowed program)")
	}

	if !forXDP {
		_, err = bpftool("map", "update", "pinned", jumpMap.Path(), "key", "2", "0", "0", "0", "value", "pinned", path.Join(bpfFsDir, "classifier_tc_icmp"))
		if err != nil {
			return errors.Wrap(err, "failed to update jump map (icmp program)")
		}
	}

	if !forXDP {
		_, err = bpftool("map", "update", "pinned", jumpMap.Path(), "key", "4", "0", "0", "0", "value", "pinned", path.Join(bpfFsDir, "classifier_tc_host_ct_conflict"))
		if err != nil {
			return errors.Wrap(err, "failed to update jump map (icmp program)")
		}
	}

	return nil
}

type bpfRunResult struct {
	Retval   int
	Duration int
	dataOut  []byte
}

func (r bpfRunResult) RetvalStr() string {
	s := retvalToStr[r.Retval]
	if s == "" {
		return fmt.Sprint(r.Retval)
	}
	return s
}

func (r bpfRunResult) RetvalStrXDP() string {
	s := retvalToStrXDP[r.Retval]
	if s == "" {
		return fmt.Sprint(r.Retval)
	}
	return s
}

func bpftoolProgRun(progName string, dataIn []byte) (bpfRunResult, error) {
	return bpftoolProgRunN(progName, dataIn, 1)
}

func bpftoolProgRunN(progName string, dataIn []byte, N int) (bpfRunResult, error) {
	var res bpfRunResult

	tempDir, err := ioutil.TempDir("", "bpftool-data-")
	Expect(err).NotTo(HaveOccurred())

	defer os.RemoveAll(tempDir)

	dataInFname := tempDir + "/data_in"
	dataOutFname := tempDir + "/data_out"

	if err := ioutil.WriteFile(dataInFname, dataIn, 0644); err != nil {
		return res, errors.Errorf("failed to write input data in file: %s", err)
	}

	args := []string{"prog", "run", "pinned", progName, "data_in", dataInFname, "data_out", dataOutFname}
	if N > 1 {
		args = append(args, "repeat", fmt.Sprintf("%d", N))
	}

	out, err := bpftool(args...)
	if err != nil {
		return res, err
	}

	if err := json.Unmarshal(out, &res); err != nil {
		return res, errors.Errorf("failed to unmarshall json: %s", err)
	}

	res.dataOut, err = ioutil.ReadFile(dataOutFname)
	if err != nil {
		return res, errors.Errorf("failed to read output data from file: %s", err)
	}

	return res, nil
}

type bpfProgRunFn func(data []byte) (bpfRunResult, error)

// runBpfUnitTest runs a small unit in isolation. It requires a small .c file
// that wraps the unit and compiles into a calico_unittest section.
func runBpfUnitTest(t *testing.T, source string, testFn func(bpfProgRunFn), opts ...testOption) {
	RegisterTestingT(t)

	topts := testOpts{
		subtests: true,
		logLevel: log.DebugLevel,
	}

	for _, o := range opts {
		o(&topts)
	}

	loglevel := log.GetLevel()
	if topts.logLevel != loglevel {
		defer log.SetLevel(loglevel)
		log.SetLevel(topts.logLevel)
	}

	maps := make([]bpf.Map, len(progMaps))
	copy(maps, progMaps)

outter:
	for _, m := range topts.extraMaps {
		for i := range maps {
			if maps[i].Path() == m.Path() {
				continue outter
			}
		}
		maps = append(maps, m)
	}

	tempDir, err := ioutil.TempDir("", "calico-bpf-")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tempDir)

	unique := path.Base(tempDir)
	bpfFsDir := "/sys/fs/bpf/" + unique

	err = os.Mkdir(bpfFsDir, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir)

	objFname := "../../bpf-gpl/ut/" + strings.TrimSuffix(source, path.Ext(source)) + ".o"

	log.Infof("Patching binary %s", objFname)
	bin, err := bpf.BinaryFromFile(objFname)
	Expect(err).NotTo(HaveOccurred())
	err = bin.PatchIPv4(hostIP)
	Expect(err).NotTo(HaveOccurred())
	err = bin.PatchIntfAddr(intfIP)
	Expect(err).NotTo(HaveOccurred())
	bin.PatchTunnelMTU(natTunnelMTU)
	bin.PatchVXLANPort(testVxlanPort)
	tempObj := tempDir + "bpf.o"
	err = bin.WriteToFile(tempObj)
	Expect(err).NotTo(HaveOccurred())

	err = bpftoolProgLoadAll(tempObj, bpfFsDir, false, true, maps...)
	Expect(err).NotTo(HaveOccurred())

	runTest := func() {
		testFn(func(dataIn []byte) (bpfRunResult, error) {
			res, err := bpftoolProgRun(bpfFsDir+"/calico_unittest", dataIn)
			log.Debugf("dataIn  = %+v", dataIn)
			if err == nil {
				log.Debugf("dataOut = %+v", res.dataOut)
			}
			return res, err
		})
	}

	if topts.subtests {
		t.Run(source, func(_ *testing.T) {
			runTest()
		})
	} else {
		runTest()
	}
}

type testOpts struct {
	subtests  bool
	logLevel  log.Level
	extraMaps []bpf.Map
	xdp       bool
	psnaStart uint32
	psnatEnd  uint32
}

type testOption func(opts *testOpts)

func withSubtests(v bool) testOption {
	return func(o *testOpts) {
		o.subtests = v
	}
}

var _ = withSubtests

func withLogLevel(l log.Level) testOption {
	return func(o *testOpts) {
		o.logLevel = l
	}
}

var _ = withLogLevel

func withExtraMap(m bpf.Map) testOption {
	return func(o *testOpts) {
		o.extraMaps = append(o.extraMaps, m)
	}
}

func withXDP() testOption {
	return func(o *testOpts) {
		o.xdp = true
	}
}

func withPSNATPorts(start, end uint16) testOption {
	return func(o *testOpts) {
		o.psnaStart = uint32(start)
		o.psnatEnd = uint32(end)
	}
}

var _ = withExtraMap

// layersMatchFields matches all Exported fields and ignore the ones explicitly
// listed. It always ignores BaseLayer as that is not set by the tests.
func layersMatchFields(l gopacket.Layer, ignore ...string) types.GomegaMatcher {
	toIgnore := make(map[string]bool)
	for _, x := range ignore {
		toIgnore[x] = true
	}

	toIgnore["BaseLayer"] = true

	f := Fields{}
	v := reflect.Indirect(reflect.ValueOf(l))
	if v.Kind() != reflect.Struct {
		return Reject()
	}

	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if !toIgnore[name] && v.Field(i).CanInterface() {
			val := v.Field(i).Interface()
			f[name] = Equal(val)
		}
	}

	return PointTo(MatchFields(IgnoreMissing|IgnoreExtras, f))
}

func udpResponseRaw(in []byte) []byte {
	pkt := gopacket.NewPacket(in, layers.LayerTypeEthernet, gopacket.Default)
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ethR := ethL.(*layers.Ethernet)
	ethR.SrcMAC, ethR.DstMAC = ethR.DstMAC, ethR.SrcMAC

	ipv4L := pkt.Layer(layers.LayerTypeIPv4)
	ipv4R := ipv4L.(*layers.IPv4)
	ipv4R.SrcIP, ipv4R.DstIP = ipv4R.DstIP, ipv4R.SrcIP

	udpL := pkt.Layer(layers.LayerTypeUDP)
	udpR := udpL.(*layers.UDP)
	udpR.SrcPort, udpR.DstPort = udpR.DstPort, udpR.SrcPort

	_ = udpR.SetNetworkLayerForChecksum(ipv4R)

	out := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(out, gopacket.SerializeOptions{ComputeChecksums: true},
		ethR, ipv4R, udpR, gopacket.Payload(pkt.ApplicationLayer().Payload()))
	Expect(err).NotTo(HaveOccurred())

	return out.Bytes()
}

func tcpResponseRaw(in []byte) []byte {
	pkt := gopacket.NewPacket(in, layers.LayerTypeEthernet, gopacket.Default)
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ethR := ethL.(*layers.Ethernet)
	ethR.SrcMAC, ethR.DstMAC = ethR.DstMAC, ethR.SrcMAC

	ipv4L := pkt.Layer(layers.LayerTypeIPv4)
	ipv4R := ipv4L.(*layers.IPv4)
	ipv4R.SrcIP, ipv4R.DstIP = ipv4R.DstIP, ipv4R.SrcIP

	tcpL := pkt.Layer(layers.LayerTypeTCP)
	tcpR := tcpL.(*layers.TCP)
	tcpR.SrcPort, tcpR.DstPort = tcpR.DstPort, tcpR.SrcPort

	if tcpR.SYN {
		tcpR.ACK = true
	}

	_ = tcpR.SetNetworkLayerForChecksum(ipv4R)

	out := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(out, gopacket.SerializeOptions{ComputeChecksums: true},
		ethR, ipv4R, tcpR, gopacket.Payload(pkt.ApplicationLayer().Payload()))
	Expect(err).NotTo(HaveOccurred())

	return out.Bytes()
}

func dumpNATMap(natMap bpf.Map) {
	nt, err := nat.LoadFrontendMap(natMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range nt {
		fmt.Printf("%s : %s\n", k, v)
	}
}

func resetMap(m bpf.Map) {
	err := m.Iter(func(_, _ []byte) bpf.IteratorAction {
		return bpf.IterDelete
	})
	Expect(err).NotTo(HaveOccurred())
}

func dumpCTMap(ctMap bpf.Map) {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("Conntrack dump:\n")
	for k, v := range ct {
		fmt.Printf("- %s : %s\n", k, v)
	}
	fmt.Printf("\n")
}

func resetCTMap(ctMap bpf.Map) {
	resetMap(ctMap)
}

func saveCTMap(ctMap bpf.Map) conntrack.MapMem {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	return ct
}

func restoreCTMap(ctMap bpf.Map, m conntrack.MapMem) {
	for k, v := range m {
		err := ctMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func dumpRTMap(rtMap bpf.Map) {
	rt, err := routes.LoadMap(rtMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range rt {
		fmt.Printf("%15s: %s\n", k.Dest(), v)
	}
}

func resetRTMap(rtMap bpf.Map) {
	resetMap(rtMap)
}

func saveRTMap(rtMap bpf.Map) routes.MapMem {
	rt, err := routes.LoadMap(rtMap)
	Expect(err).NotTo(HaveOccurred())
	return rt
}

func restoreRTMap(rtMap bpf.Map, m routes.MapMem) {
	for k, v := range m {
		err := rtMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func dumpARPMap(arpMap bpf.Map) {
	ct, err := arp.LoadMapMem(arpMap)
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("ARP dump:\n")
	for k, v := range ct {
		fmt.Printf("- %s : %s\n", k, v)
	}
	fmt.Printf("\n")
}

func saveARPMap(ctMap bpf.Map) arp.MapMem {
	m, err := arp.LoadMapMem(arpMap)
	Expect(err).NotTo(HaveOccurred())
	return m
}

var ethDefault = &layers.Ethernet{
	SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
	DstMAC:       []byte{0, 0, 0, 0, 0, 2},
	EthernetType: layers.EthernetTypeIPv4,
}

var ethDefaultWithIPv6 = &layers.Ethernet{
	SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
	DstMAC:       []byte{0, 0, 0, 0, 0, 2},
	EthernetType: layers.EthernetTypeIPv6,
}

var payloadDefault = []byte("ABCDEABCDEXXXXXXXXXXXX")

var srcIP = net.IPv4(1, 1, 1, 1)
var dstIP = net.IPv4(2, 2, 2, 2)
var srcV4CIDR = ip.CIDRFromNetIP(srcIP).(ip.V4CIDR)

var ipv4Default = &layers.IPv4{
	Version:  4,
	IHL:      5,
	TTL:      64,
	Flags:    layers.IPv4DontFragment,
	SrcIP:    srcIP,
	DstIP:    dstIP,
	Protocol: layers.IPProtocolUDP,
}

var srcIPv6 = net.IP([]byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
var dstIPv6 = net.IP([]byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})

var ipv6Default = &layers.IPv6{
	Version:    6,
	HopLimit:   64,
	SrcIP:      srcIPv6,
	DstIP:      dstIPv6,
	NextHeader: layers.IPProtocolUDP,
}

var udpDefault = &layers.UDP{
	SrcPort: 1234,
	DstPort: 5678,
}

func testPacket(ethAlt *layers.Ethernet, ipv4Alt *layers.IPv4, l4Alt gopacket.Layer, payloadAlt []byte) (
	*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	eth, ipv4, _, l4, bytes, payload, err := testPacket46(ethAlt, ipv4Alt, nil, l4Alt, payloadAlt, false)
	return eth, ipv4, l4, bytes, payload, err
}

func testPacketv6(ethAlt *layers.Ethernet, ipv6Alt *layers.IPv6, l4Alt gopacket.Layer, payloadAlt []byte) (
	*layers.Ethernet, *layers.IPv6, gopacket.Layer, []byte, []byte, error) {
	eth, _, ipv6, l4, bytes, payload, err := testPacket46(ethAlt, nil, ipv6Alt, l4Alt, payloadAlt, true)
	return eth, ipv6, l4, bytes, payload, err
}

func testPacket46(ethAlt *layers.Ethernet, ipv4Alt *layers.IPv4, ipv6Alt *layers.IPv6, l4Alt gopacket.Layer, payloadAlt []byte, ipv6Enabled bool) (
	*layers.Ethernet, *layers.IPv4, *layers.IPv6, gopacket.Layer, []byte, []byte, error) {

	var (
		eth     *layers.Ethernet
		ipv4    *layers.IPv4
		ipv6    *layers.IPv6
		payload []byte
	)

	if ethAlt != nil {
		eth = ethAlt
	} else {
		if ipv6Enabled {
			eth = ethDefaultWithIPv6
		} else {
			eth = ethDefault
		}
	}

	if ipv6Enabled {
		if ipv6Alt != nil {
			ipv6 = ipv6Alt
		} else {
			// Make a copy so that we do not mangle the default if we set the
			// protocol below.
			ipv6 = new(layers.IPv6)
			*ipv6 = *ipv6Default
		}
	} else {
		if ipv4Alt != nil {
			ipv4 = ipv4Alt
		} else {
			// Make a copy so that we do not mangle the default if we set the
			// protocol below.
			ipv4 = new(layers.IPv4)
			*ipv4 = *ipv4Default
		}
	}

	if l4Alt == nil {
		l4Alt = udpDefault
	}

	if payloadAlt != nil {
		payload = payloadAlt
	} else {
		payload = payloadDefault
	}

	return generatePacket(eth, ipv4, ipv6, l4Alt, payload, ipv6Enabled)

}

func generatePacket(eth *layers.Ethernet, ipv4 *layers.IPv4, ipv6 *layers.IPv6, l4 gopacket.Layer, payload []byte, ipv6Enabled bool) (
	*layers.Ethernet, *layers.IPv4, *layers.IPv6, gopacket.Layer, []byte, []byte, error) {
	var (
		udp    *layers.UDP
		tcp    *layers.TCP
		icmp   *layers.ICMPv4
		icmpv6 *layers.ICMPv6
	)

	if l4 != nil {
		switch v := l4.(type) {
		case *layers.UDP:
			udp = v
			if ipv6Enabled {
				ipv6.NextHeader = layers.IPProtocolUDP
			} else {
				ipv4.Protocol = layers.IPProtocolUDP
			}
		case *layers.TCP:
			tcp = v
			if ipv6Enabled {
				ipv6.NextHeader = layers.IPProtocolTCP
			} else {
				ipv4.Protocol = layers.IPProtocolTCP
			}
		case *layers.ICMPv4:
			icmp = v
			ipv4.Protocol = layers.IPProtocolICMPv4
		case *layers.ICMPv6:
			icmpv6 = v
			ipv6.NextHeader = layers.IPProtocolICMPv6
		default:
			return nil, nil, nil, nil, nil, nil, errors.Errorf("unrecognized l4 layer type %t", l4)
		}
	}

	switch {
	case udp != nil:
		if ipv6Enabled {
			ipv6.Length = uint16(8 + len(payload))
			_ = udp.SetNetworkLayerForChecksum(ipv6)
			udp.Length = uint16(8 + len(payload))

			pkt := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
				eth, ipv6, udp, gopacket.Payload(payload))
			return eth, nil, ipv6, udp, payload, pkt.Bytes(), err
		} else {
			ipv4.Length = uint16(5*4 + 8 + len(payload))
			_ = udp.SetNetworkLayerForChecksum(ipv4)
			udp.Length = uint16(8 + len(payload))

			pkt := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
				eth, ipv4, udp, gopacket.Payload(payload))
			return eth, ipv4, nil, udp, payload, pkt.Bytes(), err
		}
	case tcp != nil:
		if tcp == nil {
			return nil, nil, nil, nil, nil, nil, errors.Errorf("tcp default not implemented yet")
		}
		if ipv6Enabled {
			ipv6.Length = uint16(8 + len(payload))
			_ = tcp.SetNetworkLayerForChecksum(ipv6)

			pkt := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
				eth, ipv6, tcp, gopacket.Payload(payload))

			return eth, nil, ipv6, tcp, payload, pkt.Bytes(), err

		} else {
			ipv4.Length = uint16(5*4 + 8 + len(payload))
			_ = tcp.SetNetworkLayerForChecksum(ipv4)

			pkt := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
				eth, ipv4, tcp, gopacket.Payload(payload))

			return eth, ipv4, nil, tcp, payload, pkt.Bytes(), err
		}
	case icmp != nil:
		ipv4.Length = uint16(5*4 + 8 + len(payload))

		pkt := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
			eth, ipv4, icmp, gopacket.Payload(payload))

		return eth, ipv4, nil, icmp, payload, pkt.Bytes(), err
	case icmpv6 != nil:
		ipv6.Length = uint16(8 + len(payload))

		pkt := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
			eth, ipv6, icmp, gopacket.Payload(payload))

		return eth, nil, ipv6, icmp, payload, pkt.Bytes(), err
	default:
		if ipv6Enabled {
			ipv6.Length = uint16(8 + len(payload))

			pkt := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
				eth, ipv6, gopacket.Payload(payload))

			return eth, nil, ipv6, nil, payload, pkt.Bytes(), err
		} else {
			ipv4.Length = uint16(5*4 + 8 + len(payload))

			pkt := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
				eth, ipv4, gopacket.Payload(payload))

			return eth, ipv4, nil, nil, payload, pkt.Bytes(), err

		}
	}
}

func testPacketUDPDefault() (*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	return testPacket(nil, nil, nil, nil)
}

func testPacketUDPDefaultNP(destIP net.IP) (*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	if destIP == nil {
		return testPacketUDPDefault()
	}

	ip := *ipv4Default
	ip.DstIP = destIP

	return testPacket(nil, &ip, nil, nil)
}

func resetBPFMaps() {
	resetCTMap(ctMap)
	resetRTMap(rtMap)
	resetMap(fsafeMap)
}

func TestMapIterWithDelete(t *testing.T) {
	RegisterTestingT(t)

	m := (&bpf.MapContext{}).NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/tc/globals/cali_tmap",
		Type:       "hash",
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 1000,
		Name:       "cali_tmap",
		Flags:      unix.BPF_F_NO_PREALLOC,
	})

	err := m.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 10; i++ {
		var k, v [8]byte

		binary.LittleEndian.PutUint64(k[:], uint64(i))
		binary.LittleEndian.PutUint64(v[:], uint64(i*7))

		err := m.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}

	out := make(map[uint64]uint64)

	cnt := 0
	err = m.Iter(func(K, V []byte) bpf.IteratorAction {
		k := binary.LittleEndian.Uint64(K)
		v := binary.LittleEndian.Uint64(V)

		out[k] = v
		cnt++

		return bpf.IterDelete
	})
	Expect(err).NotTo(HaveOccurred())

	Expect(cnt).To(Equal(10))

	for i := 0; i < 10; i++ {
		Expect(out).To(HaveKey(uint64(i)))
		Expect(out[uint64(i)]).To(Equal(uint64(i * 7)))
	}
}

func TestMapIterWithDeleteLastOfBatch(t *testing.T) {
	RegisterTestingT(t)

	m := (&bpf.MapContext{}).NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/tc/globals/cali_tmap",
		Type:       "hash",
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 1000,
		Name:       "cali_tmap",
		Flags:      unix.BPF_F_NO_PREALLOC,
	})

	err := m.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 40; i++ {
		var k, v [8]byte

		binary.LittleEndian.PutUint64(k[:], uint64(i))
		binary.LittleEndian.PutUint64(v[:], uint64(i*7))

		err := m.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}

	out := make(map[uint64]uint64)

	cnt := 0
	err = m.Iter(func(K, V []byte) bpf.IteratorAction {
		k := binary.LittleEndian.Uint64(K)
		v := binary.LittleEndian.Uint64(V)

		out[k] = v

		cnt++
		// Delete the last of the first batch. Must not make the iteration to
		// restart from the beginning.
		if cnt == bpf.MapIteratorNumKeys {
			return bpf.IterDelete
		}
		return bpf.IterNone
	})
	Expect(err).NotTo(HaveOccurred())

	Expect(cnt).To(Equal(40))

	for i := 0; i < 40; i++ {
		Expect(out).To(HaveKey(uint64(i)))
		Expect(out[uint64(i)]).To(Equal(uint64(i * 7)))
	}
}

func TestJumpMap(t *testing.T) {
	RegisterTestingT(t)

	jumpMapFD := tcJumpMap.MapFD()
	pg := polprog.NewBuilder(idalloc.New(), ipsMap.MapFD(), stateMap.MapFD(), jumpMapFD)
	rules := polprog.Rules{}
	insns, err := pg.Instructions(rules)
	Expect(err).NotTo(HaveOccurred())
	progFD, err := bpf.LoadBPFProgramFromInsns(insns, "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	Expect(err).NotTo(HaveOccurred())

	k := make([]byte, 4)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(progFD))

	err = bpf.UpdateMapEntry(jumpMapFD, k, v)
	Expect(err).NotTo(HaveOccurred())

	err = bpf.DeleteMapEntry(jumpMapFD, k, 4)
	Expect(err).NotTo(HaveOccurred())

	err = bpf.UpdateMapEntry(jumpMapFD, k, v)
	Expect(err).NotTo(HaveOccurred())

	err = bpf.DeleteMapEntryIfExists(jumpMapFD, k, 4)
	Expect(err).NotTo(HaveOccurred())

	err = bpf.DeleteMapEntryIfExists(jumpMapFD, k, 4)
	Expect(err).NotTo(HaveOccurred())

	err = bpf.DeleteMapEntry(jumpMapFD, k, 4)
	Expect(err).To(HaveOccurred())
}
