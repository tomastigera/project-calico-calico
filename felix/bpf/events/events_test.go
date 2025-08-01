package events

import (
	"encoding/binary"
	"net"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/state"
)

func TestParsePolicyVerdictEvents(t *testing.T) {
	RegisterTestingT(t)

	t.Run("without device indices", func(t *testing.T) {
		data := createTestPolicyVerdictData(3, false, false)
		verdict := ParsePolicyVerdict(data, false)
		Expect(verdict.RulesHit).To(Equal(uint32(3)))
		for i := range 3 {
			Expect(verdict.RuleIDs[i]).To(Equal(uint64(1000 + i)))
		}
		Expect(verdict.SrcAddr.Equal(net.ParseIP("192.168.1.1"))).To(BeTrue())
		Expect(verdict.DstAddr.Equal(net.ParseIP("192.168.1.2"))).To(BeTrue())
		Expect(verdict.PostNATDstAddr.Equal(net.ParseIP("192.168.1.4"))).To(BeTrue())
		Expect(verdict.SrcPort).To(Equal(uint16(8080)))
		Expect(verdict.DstPort).To(Equal(uint16(80)))
		Expect(verdict.PostNATDstPort).To(Equal(uint16(8081)))
		Expect(verdict.IPProto).To(Equal(uint8(6)))
		Expect(verdict.OutDeviceIndex).To(Equal(uint32(0)))
		Expect(verdict.InDeviceIndex).To(Equal(uint32(0)))
	})

	t.Run("with device indices", func(t *testing.T) {
		data := createTestPolicyVerdictData(3, false, true)
		verdict := ParsePolicyVerdict(data, false)
		Expect(verdict.RulesHit).To(Equal(uint32(3)))
		for i := range 3 {
			Expect(verdict.RuleIDs[i]).To(Equal(uint64(1000 + i)))
		}
		Expect(verdict.SrcAddr.Equal(net.ParseIP("192.168.1.1"))).To(BeTrue())
		Expect(verdict.DstAddr.Equal(net.ParseIP("192.168.1.2"))).To(BeTrue())
		Expect(verdict.PostNATDstAddr.Equal(net.ParseIP("192.168.1.4"))).To(BeTrue())
		Expect(verdict.SrcPort).To(Equal(uint16(8080)))
		Expect(verdict.DstPort).To(Equal(uint16(80)))
		Expect(verdict.PostNATDstPort).To(Equal(uint16(8081)))
		Expect(verdict.IPProto).To(Equal(uint8(6)))
		Expect(verdict.OutDeviceIndex).To(Equal(uint32(42)))
		Expect(verdict.InDeviceIndex).To(Equal(uint32(84)))
	})
}

// createTestPolicyVerdictData is a helper to create test data for PolicyVerdict
func createTestPolicyVerdictData(rulesHit uint32, isIPv6 bool, withDevices bool) []byte {
	offSt := 104
	ruleIDsEnd := offSt + int(rulesHit)*8
	ruleIDsLen := 8 * int(state.MaxRuleIDs)
	ctOffset := offSt + ruleIDsLen

	// Minimum size for main fields and rule IDs
	minSize := ruleIDsEnd
	// If device indices should be included, extend size
	if withDevices {
		minSize = ctOffset + 36 // enough for InDeviceIndex
	}
	// Add extra space for safety
	if minSize < 256 {
		minSize = 256
	}
	data := make([]byte, minSize)

	// IPs
	if isIPv6 {
		copy(data[0:16], net.ParseIP("2001:db8::1").To16())
		copy(data[32:48], net.ParseIP("2001:db8::2").To16())
		copy(data[48:64], net.ParseIP("2001:db8::4").To16())
		copy(data[64:80], net.ParseIP("2001:db8::4").To16())
	} else {
		copy(data[0:4], net.ParseIP("192.168.1.1").To4())
		copy(data[32:36], net.ParseIP("192.168.1.2").To4())
		copy(data[48:52], net.ParseIP("192.168.1.4").To4())
		copy(data[64:68], net.ParseIP("192.168.1.4").To4())
	}

	binary.LittleEndian.PutUint32(data[84:88], uint32(state.PolicyAllow))
	binary.LittleEndian.PutUint16(data[88:90], 8080)
	binary.LittleEndian.PutUint16(data[92:94], 80)
	binary.LittleEndian.PutUint16(data[94:96], 8081)
	data[96] = 6 // TCP
	binary.BigEndian.PutUint16(data[98:100], 1500)
	binary.LittleEndian.PutUint32(data[100:104], rulesHit)

	off := offSt
	for i := uint32(0); i < rulesHit && i < state.MaxRuleIDs; i++ {
		binary.LittleEndian.PutUint64(data[off:off+8], uint64(1000+i))
		off += 8
	}

	if withDevices {
		binary.LittleEndian.PutUint32(data[ctOffset+28:ctOffset+32], 42)
		binary.LittleEndian.PutUint32(data[ctOffset+32:ctOffset+36], 84)
	}

	return data
}
