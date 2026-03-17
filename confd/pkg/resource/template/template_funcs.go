package template

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kelseyhightower/memkv"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/confd/pkg/backends"
)

const (
	maxBIRDSymLen = 64
)

func newFuncMap() map[string]any {
	m := make(map[string]any)
	m["base"] = path.Base
	m["split"] = strings.Split
	m["json"] = UnmarshalJsonObject
	m["jsonArray"] = UnmarshalJsonArray
	m["dir"] = path.Dir
	m["map"] = CreateMap
	m["join"] = strings.Join
	m["datetime"] = time.Now
	m["toUpper"] = strings.ToUpper
	m["toLower"] = strings.ToLower
	m["contains"] = strings.Contains
	m["replace"] = strings.Replace
	m["hasSuffix"] = strings.HasSuffix
	m["lookupIP"] = LookupIP
	m["lookupSRV"] = LookupSRV
	m["fileExists"] = isFileExist
	m["base64Encode"] = Base64Encode
	m["base64Decode"] = Base64Decode
	m["hashToIPv4"] = hashToIPv4
	m["externalNetworkBIRDConfig"] = ExternalNetworkBIRDConfig
	m["bgpFilterBIRDFuncs"] = BGPFilterBIRDFuncs
	return m
}

func addFuncs(out, in map[string]any) {
	maps.Copy(out, in)
}

// ExternalNetworkTableName returns a formatted name for use as a BIRD table, truncating and hashing if the provided
// name would result in a table name longer than the max allowable length of 64 chars.
// e.g. input of "my-external-network" would result in output of "'T_my-external-network'"
func ExternalNetworkTableName(name string) (string, error) {
	prefix := "T_"
	resizedName, err := TruncateAndHashName(name, maxBIRDSymLen-len(prefix))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("'%s%s'", prefix, resizedName), nil
}

// addCalicoFuncs adds Calico-specific template functions
func addCalicoFuncs(funcMap map[string]any) {
	// Add getBGPConfig function that takes the ipVersion and client as parameters
	funcMap["getBGPConfig"] = func(ipVersion int, client any) (any, error) {
		if storeClient, ok := client.(backends.StoreClient); ok {
			config, err := storeClient.GetBirdBGPConfig(ipVersion)
			if err != nil {
				// Return error to fail template execution and prevent broken config
				return nil, err
			}
			return config, nil
		}
		return nil, errors.New("client does not support GetBirdBGPConfig")
	}
}

// filterStatement produces a single comparison expression to be used within a multi-statement BIRD filter
// function.
// e.g input of ("In", "77.0.0.1/16", "accept") produces output of "if ((net ~ 77.0.0.1/16)) then { accept; }"
func filterStatement(fields filterArgs) (string, error) {
	actionStatement, err := filterAction(fields.action)
	if err != nil {
		return "", err
	}

	var conditions []string
	if fields.cidr != "" {
		if fields.operator == "" {
			return "", fmt.Errorf("operator not included in BGPFilter")
		}
		cidrCondition, err := filterMatchCIDR(fields.cidr, fields.prefixLengthV4, fields.prefixLengthV6, fields.operator)
		if err != nil {
			return "", err
		}
		conditions = append(conditions, cidrCondition)
	}

	if fields.source != "" {
		sourceCondition, err := filterMatchSource(fields.source)
		if err != nil {
			return "", nil
		}
		conditions = append(conditions, sourceCondition)
	}

	if fields.iface != "" {
		ifaceCondition, err := filterMatchInterface(fields.iface)
		if err != nil {
			return "", nil
		}
		conditions = append(conditions, ifaceCondition)
	}

	conditionExpr := strings.Join(conditions, "&&")
	if conditionExpr != "" {
		return fmt.Sprintf("if (%s) then { %s }", conditionExpr, actionStatement), nil
	}
	return actionStatement, nil
}

func filterAction(action v3.BGPFilterAction) (string, error) {
	if action != v3.Accept && action != v3.Reject {
		return "", fmt.Errorf("unexpected action found in BGPFilter: %s", action)
	}
	return fmt.Sprintf("%s;", strings.ToLower(string(action))), nil
}

var operatorLUT = map[v3.BGPFilterMatchOperator]string{
	v3.MatchOperatorEqual:    "=",
	v3.MatchOperatorNotEqual: "!=",
	v3.MatchOperatorIn:       "~",
	v3.MatchOperatorNotIn:    "!~",
}

func filterMatchPrefixLength(cidr string, prefixMin, prefixMax *int32) (string, error) {
	cidrIP, cidrNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("unexpected error when parsing cidr %s: %s", cidr, err)
	}

	mask, _ := cidrNet.Mask.Size()
	minLength := int32(mask)
	// default for ipv4
	maxLength := int32(32)

	// check for ipv6 IP
	if cidrIP.To4() == nil {
		maxLength = 128
	}

	if prefixMin != nil {
		minLength = max(minLength, *prefixMin)
	}
	if prefixMax != nil {
		maxLength = min(maxLength, *prefixMax)
	}

	return fmt.Sprintf("[ %s{%d,%d} ]", cidr, minLength, maxLength), nil
}

func filterMatchCIDR(cidr string, prefixLengthV4 *v3.BGPFilterPrefixLengthV4, prefixLengthV6 *v3.BGPFilterPrefixLengthV6, operator v3.BGPFilterMatchOperator) (string, error) {
	op, ok := operatorLUT[operator]
	if !ok {
		return "", fmt.Errorf("unexpected operator found in BGPFilter: %s", operator)
	}

	var err error
	if prefixLengthV4 != nil {
		cidr, err = filterMatchPrefixLength(cidr, prefixLengthV4.Min, prefixLengthV4.Max)
	} else if prefixLengthV6 != nil {
		cidr, err = filterMatchPrefixLength(cidr, prefixLengthV6.Min, prefixLengthV6.Max)
	}

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("(net %s %s)", op, cidr), nil
}

func filterMatchSource(source v3.BGPFilterMatchSource) (string, error) {
	switch source {
	case v3.BGPFilterSourceRemotePeers:
		return "((defined(source))&&(source ~ [ RTS_BGP ]))", nil
	default:
		return "", fmt.Errorf("unexpected source found in BGPFilter: %s", source)
	}
}

func filterMatchInterface(iface string) (string, error) {
	if iface == "" {
		return "", fmt.Errorf("empty interface found in BGPFilter")
	}
	return fmt.Sprintf("((defined(ifname))&&(ifname ~ \"%s\"))", iface), nil
}

// BGPFilterFunctionName returns a formatted name for use as a BIRD function, truncating and hashing if the provided
// name would result in a function name longer than the max allowable length of 64 chars.
// e.g. input of ("my-bgp-filter", "import", "4") would result in output of "'bgp_my-bpg-filter_importFilterV4'"
func BGPFilterFunctionName(filterName, direction, version string) (string, error) {
	normalizedDirection := strings.ToLower(direction)
	if normalizedDirection != "import" && normalizedDirection != "export" {
		return "", fmt.Errorf("provided direction '%s' does not map to either 'import' or 'export'", direction)
	}
	pieces := []string{"bgp_", "", "_", normalizedDirection, "FilterV", version}
	resizedName, err := TruncateAndHashName(filterName, maxBIRDSymLen-len(strings.Join(pieces, "")))
	if err != nil {
		return "", err
	}
	pieces[1] = resizedName
	fullName := strings.Join(pieces, "")
	return fmt.Sprintf("'%s'", fullName), nil
}

// ExternalNetworkBIRDConfig generates BIRD config for the tables and kernel protocol configuration based on
// configured ExternalNetwork resources.
//
// e.g. for ExternalNetwork resource configured as follows:
//
// kind: ExternalNetwork
// apiVersion: projectcalico.org/v3
// metadata:
//
//	name: test-enet
//
// spec:
//
//	routeTableIndex: 7
//
// Would produce the following string array that can be easily output via BIRD config template:
//
//	[]string {
//	  "# ExternalNetwork test-enet",
//	  "table 'T_test-enet';",
//	  "protocol kernel 'K_test-enet' from kernel_template {",
//	  "  device routes yes;",
//	  "  table 'T_test-enet';",
//	  "  kernel table 7;",
//	  "  export filter {",
//	  "    print \"route: \", net, \", from, \", \", \", proto, \", \", bgp_next_hop;",
//	  "    if proto = \"Global_10_192_0_3\" then accept;",
//	  "    if proto = \"Global_10_192_0_4\" then accept;",
//	  "    reject;",
//	  "  };",
//	  "}",
//	 }
func ExternalNetworkBIRDConfig(selfIP string, externalNetworkKVPs memkv.KVPairs, globalPeersKVP memkv.KVPairs,
	nodeSpecificPeersKVP memkv.KVPairs,
) ([]string, error) {
	lines := []string{}
	peerReferencedExternalNetworks := map[string][]string{}
	var line string

	if len(externalNetworkKVPs) == 0 {
		return []string{"# No ExternalNetworks configured"}, nil
	}

	emitExternalNetworkProtoStatements := func(peerNamePrefix, selfIP string, peers memkv.KVPairs) (map[string][]string, error) {
		eNetProtoStatements := make(map[string][]string)
		for _, peer := range peers {
			var backendPeer backends.BGPPeer
			err := json.Unmarshal([]byte(peer.Value), &backendPeer)
			if err != nil {
				return map[string][]string{}, fmt.Errorf("error unmarshalling JSON into backend BGPPeer: %s", err)
			}
			if backendPeer.PeerIP.String() == selfIP || backendPeer.ExternalNetwork == "" {
				continue // Skip ourselves because we don't generate a protocol definition for ourselves
			}
			var sep string
			if backendPeer.PeerIP.Version() == 4 {
				sep = "."
			} else {
				sep = ":"
			}
			ipParts := strings.Split(backendPeer.PeerIP.String(), sep)
			ipParts = append([]string{peerNamePrefix}, ipParts...)
			if backendPeer.Port > 0 {
				portStrParts := []string{"port", strconv.Itoa(int(backendPeer.Port))}
				ipParts = append(ipParts, portStrParts...)
			}
			eNetProtoStatements[backendPeer.ExternalNetwork] = append(eNetProtoStatements[backendPeer.ExternalNetwork],
				fmt.Sprintf("    if proto = \"%s\" then accept;", strings.Join(ipParts, "_")))
		}
		return eNetProtoStatements, nil
	}

	globalEnetProtoStatements, err := emitExternalNetworkProtoStatements("Global", selfIP, globalPeersKVP)
	if err != nil {
		return []string{}, err
	}

	explicitEnetProtoStatements, err := emitExternalNetworkProtoStatements("Node", selfIP, nodeSpecificPeersKVP)
	if err != nil {
		return []string{}, err
	}

	for enet, statements := range globalEnetProtoStatements {
		peerReferencedExternalNetworks[enet] = append(peerReferencedExternalNetworks[enet], statements...)
	}

	for enet, statements := range explicitEnetProtoStatements {
		peerReferencedExternalNetworks[enet] = append(peerReferencedExternalNetworks[enet], statements...)
	}

	if len(peerReferencedExternalNetworks) == 0 {
		line = "# No ExternalNetworks configured for any of this node's BGP peers"
		lines = append(lines, line)
		return lines, nil
	}
	for _, kvp := range externalNetworkKVPs {
		var externalNetwork v3.ExternalNetwork
		err := json.Unmarshal([]byte(kvp.Value), &externalNetwork)
		if err != nil {
			return []string{}, fmt.Errorf("error unmarshalling JSON into ExternalNetwork: %s", err)
		}
		externalNetworkName := path.Base(kvp.Key)
		peerStatements, ok := peerReferencedExternalNetworks[externalNetworkName]
		if !ok {
			continue // No peers reference this external network so we don't need to emit any config for it
		}
		var routeTableIndex uint32
		if externalNetwork.Spec.RouteTableIndex != nil {
			routeTableIndex = *externalNetwork.Spec.RouteTableIndex
		}
		tableName, err := ExternalNetworkTableName(externalNetworkName)
		if err != nil {
			return []string{}, err
		}

		line = fmt.Sprintf("# ExternalNetwork %s", externalNetworkName)
		lines = append(lines, line)

		line = fmt.Sprintf("table %s;", tableName)
		lines = append(lines, line)

		kernelName := strings.Replace(tableName, "T_", "K_", 1)
		kernel := []string{
			fmt.Sprintf("protocol kernel %s from kernel_template {", kernelName),
			"  device routes yes;",
			fmt.Sprintf("  table %s;", tableName),
			fmt.Sprintf("  kernel table %d;", routeTableIndex),
			"  export filter {",
			"    print \"route: \", net, \", from, \", \", \", proto, \", \", bgp_next_hop;",
		}

		kernel = append(kernel, peerStatements...)

		kernel = append(kernel, []string{
			"    reject;",
			"  };",
			"}",
		}...)

		kernel = append(kernel,
			"protocol pipe {",
			"  peer table "+tableName+";",
			"  export filter {",
			"    if (ifname ~ \"cali*\") then {",
			"      accept;",
			"    } else {",
			"      reject;",
			"    }",
			"  };",
			"  import filter {",
			"    reject;",
			"  };",
			"}",
		)

		lines = append(lines, kernel...)

		directName := strings.Replace(tableName, "T_", "D_", 1)
		direct := []string{
			fmt.Sprintf("protocol direct %s from direct_template {", directName),
			fmt.Sprintf("  table %s;", tableName),
			"}",
		}
		lines = append(lines, direct...)

		staticName := strings.Replace(tableName, "T_", "S_", 1)
		static := []string{
			fmt.Sprintf("protocol static %s from static_template {", staticName),
			fmt.Sprintf("  table %s;", tableName),
			"}",
		}
		lines = append(lines, static...)
	}
	return lines, nil
}

type filterArgs struct {
	operator       v3.BGPFilterMatchOperator
	cidr           string
	prefixLengthV4 *v3.BGPFilterPrefixLengthV4
	prefixLengthV6 *v3.BGPFilterPrefixLengthV6
	source         v3.BGPFilterMatchSource
	iface          string
	action         v3.BGPFilterAction
}

// BGPFilterBIRDFuncs generates a set of BIRD functions for BGPFilter resources that have been packaged into KVPairs.
// By doing the formatting inside of this function we eliminate the need to copy and paste repeated blocks of golang
// template code into our BIRD config templates that is both difficult to read and prone to errors
//
// e.g. for a BGPFilter resource specified as follows:
//
// kind: BGPFilter
// apiVersion: projectcalico.org/v3
// metadata:
//
//	name: test-bgpfilter
//
// spec:
//
//	exportV4:
//	  - action: Accept
//	    matchOperator: In
//	    cidr: 77.0.0.0/16
//	  - action: Reject
//	    matchOperator: In
//	    cidr: 77.1.0.0/16
//	importV4:
//	  - action: Accept
//	    matchOperator: In
//	    cidr: 44.0.0.0/16
//	  - action: Reject
//	    matchOperator: In
//	    cidr: 44.1.0.0/16
//
// Would produce the following string array that can be easily output via BIRD config template:
//
//	[]string{
//	  "# v4 BGPFilter test-bgpfilter",
//	  "function 'bgp_test-bgpfilter_importFilterV4'() {",
//	  "  if ((net ~ 44.0.0.0/16)) then { accept; }",
//	  "  if ((net ~ 44.1.0.0/16)) then { reject; }",
//	  "}",
//	  "function 'bgp_test-bgpfilter_exportFilterV4'() {",
//	  "  if ((net ~ 77.0.0.0/16)) then { accept; }",
//	  "  if ((net ~ 77.1.0.0/16)) then { reject; }",
//	  "}",
//	 }
func BGPFilterBIRDFuncs(pairs memkv.KVPairs, version int) ([]string, error) {
	lines := []string{}
	var line string
	var versionStr string

	if version == 4 || version == 6 {
		versionStr = fmt.Sprintf("%d", version)
	} else {
		return []string{}, fmt.Errorf("version must be either 4 or 6")
	}

	for _, kvp := range pairs {
		var filter v3.BGPFilter
		err := json.Unmarshal([]byte(kvp.Value), &filter)
		if err != nil {
			return []string{}, fmt.Errorf("error unmarshalling JSON: %s", err)
		}

		importFiltersV4 := filter.Spec.ImportV4
		exportFiltersV4 := filter.Spec.ExportV4
		importFiltersV6 := filter.Spec.ImportV6
		exportFiltersV6 := filter.Spec.ExportV6

		var filterName string
		var emitImports bool
		var emitExports bool
		v4Selected := version == 4

		if v4Selected {
			emitImports = len(importFiltersV4) > 0
			emitExports = len(exportFiltersV4) > 0
		} else {
			emitImports = len(importFiltersV6) > 0
			emitExports = len(exportFiltersV6) > 0
		}

		if emitImports || emitExports {
			filterName = path.Base(kvp.Key)
			line = fmt.Sprintf("# v%s BGPFilter %s", versionStr, filterName)
			lines = append(lines, line)
		}

		var filterFuncName string
		var filterRule string
		if emitImports {
			filterFuncName, err = BGPFilterFunctionName(filterName, "import", versionStr)
			if err != nil {
				return []string{}, err
			}
			line = fmt.Sprintf("function %s() {", filterFuncName)
			lines = append(lines, line)

			var ruleFields []filterArgs

			if v4Selected {
				for _, importV4 := range importFiltersV4 {
					ruleFields = append(ruleFields, filterArgs{
						operator:       importV4.MatchOperator,
						cidr:           importV4.CIDR,
						prefixLengthV4: importV4.PrefixLength,
						source:         importV4.Source,
						iface:          importV4.Interface,
						action:         importV4.Action,
					})
				}
			} else {
				for _, importV6 := range importFiltersV6 {
					ruleFields = append(ruleFields, filterArgs{
						operator:       importV6.MatchOperator,
						cidr:           importV6.CIDR,
						prefixLengthV6: importV6.PrefixLength,
						source:         importV6.Source,
						iface:          importV6.Interface,
						action:         importV6.Action,
					})
				}
			}

			for _, fields := range ruleFields {
				filterRule, err = filterStatement(fields)
				if err != nil {
					return []string{}, err
				}
				line = fmt.Sprintf("  %s", filterRule)
				lines = append(lines, line)
			}

			line = "}"
			lines = append(lines, line)
		}

		if emitExports {
			filterFuncName, err = BGPFilterFunctionName(filterName, "export", versionStr)
			if err != nil {
				return []string{}, err
			}
			line = fmt.Sprintf("function %s() {", filterFuncName)
			lines = append(lines, line)

			var ruleFields []filterArgs

			if v4Selected {
				for _, exportV4 := range exportFiltersV4 {
					ruleFields = append(ruleFields, filterArgs{
						operator:       exportV4.MatchOperator,
						cidr:           exportV4.CIDR,
						prefixLengthV4: exportV4.PrefixLength,
						source:         exportV4.Source,
						iface:          exportV4.Interface,
						action:         exportV4.Action,
					})
				}
			} else {
				for _, exportV6 := range exportFiltersV6 {
					ruleFields = append(ruleFields, filterArgs{
						operator:       exportV6.MatchOperator,
						cidr:           exportV6.CIDR,
						prefixLengthV6: exportV6.PrefixLength,
						source:         exportV6.Source,
						iface:          exportV6.Interface,
						action:         exportV6.Action,
					})
				}
			}

			for _, fields := range ruleFields {
				filterRule, err = filterStatement(fields)
				if err != nil {
					return []string{}, err
				}
				line = fmt.Sprintf("  %s", filterRule)
				lines = append(lines, line)
			}

			line = "}"
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		line = fmt.Sprintf("# No v%s BGPFilters configured", versionStr)
		lines = append(lines, line)
	}
	return lines, nil
}

// hashToIPv4 is a wrapper for template use
func hashToIPv4(nodeName string) string {
	result, _ := HashToIPv4(nodeName)
	return result
}

// CreateMap creates a key-value map of string -> interface{}
// The i'th is the key and the i+1 is the value
func CreateMap(values ...any) (map[string]any, error) {
	if len(values)%2 != 0 {
		return nil, errors.New("invalid map call")
	}
	dict := make(map[string]any, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, errors.New("map keys must be strings")
		}
		dict[key] = values[i+1]
	}
	return dict, nil
}

func UnmarshalJsonObject(data string) (map[string]any, error) {
	var ret map[string]any
	err := json.Unmarshal([]byte(data), &ret)
	return ret, err
}

func UnmarshalJsonArray(data string) ([]any, error) {
	var ret []any
	err := json.Unmarshal([]byte(data), &ret)
	return ret, err
}

func LookupIP(data string) []string {
	ips, err := net.LookupIP(data)
	if err != nil {
		return nil
	}
	// "Cast" IPs into strings and sort the array
	ipStrings := make([]string, len(ips))

	for i, ip := range ips {
		ipStrings[i] = ip.String()
	}
	sort.Strings(ipStrings)
	return ipStrings
}

type sortSRV []*net.SRV

func (s sortSRV) Len() int {
	return len(s)
}

func (s sortSRV) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s sortSRV) Less(i, j int) bool {
	str1 := fmt.Sprintf("%s%d%d%d", s[i].Target, s[i].Port, s[i].Priority, s[i].Weight)
	str2 := fmt.Sprintf("%s%d%d%d", s[j].Target, s[j].Port, s[j].Priority, s[j].Weight)
	return str1 < str2
}

func LookupSRV(service, proto, name string) []*net.SRV {
	_, addrs, err := net.LookupSRV(service, proto, name)
	if err != nil {
		return []*net.SRV{}
	}
	sort.Sort(sortSRV(addrs))
	return addrs
}

func Base64Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func Base64Decode(data string) (string, error) {
	s, err := base64.StdEncoding.DecodeString(data)
	return string(s), err
}
