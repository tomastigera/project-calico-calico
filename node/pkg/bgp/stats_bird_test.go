// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package bgp

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func Test_parsePeers(t *testing.T) {
	// Set this to debug level so we can see detailed output when tests fail
	log.SetLevel(log.DebugLevel)

	type args struct {
		ipVer    Version
		filename string
	}
	tests := []struct {
		name    string
		args    args
		want    []Peer
		wantErr bool
	}{
		// Add test cases ...
		{
			name: "Successfully parse single peer",
			args: args{
				ipVer:    IPv4,
				filename: "test_parsePeers.1.data",
			},
			want: []Peer{
				Peer{
					PeerIP:   "10.128.0.78",
					PeerType: "node-to-node mesh",
					State:    "up",
					Since:    "06:31:44",
					BGPState: "Established",
					Info:     "",
					Details: PeerDetails{
						RouteCounts: PeerRouteCounts{
							NumImported:  1,
							NumExported:  1,
							NumPreferred: 1,
						},
						ImportUpdateCounts: PeerImportUpdateCounts{
							NumReceived: 2,
							NumRejected: 0,
							NumFiltered: 0,
							NumIgnored:  1,
							NumAccepted: 1,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Successfully parse single peer",
			args: args{
				ipVer:    IPv6,
				filename: "test_parsePeers.1.data",
			},
			want: []Peer{
				Peer{
					PeerIP:   "10:128:0:78",
					PeerType: "node-to-node mesh",
					State:    "up",
					Since:    "06:31:44",
					BGPState: "Established",
					Info:     "",
					Details: PeerDetails{
						RouteCounts: PeerRouteCounts{
							NumImported:  1,
							NumExported:  1,
							NumPreferred: 1,
						},
						ImportUpdateCounts: PeerImportUpdateCounts{
							NumReceived: 2,
							NumRejected: 0,
							NumFiltered: 0,
							NumIgnored:  1,
							NumAccepted: 1,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Successfully parse multiple peers",
			args: args{
				ipVer:    IPv4,
				filename: "test_parsePeers.2.data",
			},
			want: []Peer{
				Peer{
					PeerIP:   "10.128.0.83",
					PeerType: "node-to-node mesh",
					State:    "up",
					Since:    "06:31:30",
					BGPState: "Established",
					Info:     "",
					Details: PeerDetails{
						RouteCounts: PeerRouteCounts{
							NumImported:  1,
							NumExported:  1,
							NumPreferred: 1,
						},
						ImportUpdateCounts: PeerImportUpdateCounts{
							NumReceived: 2,
							NumRejected: 0,
							NumFiltered: 0,
							NumIgnored:  1,
							NumAccepted: 1,
						},
					},
				},
				Peer{
					PeerIP:   "10.128.0.22",
					PeerType: "global",
					State:    "up",
					Since:    "06:31:58",
					BGPState: "Established",
					Info:     "",
					Details: PeerDetails{
						RouteCounts: PeerRouteCounts{
							NumImported:  10,
							NumExported:  10,
							NumPreferred: 10,
						},
						ImportUpdateCounts: PeerImportUpdateCounts{
							NumReceived: 2,
							NumRejected: 0,
							NumFiltered: 0,
							NumIgnored:  1,
							NumAccepted: 1,
						},
					},
				},
				Peer{
					PeerIP:   "10.128.0.78",
					PeerType: "node specific",
					State:    "up",
					Since:    "06:31:44",
					BGPState: "Established",
					Info:     "",
					Details: PeerDetails{
						RouteCounts: PeerRouteCounts{
							NumImported:  1,
							NumExported:  1,
							NumPreferred: 1,
						},
						ImportUpdateCounts: PeerImportUpdateCounts{
							NumReceived: 2,
							NumRejected: 0,
							NumFiltered: 0,
							NumIgnored:  1,
							NumAccepted: 1,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Successfully parse multiple peers",
			args: args{
				ipVer:    IPv4,
				filename: "test_parsePeers.3.data",
			},
			want: []Peer{
				Peer{
					PeerIP:   "10.128.0.83",
					PeerType: "node-to-node mesh",
					State:    "up",
					Since:    "06:31:30",
					BGPState: "Established",
					Info:     "",
					Details: PeerDetails{
						RouteCounts: PeerRouteCounts{
							NumImported:  1,
							NumExported:  1,
							NumPreferred: 1,
						},
						ImportUpdateCounts: PeerImportUpdateCounts{
							NumReceived: 2,
							NumRejected: 0,
							NumFiltered: 0,
							NumIgnored:  1,
							NumAccepted: 1,
						},
					},
				},
				Peer{
					PeerIP:   "10.128.0.19",
					PeerType: "global",
					State:    "start",
					Since:    "22:19:52",
					BGPState: "Active",
					Info:     "Socket: Connection refused",
					Details: PeerDetails{
						RouteCounts: PeerRouteCounts{
							NumImported:  1,
							NumExported:  0,
							NumPreferred: 1,
						},
						ImportUpdateCounts: PeerImportUpdateCounts{
							NumReceived: 1,
							NumRejected: 0,
							NumFiltered: 0,
							NumIgnored:  0,
							NumAccepted: 1,
						},
					},
				},
				Peer{
					PeerIP:   "10.128.0.44",
					PeerType: "node specific",
					State:    "start",
					Since:    "22:19:56",
					BGPState: "Active",
					Info:     "Socket: Connection closed",
					Details: PeerDetails{
						RouteCounts: PeerRouteCounts{
							NumImported:  1,
							NumExported:  0,
							NumPreferred: 1,
						},
						ImportUpdateCounts: PeerImportUpdateCounts{
							NumReceived: 4,
							NumRejected: 0,
							NumFiltered: 0,
							NumIgnored:  3,
							NumAccepted: 1,
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := openTestFile(tt.args.filename)
			if err != nil {
				t.Errorf("test setup failed (%v), could not open file %v", err, tt.args.filename)
			}
			conn := newTestConn(f)
			got, err := parsePeers(tt.args.ipVer, conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePeers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePeers() = %v, want %v", got, tt.want)
			}
			_ = f.Close()
		})
	}
}

// TestPeer_parsePeerSummary tests the correctness of the parsePeerSummary function.
//
// The below are sample lines of output that parsePeerSummary understands how to parse.
// 1002-static1  Static   master   up     06:31:13
// 1002-kernel1  Kernel   master   up     06:31:13
// 1002-device1  Device   master   up     06:31:13
// 1002-direct1  Direct   master   up     06:31:13
// 1002-bfd1     BFD      master   up     06:31:13
// 1002-Mesh_10_128_0_83 BGP      master   up     06:31:29    Established
// 1002-Global_10_128_0_22 BGP      master   start  19:25:06    Active        Socket: Connection refused
// 1002-Node_10_128_0_78 BGP      master   up     06:31:43    Established
// 0000
func TestPeer_parsePeerSummary(t *testing.T) {
	// Set this to debug level so we can see detailed output when tests fail
	log.SetLevel(log.DebugLevel)

	type args struct {
		line        string
		ipSeparator string
	}
	tests := []struct {
		name       string
		fields     Peer
		args       args
		expectFail bool
	}{
		// Add test cases here ...
		{
			name:   "Should not extract Peer from BIRD output (first row of data)",
			fields: Peer{},
			args: args{
				line:        "1002-static1  Static   master   up     06:31:13",
				ipSeparator: delimiterIPv4,
			},
			expectFail: true,
		},
		{
			name: "Should successfully extract Peer from BIRD output, BGP state Established (first row of data)",
			fields: Peer{
				PeerIP:   "10.128.0.83",
				PeerType: "node-to-node mesh",
				State:    "up",
				Since:    "06:31:30",
				BGPState: "Established",
				Info:     "",
			},
			args: args{
				line:        "1002-Mesh_10_128_0_83 BGP      master   up     06:31:30    Established      ",
				ipSeparator: delimiterIPv4,
			},
			expectFail: false,
		},
		{
			name:   "Should not extract Peer from BIRD output proto Kernel",
			fields: Peer{},
			args: args{
				line:        "1002-kernel1  Kernel   master   up     06:31:14",
				ipSeparator: delimiterIPv4,
			},
			expectFail: true,
		},
		{
			name:   "Should not extract Peer from BIRD output proto Device",
			fields: Peer{},
			args: args{
				line:        "1002-device1  Device   master   up     06:31:14",
				ipSeparator: delimiterIPv4,
			},
			expectFail: true,
		},
		{
			name:   "Should not extract Peer from BIRD output proto Direct",
			fields: Peer{},
			args: args{
				line:        "1002-direct1  Direct   master   up     06:31:14",
				ipSeparator: delimiterIPv4,
			},
			expectFail: true,
		},
		{
			name:   "Should not extract Peer from BIRD output proto BFD",
			fields: Peer{},
			args: args{
				line:        "1002-bfd1     BFD      master   up     06:31:14",
				ipSeparator: delimiterIPv4,
			},
			expectFail: true,
		},
		{
			name:   "Should not extract Peer from BIRD output proto BGP (not valid name prefix)",
			fields: Peer{},
			args: args{
				line:        "1002-NotValid_10_128_0_22 BGP      master   start  19:25:06    Established",
				ipSeparator: delimiterIPv4,
			},
			expectFail: true,
		},
		{
			name: "Should successfully extract Peer from BIRD output BGP state Active",
			fields: Peer{
				PeerIP:   "10.128.0.22",
				PeerType: "node-to-node mesh",
				State:    "start",
				Since:    "19:25:06",
				BGPState: "Active",
				Info:     "Socket: Connection refused",
			},
			args: args{
				line:        "1002-Mesh_10_128_0_22 BGP      master   start  19:25:06    Active        Socket: Connection refused",
				ipSeparator: delimiterIPv4,
			},
			expectFail: false,
		},
		{
			name: "Should successfully extract Peer from BIRD output",
			fields: Peer{
				PeerIP:   "10.128.0.22",
				PeerType: "node-to-node mesh",
				State:    "start",
				Since:    "19:25:06",
				BGPState: "Connect",
				Info:     "Socket: No route to host",
			},
			args: args{
				line:        "1002-Mesh_10_128_0_22 BGP      master   start  19:25:06    Connect        Socket: No route to host",
				ipSeparator: delimiterIPv4,
			},
			expectFail: false,
		},
		{
			name: "Should successfully extract Peer from BIRD output",
			fields: Peer{
				PeerIP:   "fc00:0:1:6",
				PeerType: "node-to-node mesh",
				State:    "start",
				Since:    "19:25:06",
				BGPState: "Connect",
				Info:     "Socket: No route to host",
			},
			args: args{
				line:        "1002-Mesh_fc00_0_1_6 BGP      master   start  19:25:06    Connect        Socket: No route to host",
				ipSeparator: delimiterIPv6,
			},
			expectFail: false,
		},
		{
			name: "Should successfully extract Peer from BIRD output (Node)",
			fields: Peer{
				PeerIP:   "10.128.0.22",
				PeerType: "node specific",
				State:    "start",
				Since:    "19:25:06",
				BGPState: "Connect",
				Info:     "Socket: No route to host",
			},
			args: args{
				line:        "1002-Node_10_128_0_22 BGP      master   start  19:25:06    Connect        Socket: No route to host",
				ipSeparator: delimiterIPv4,
			},
			expectFail: false,
		},
		{
			name: "Should successfully extract Peer from BIRD output (Global)",
			fields: Peer{
				PeerIP:   "10.128.0.22",
				PeerType: "global",
				State:    "start",
				Since:    "19:25:06",
				BGPState: "Connect",
				Info:     "Socket: No route to host",
			},
			args: args{
				line:        "1002-Global_10_128_0_22 BGP      master   start  19:25:06    Connect        Socket: No route to host",
				ipSeparator: delimiterIPv4,
			},
			expectFail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := &Peer{
				PeerIP:   tt.fields.PeerIP,
				PeerType: tt.fields.PeerType,
				State:    tt.fields.State,
				Since:    tt.fields.Since,
				BGPState: tt.fields.BGPState,
				Info:     tt.fields.Info,
				Details:  PeerDetails{},
			}
			actual := &Peer{}
			passed := parsePeerSummary(tt.args.line, tt.args.ipSeparator, actual)
			// Ensure parsePeerSummary returns false when parsing of output is expected to fail
			if tt.expectFail == passed {
				t.Errorf("Peer.parsePeerSummary() = %+v, but expected to fail for line '%s'", passed, tt.args.line)
			}
			// Ensure parsePeerSummary returns Peer with correct values when Peer is expected
			if !tt.expectFail && !reflect.DeepEqual(*expected, *actual) {
				t.Errorf("Peer.parsePeerSummary() extracted %+v, expected %+v", actual, expected)
			}
		})
	}
}

// Sample output for test cases for Test_parsePeers()
const (
	parsePeerDetails1 = `1002-Mesh_10_128_0_83 BGP      master   up     06:31:30    Established
1006-  Description:    Connection to BGP peer
    Preference:     100
    Input filter:   ACCEPT
    Output filter:  calico_export_to_bgp_peers
    Routes:         1 imported, 1 exported, 1 preferred
    Route change stats:     received   rejected   filtered    ignored   accepted
        Import updates:              2          0          0          1          1
        Import withdraws:            0          0        ---          0          0
        Export updates:             26          6         18        ---          2
        Export withdraws:            0        ---        ---        ---          0
    BGP state:          Established
        Neighbor address: 10.128.0.83
        Neighbor AS:      64512
        Neighbor ID:      10.128.0.83
        Neighbor caps:    refresh enhanced-refresh restart-able llgr-aware AS4 add-path-rx add-path-tx
        Session:          internal multihop AS4 add-path-rx add-path-tx
        Source address:   10.128.0.82
        Hold timer:       151/240
        Keepalive timer:  28/80
`
	parsePeerDetails2 = `1002-static1  Static   master   up     06:31:14
	1006-  Preference:     200
	   Input filter:   ACCEPT
	   Output filter:  REJECT
	   Routes:         1 imported, 0 exported, 1 preferred
	   Route change stats:     received   rejected   filtered    ignored   accepted
		 Import updates:              1          0          0          0          1
		 Import withdraws:            0          0        ---          0          0
		 Export updates:              0          0          0        ---          0
		 Export withdraws:            0        ---        ---        ---          0	
`

	parsePeerDetails3 = `1002-Node_10_128_0_78 BGP      master   up     06:31:44    Active        Socket: No route to host
	1006-  Description:    Connection to BGP peer
	   Preference:     100
	   Input filter:   ACCEPT
	   Output filter:  calico_export_to_bgp_peers
	   Routes:         100 imported, 11 filtered, 31 exported, 40 preferred
	   Route change stats:     received   rejected   filtered    ignored   accepted
		 Import updates:            300         10         90         81        100
		 Import withdraws:            0          0        ---          0          0
		 Export updates:             26          6         18        ---          2
		 Export withdraws:            0        ---        ---        ---          0
	   BGP state:          Active
		 Neighbor address: 10.128.0.78
		 Neighbor AS:      64512
		 Neighbor ID:      10.128.0.78
		 Neighbor caps:    refresh enhanced-refresh restart-able llgr-aware AS4 add-path-rx add-path-tx
		 Session:          internal multihop AS4 add-path-rx add-path-tx
		 Source address:   10.128.0.82
		 Hold timer:       158/240
		 Keepalive timer:  46/80
		 Last error:       Socket: No route to host
`
)

// See preceeding const strings for sample BIRD output that parsePeerDetails understands how to parse.
func Test_parsePeerDetails(t *testing.T) {
	type args struct {
		output      string
		ipSeparator string
	}
	tests := []struct {
		name string
		args args
		want *Peer
	}{
		// Add test cases ...
		{
			name: "Successfully parse peer details (node-to-node mesh)",
			args: args{
				output:      parsePeerDetails1,
				ipSeparator: delimiterIPv4,
			},
			want: &Peer{
				PeerIP:   "10.128.0.83",
				PeerType: "node-to-node mesh",
				State:    "up",
				Since:    "06:31:30",
				BGPState: "Established",
				Info:     "",
				Details: PeerDetails{
					RouteCounts: PeerRouteCounts{
						NumImported:  1,
						NumExported:  1,
						NumPreferred: 1,
					},
					ImportUpdateCounts: PeerImportUpdateCounts{
						NumReceived: 2,
						NumRejected: 0,
						NumFiltered: 0,
						NumIgnored:  1,
						NumAccepted: 1,
					},
				},
			},
		},
		{
			name: "Fail to parse peer details",
			args: args{
				output:      parsePeerDetails2,
				ipSeparator: delimiterIPv4,
			},
			want: nil,
		},
		{
			name: "Successfully parse peer details (node specifc)",
			args: args{
				output:      parsePeerDetails3,
				ipSeparator: delimiterIPv4,
			},
			want: &Peer{
				PeerIP:   "10.128.0.78",
				PeerType: "node specific",
				State:    "up",
				Since:    "06:31:44",
				BGPState: "Active",
				Info:     "Socket: No route to host",
				Details: PeerDetails{
					RouteCounts: PeerRouteCounts{
						NumImported:  100,
						NumFiltered:  11,
						NumExported:  31,
						NumPreferred: 40,
					},
					ImportUpdateCounts: PeerImportUpdateCounts{
						NumReceived: 300,
						NumRejected: 10,
						NumFiltered: 90,
						NumIgnored:  81,
						NumAccepted: 100,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parsePeerDetails(tt.args.output, tt.args.ipSeparator); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePeerDetails() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ignoreRow(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		// Add test cases ...
		{name: "Successfully ignore row", line: "1006-   Preference:     100", want: true},
		{name: "Successfully ignore row", line: "   Input filter:   ACCEPT", want: true},
		{name: "Successfully ignore row", line: "   Output filter:  calico_export_to_bgp_peers", want: true},
		{name: "Successfully ignore row", line: "   Routes:         1 imported, 1 exported, 1 preferred", want: true},
		{name: "Successfully ignore row", line: "   Route change stats:     received   rejected   filtered    ignored   accepted", want: true},
		{name: "Successfully ignore row", line: "     Import updates:              2          0          0          1          1", want: true},
		{name: "Successfully ignore row", line: "     Import withdraws:            0          0        ---          0          0", want: true},
		{name: "Successfully ignore row", line: "     Export updates:             26          6         18        ---          2", want: true},
		{name: "Successfully ignore row", line: "     Export withdraws:            0        ---        ---        ---          0", want: true},
		{name: "Successfully ignore row", line: "   BGP state:          Established", want: true},
		{name: "Successfully ignore row", line: "     Neighbor address: 10.128.0.22", want: true},
		{name: "Successfully ignore row", line: "     Neighbor AS:      64512", want: true},
		{name: "Successfully ignore row", line: "     Neighbor ID:      10.128.0.22", want: true},
		{name: "Successfully ignore row", line: "     Neighbor caps:    refresh enhanced-refresh restart-able llgr-aware AS4 add-path-rx add-path-tx", want: true},
		{name: "Successfully ignore row", line: "     Session:          internal multihop AS4 add-path-rx add-path-tx", want: true},
		{name: "Successfully ignore row", line: "     Source address:   10.128.0.82", want: true},
		{name: "Successfully ignore row", line: "     Hold timer:       224/240", want: true},
		{name: "Successfully ignore row", line: "     Keepalive timer:  47/80", want: true},
		{name: "Fail to ignore row (empty string)", line: "", want: false},
		{name: "Fail to ignore row (no starting spaces)", line: "1002-  Description:    Connection to BGP peer", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ignoreRow(tt.line); got != tt.want {
				t.Errorf("ignoreRow() = %v, want %v for line %v", got, tt.want, tt.line)
			}
		})
	}
}

func Test_parseRoutes(t *testing.T) {
	type args struct {
		line string
		prc  *PeerRouteCounts
	}
	tests := []struct {
		name   string
		args   args
		want   bool
		expect *PeerRouteCounts
	}{
		// Add test case ...
		{
			name: "Successfully parse routes (3 categories)",
			args: args{
				line: " Routes:         1 imported, 1 exported, 1 preferred",
				prc:  &PeerRouteCounts{},
			},
			want: true,
			expect: &PeerRouteCounts{
				NumExported:  1,
				NumFiltered:  0,
				NumImported:  1,
				NumPreferred: 1,
			},
		},
		{
			name: "Successfully parse routes (4 categories)",
			args: args{
				line: " Routes:         1 imported, 1 exported, 1 preferred, 3 filtered",
				prc:  &PeerRouteCounts{},
			},
			want: true,
			expect: &PeerRouteCounts{
				NumExported:  1,
				NumFiltered:  3,
				NumImported:  1,
				NumPreferred: 1,
			},
		},
		{
			name: "Fail to parse (missing starting whitespace)",
			args: args{
				line: "Routes:         1 imported, 1 exported, 1 preferred",
				prc:  &PeerRouteCounts{},
			},
			want:   false,
			expect: &PeerRouteCounts{},
		},
		{
			name: "Fail to parse (unknown category)",
			args: args{
				line: "Routes:         1 imported, 1 exported, 1 preferred, 5 deported",
				prc:  &PeerRouteCounts{},
			},
			want:   false,
			expect: &PeerRouteCounts{},
		},
		{
			name: "Fail to parse (unknown category)",
			args: args{
				line: "Routes:         -1 imported, 1 exported, 1 preferred",
				prc:  &PeerRouteCounts{},
			},
			want:   false,
			expect: &PeerRouteCounts{},
		},
		{
			name: "Fail to parse (unknown category)",
			args: args{
				line: "Routes:         1",
				prc:  &PeerRouteCounts{},
			},
			want:   false,
			expect: &PeerRouteCounts{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseRoutes(tt.args.line, tt.args.prc); got != tt.want {
				t.Errorf("parseRoutes() = %v, want %v for line '%v'", got, tt.want, tt.args.line)
			} else if got && !reflect.DeepEqual(tt.args.prc, tt.expect) {
				t.Errorf("parseRoutes() parsed into %+v, want %+v for line '%v'", tt.args.prc, tt.expect, tt.args.line)
			}
		})
	}
}

func Test_parseImportUpdates(t *testing.T) {
	type args struct {
		line string
		iuc  *PeerImportUpdateCounts
	}
	tests := []struct {
		name   string
		args   args
		want   bool
		expect *PeerImportUpdateCounts
	}{
		// Add test cases ...
		{
			name: "Successfully parse import update line",
			args: args{
				line: "  Import updates:              2          0          0          1          1",
				iuc:  &PeerImportUpdateCounts{},
			},
			want: true,
			expect: &PeerImportUpdateCounts{
				NumReceived: 2,
				NumRejected: 0,
				NumFiltered: 0,
				NumIgnored:  1,
				NumAccepted: 1,
			},
		},
		{
			name: "Fail to parse due to wrong format (missing beginning spaces)",
			args: args{
				line: "Import updates:              2          0          0          1          1",
				iuc:  &PeerImportUpdateCounts{},
			},
			want:   false,
			expect: &PeerImportUpdateCounts{},
		},
		{
			name: "Fail to parse due to wrong format (not numeric values)",
			args: args{
				line: " Import updates:              s          s          s          s          1",
				iuc:  &PeerImportUpdateCounts{},
			},
			want:   false,
			expect: &PeerImportUpdateCounts{},
		},
		{
			name: "Fail to parse due to wrong format (missing column)",
			args: args{
				line: " Import updates:              1          0          1               1",
				iuc:  &PeerImportUpdateCounts{},
			},
			want:   false,
			expect: &PeerImportUpdateCounts{},
		},
		{
			name: "Fail to parse due to wrong format (invalid value)",
			args: args{
				line: " Import updates:       -       2          0          1               1",
				iuc:  &PeerImportUpdateCounts{},
			},
			want:   false,
			expect: &PeerImportUpdateCounts{},
		},
		{
			name: "Fail to parse due to wrong format (invalid value)",
			args: args{
				line: " Import updates:       -1       2          0          1               1",
				iuc:  &PeerImportUpdateCounts{},
			},
			want:   false,
			expect: &PeerImportUpdateCounts{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseImportUpdates(tt.args.line, tt.args.iuc); got != tt.want {
				t.Errorf("parseImportUpdates() = %v, want %v for line %v", got, tt.want, tt.args.line)
			} else if got && !reflect.DeepEqual(tt.args.iuc, tt.expect) {
				t.Errorf("parseImportUpdates() parsed into %+v, want %+v for line %v", tt.args.iuc, tt.expect, tt.args.line)
			}
		})
	}
}

func Test_applyParsers(t *testing.T) {
	type args struct {
		line    string
		parsers []func(s string) bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// Add test cases ...
		{
			name: "Successfully parse string",
			args: args{
				line: "s",
				parsers: []func(s string) bool{
					func(s string) bool { return true },
				},
			},
			want: true,
		},
		{
			name: "Fail to parse string",
			args: args{
				line: "s",
				parsers: []func(s string) bool{
					func(s string) bool { return false },
				},
			},
			want: false,
		},
		{
			name: "Successfully parse string (more than one parser)",
			args: args{
				line: "s",
				parsers: []func(s string) bool{
					func(s string) bool { return s == "" },
					func(s string) bool { return s == "s" },
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := applyParsers(tt.args.line, tt.args.parsers); got != tt.want {
				t.Errorf("applyParsers() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The following is sample output from BIRD
//
// 0001 BIRD v0.3.2+birdv1.6.3 ready.
// 1000-BIRD v0.3.2+birdv1.6.3
// 1011-Router ID is 172.18.0.4
//
//	Current server time is 2018-04-03 22:59:51
//	Last reboot on 2018-04-03 22:59:26
//	Last reconfiguration on 2018-04-03 22:59:26
//
// 0024-Graceful restart recovery in progress
//
//	Waiting for 1 protocols to recover
//	Wait timer is 215/240
//
// 0013 Daemon is up and running
func Test_containsGracefulRestart(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		expectGR   bool
		expectStop bool
		expectErr  bool
	}{
		// Add test cases ...
		{
			name:       "Should detect no GR, no stop, no erro on welcome liner",
			line:       "0001 BIRD v0.3.2+birdv1.6.3 ready.",
			expectGR:   false,
			expectStop: false,
			expectErr:  false,
		},
		{
			name:       "Should detect no GR, no stop, no error on BIRD version",
			line:       "1000-BIRD v0.3.2+birdv1.6.3",
			expectGR:   false,
			expectStop: false,
			expectErr:  false,
		},
		{
			name:       "Should detect no GR, no stop, no error on uptime line",
			line:       "1011-Router ID is 172.18.0.4",
			expectGR:   false,
			expectStop: false,
			expectErr:  false,
		},
		{
			name:       "Should detect no GR, no stop, no error on current server line",
			line:       "     Current server time is 2018-04-03 22:59:51",
			expectGR:   false,
			expectStop: false,
			expectErr:  false,
		},
		{
			name:       "Should detect no GR, no stop, no error on last reboot line",
			line:       "     Last reboot on 2018-04-03 22:59:26",
			expectGR:   false,
			expectStop: false,
			expectErr:  false,
		},
		{
			name:       "Should detect no GR, no stop, no error on last config line",
			line:       "     Last reconfiguration on 2018-04-03 22:59:26",
			expectGR:   false,
			expectStop: false,
			expectErr:  false,
		},
		{
			name:       "Should detect GR",
			line:       "0024-Graceful restart recovery in progress",
			expectGR:   true,
			expectStop: false,
			expectErr:  false,
		},
		{
			name:       "Should detect no GR, no stop, no error on waiting protocol line",
			line:       "     Waiting for 1 protocols to recover",
			expectGR:   false,
			expectStop: false,
			expectErr:  false,
		},
		{
			name:       "Should detect no GR, no stop, no error on waiting timer line",
			line:       "     Wait timer is 215/240",
			expectGR:   false,
			expectStop: false,
			expectErr:  false,
		},
		{
			name:       "Should detect stop",
			line:       "0013 Daemon is up and running",
			expectGR:   false,
			expectStop: true,
			expectErr:  false,
		},
		{
			name:       "Should detect error",
			line:       "0015 Reloading",
			expectGR:   false,
			expectStop: false,
			expectErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualGR, actualStop, err := containsGracefulRestart(tt.line)
			if (err != nil) != tt.expectErr {
				t.Errorf("containsGracefulRestart() error = %+v, expectErr %v", err, tt.expectErr)
			}
			if err != nil {
				if _, ok := err.(*ParseError); !ok {
					t.Errorf("containsGracefulRestart() error = %v, should be of type ParseError", err)
				}
			}
			if actualGR != tt.expectGR {
				t.Errorf("containsGracefulRestart() actualGR = %v, expected %v", actualGR, tt.expectGR)
			}
			if actualStop != tt.expectStop {
				t.Errorf("containsGracefulRestart() actualStop = %v, expected %v", actualStop, tt.expectStop)
			}
		})
	}
}

func Test_isEmptyString(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		// Add test cases ...
		{name: "Is empty string (empty string)", value: "", want: true},
		{name: "Is empty string (with spaces)", value: "   ", want: true},
		{name: "Is empty string (with tabs)", value: "		", want: true},
		{name: "Is empty string (with newline)", value: `
		`, want: true},
		{name: "Is not empty string (non-space chars)", value: "saas", want: false},
		{name: "Is not empty string (space + non-space chars)", value: "    cali	", want: false},
		{name: "Is not empty string (space + non-space chars)", value: `	co
		`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEmptyString(tt.value); got != tt.want {
				t.Errorf("isEmptyString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseInt(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  uint32
	}{
		// Add test cases ...
		{name: "Successfully parse string to uint32", value: "1", want: 1},
		{name: "Successfully parse string to uint32 (max value)", value: "4294967295", want: 4294967295},
		{name: "Fail to string to uint32 (overflow value)", value: "4294967296", want: 0},
		{name: "Fail to parse string to uint32 (decimal)", value: "101.11", want: 0},
		{name: "Fail to parse string to uint32 (negative value)", value: "-1", want: 0},
		{name: "Fail to parse string to uint32 (NaN)", value: "notvalid", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseInt(tt.value); got != tt.want {
				t.Errorf("parseInt() = %v, want %v, for value '%v'", got, tt.want, tt.value)
			}
		})
	}
}

func openTestFile(filename string) (*os.File, error) {
	return os.Open(filepath.Join("testdata", filename))
}

// testConn is used to provide a mock for parsePeers function
type testConn struct {
	r  io.Reader
	ta *testAddr
}

// newTestConn returns a new testConn that wraps a strings.Reader reading from s.
// This will simulate output coming from BIRD socket.

func newTestConn(r io.Reader) *testConn {
	return &testConn{
		r:  r,
		ta: &testAddr{},
	}
}

// Read simply wraps the Read method of the strings.Reader object within the testConn.
func (tc *testConn) Read(b []byte) (n int, err error) {
	return tc.r.Read(b)
}

// Write is a dummy stub.
func (tc *testConn) Write(b []byte) (n int, err error) {
	return 0, nil
}

// Close is a dummy stub.
func (tc *testConn) Close() error {
	return nil
}

// LocalAddr is a dummy stub.
func (tc *testConn) LocalAddr() net.Addr {
	return tc.ta
}

// RemoteAddr is a dummy stub.
func (tc *testConn) RemoteAddr() net.Addr {
	return tc.ta
}

// SetDeadline is a dummy stub.
func (tc *testConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline is a dummy stub.
func (tc *testConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline is a dummy stub.
func (tc *testConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// testAddr is used to provide a mock for LocalAddr() and RemoteAddr() of testConn
type testAddr struct{}

// name of the network (for example, "tcp", "udp")
func (ta *testAddr) Network() string {
	return "tcp"
}

// string form of address (for example, "192.0.2.1:25", "[2001:db8::1]:80")
func (ta *testAddr) String() string {
	return "127.0.0.1"
}
