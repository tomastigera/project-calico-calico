// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package v1_test

import (
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	. "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

var (
	// Define sets of statistics used to test aggregation is correct. The second set of stats is split into separate
	// stats with other stats being nil.
	// These stats should result in the same data irrespective of the order they are combined.
	firstStats = GraphStats{
		L3: &GraphL3Stats{
			Allowed: &GraphPacketStats{
				PacketsIn:  1,
				PacketsOut: 2,
				BytesIn:    3,
				BytesOut:   5,
			},
			DeniedAtSource: &GraphPacketStats{
				PacketsIn:  7,
				PacketsOut: 11,
				BytesIn:    13,
				BytesOut:   17,
			},
			DeniedAtDest: &GraphPacketStats{
				PacketsIn:  19,
				PacketsOut: 23,
				BytesIn:    29,
				BytesOut:   31,
			},
			Connections: GraphConnectionStats{
				TotalPerSampleInterval: 37,
				Started:                41,
				Completed:              43,
			},
			TCP: &GraphTCPStats{
				SumTotalRetransmissions:  47,
				SumLostPackets:           53,
				SumUnrecoveredTo:         59,
				MinSendCongestionWindow:  61,
				MinSendMSS:               67,
				MaxSmoothRTT:             71,
				MaxMinRTT:                73,
				MeanSendCongestionWindow: 79,
				MeanSmoothRTT:            83,
				MeanMinRTT:               89,
				MeanMSS:                  97,
				Count:                    1,
			},
		},
		L7: &GraphL7Stats{
			NoResponse: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  136,
					BytesOut: 138,
				},
				MeanDuration: 148,
				MinDuration:  150,
				MaxDuration:  156,
				Count:        1,
			},
			ResponseCode1xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  103,
					BytesOut: 107,
				},
				MeanDuration: 109,
				MinDuration:  113,
				MaxDuration:  127,
				Count:        1,
			},
			ResponseCode2xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  137,
					BytesOut: 139,
				},
				MeanDuration: 149,
				MinDuration:  151,
				MaxDuration:  157,
				Count:        1,
			},
			ResponseCode3xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  167,
					BytesOut: 173,
				},
				MeanDuration: 179,
				MinDuration:  181,
				MaxDuration:  191,
				Count:        1,
			},
			ResponseCode4xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  197,
					BytesOut: 199,
				},
				MeanDuration: 211,
				MinDuration:  223,
				MaxDuration:  227,
				Count:        1,
			},
			ResponseCode5xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  233,
					BytesOut: 239,
				},
				MeanDuration: 241,
				MinDuration:  251,
				MaxDuration:  257,
				Count:        1,
			},
		},
		Processes: &GraphProcesses{
			Source: map[string]GraphEndpointProcess{
				"source1": {
					Name:               "source1",
					MinNumNamesPerFlow: 269,
					MaxNumNamesPerFlow: 271,
					MinNumIDsPerFlow:   277,
					MaxNumIDsPerFlow:   281,
				},
			},
			Dest: map[string]GraphEndpointProcess{
				"dest1": {
					Name:               "dest1",
					MinNumNamesPerFlow: 283,
					MaxNumNamesPerFlow: 293,
					MinNumIDsPerFlow:   307,
					MaxNumIDsPerFlow:   311,
				},
			},
		},
		DNS: &GraphDNSStats{
			GraphLatencyStats: GraphLatencyStats{
				MeanRequestLatency: 269,
				MaxRequestLatency:  293,
				MinRequestLatency:  271,
				LatencyCount:       10,
			},
			ResponseCodes: map[string]GraphDNSResponseCode{
				"NXDOMAIN": {
					Code:  "NXDOMAIN",
					Count: 10,
					GraphLatencyStats: GraphLatencyStats{
						MeanRequestLatency: 269,
						MaxRequestLatency:  293,
						MinRequestLatency:  271,
						LatencyCount:       10,
					},
				},
			},
		},
	}
	secondL3Stats = GraphStats{
		L3: &GraphL3Stats{
			Allowed: &GraphPacketStats{
				PacketsIn:  313,
				PacketsOut: 317,
				BytesIn:    331,
				BytesOut:   337,
			},
			DeniedAtDest: &GraphPacketStats{
				PacketsIn:  367,
				PacketsOut: 373,
				BytesIn:    379,
				BytesOut:   383,
			},
			Connections: GraphConnectionStats{
				TotalPerSampleInterval: 389,
				Started:                397,
				Completed:              401,
			},
		},
	}
	secondL7Stats = GraphStats{
		L7: &GraphL7Stats{
			ResponseCode1xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  467,
					BytesOut: 469,
				},
				MeanDuration: 487,
				MinDuration:  491,
				MaxDuration:  499,
				Count:        2,
			},
			ResponseCode3xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  509,
					BytesOut: 521,
				},
				MeanDuration: 523,
				MinDuration:  541,
				MaxDuration:  547,
				Count:        2,
			},
			ResponseCode5xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  563,
					BytesOut: 569,
				},
				MeanDuration: 571,
				MinDuration:  577,
				MaxDuration:  587,
				Count:        2,
			},
		},
	}
	secondProcessStats = GraphStats{
		Processes: &GraphProcesses{
			Source: map[string]GraphEndpointProcess{
				"source1": {
					Name:               "source1",
					MinNumNamesPerFlow: 599,
					MaxNumNamesPerFlow: 601,
					MinNumIDsPerFlow:   607,
					MaxNumIDsPerFlow:   613,
				},
				"source2": {
					Name:               "source2",
					MinNumNamesPerFlow: 617,
					MaxNumNamesPerFlow: 619,
					MinNumIDsPerFlow:   631,
					MaxNumIDsPerFlow:   641,
				},
			},
		},
	}
	secondDNSStats = GraphStats{
		DNS: &GraphDNSStats{
			GraphLatencyStats: GraphLatencyStats{
				MeanRequestLatency: 1,
				MaxRequestLatency:  3,
				MinRequestLatency:  5,
				LatencyCount:       1,
			},
			ResponseCodes: map[string]GraphDNSResponseCode{
				"NOERROR": {
					Code:  "NOERROR",
					Count: 2,
					GraphLatencyStats: GraphLatencyStats{
						MeanRequestLatency: 1,
						MaxRequestLatency:  3,
						MinRequestLatency:  5,
						LatencyCount:       1,
					},
				},
			},
		},
	}
	thirdStats = GraphStats{
		L3: &GraphL3Stats{
			DeniedAtSource: &GraphPacketStats{
				PacketsIn:  661,
				PacketsOut: 673,
				BytesIn:    677,
				BytesOut:   683,
			},
			Connections: GraphConnectionStats{
				TotalPerSampleInterval: 727,
				Started:                733,
				Completed:              739,
			},
			TCP: &GraphTCPStats{
				SumTotalRetransmissions:  743,
				SumLostPackets:           751,
				SumUnrecoveredTo:         757,
				MinSendCongestionWindow:  761,
				MinSendMSS:               769,
				MaxSmoothRTT:             773,
				MaxMinRTT:                787,
				MeanSendCongestionWindow: 797,
				MeanSmoothRTT:            809,
				MeanMinRTT:               811,
				MeanMSS:                  821,
				Count:                    3,
			},
		},
		L7: &GraphL7Stats{
			NoResponse: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  826,
					BytesOut: 828,
				},
				MeanDuration: 838,
				MinDuration:  852,
				MaxDuration:  856,
				Count:        3,
			},
			ResponseCode2xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  827,
					BytesOut: 829,
				},
				MeanDuration: 839,
				MinDuration:  853,
				MaxDuration:  857,
				Count:        3,
			},
			ResponseCode4xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  863,
					BytesOut: 877,
				},
				MeanDuration: 881,
				MinDuration:  883,
				MaxDuration:  887,
				Count:        3,
			},
		},
		Processes: &GraphProcesses{
			Dest: map[string]GraphEndpointProcess{
				"dest1": {
					Name:               "dest1",
					MinNumNamesPerFlow: 911,
					MaxNumNamesPerFlow: 919,
					MinNumIDsPerFlow:   929,
					MaxNumIDsPerFlow:   937,
				},
				"dest2": {
					Name:               "dest2",
					MinNumNamesPerFlow: 941,
					MaxNumNamesPerFlow: 947,
					MinNumIDsPerFlow:   953,
					MaxNumIDsPerFlow:   967,
				},
			},
		},
		DNS: &GraphDNSStats{
			GraphLatencyStats: GraphLatencyStats{
				MeanRequestLatency: 10,
				MaxRequestLatency:  11,
				MinRequestLatency:  12,
				LatencyCount:       2,
			},
			ResponseCodes: map[string]GraphDNSResponseCode{
				"NOERROR": {
					Code:  "NOERROR",
					Count: 4,
					GraphLatencyStats: GraphLatencyStats{
						MeanRequestLatency: 13,
						MaxRequestLatency:  14,
						MinRequestLatency:  15,
						LatencyCount:       3,
					},
				},
				"NXDOMAIN": {
					Code:  "NXDOMAIN",
					Count: 1,
					GraphLatencyStats: GraphLatencyStats{
						MeanRequestLatency: 16,
						MaxRequestLatency:  17,
						MinRequestLatency:  18,
						LatencyCount:       1,
					},
				},
			},
		},
	}
	firstSecondCombinedStats = GraphStats{
		L3: &GraphL3Stats{
			Allowed: &GraphPacketStats{
				PacketsIn:  1 + 313,
				PacketsOut: 2 + 317,
				BytesIn:    3 + 331,
				BytesOut:   5 + 337,
			},
			DeniedAtSource: &GraphPacketStats{
				PacketsIn:  7,
				PacketsOut: 11,
				BytesIn:    13,
				BytesOut:   17,
			},
			DeniedAtDest: &GraphPacketStats{
				PacketsIn:  19 + 367,
				PacketsOut: 23 + 373,
				BytesIn:    29 + 379,
				BytesOut:   31 + 383,
			},
			Connections: GraphConnectionStats{
				TotalPerSampleInterval: 37 + 389,
				Started:                41 + 397,
				Completed:              43 + 401,
			},
			TCP: &GraphTCPStats{
				SumTotalRetransmissions:  47,
				SumLostPackets:           53,
				SumUnrecoveredTo:         59,
				MinSendCongestionWindow:  61,
				MinSendMSS:               67,
				MaxSmoothRTT:             71,
				MaxMinRTT:                73,
				MeanSendCongestionWindow: 79,
				MeanSmoothRTT:            83,
				MeanMinRTT:               89,
				MeanMSS:                  97,
				Count:                    1,
			},
		},
		L7: &GraphL7Stats{
			NoResponse: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  136,
					BytesOut: 138,
				},
				MeanDuration: 148,
				MinDuration:  150,
				MaxDuration:  156,
				Count:        1,
			},
			ResponseCode1xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  103 + 467,
					BytesOut: 107 + 469,
				},
				MeanDuration: float64((109*1)+(487*2)) / float64(3),
				MinDuration:  113,
				MaxDuration:  499,
				Count:        3,
			},
			ResponseCode2xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  137,
					BytesOut: 139,
				},
				MeanDuration: 149,
				MinDuration:  151,
				MaxDuration:  157,
				Count:        1,
			},
			ResponseCode3xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  167 + 509,
					BytesOut: 173 + 521,
				},
				MeanDuration: float64((179*1)+(523*2)) / float64(3),
				MinDuration:  181,
				MaxDuration:  547,
				Count:        3,
			},
			ResponseCode4xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  197,
					BytesOut: 199,
				},
				MeanDuration: 211,
				MinDuration:  223,
				MaxDuration:  227,
				Count:        1,
			},
			ResponseCode5xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  233 + 563,
					BytesOut: 239 + 569,
				},
				MeanDuration: float64((241*1)+(571*2)) / float64(3),
				MinDuration:  251,
				MaxDuration:  587,
				Count:        3,
			},
		},
		Processes: &GraphProcesses{
			Source: map[string]GraphEndpointProcess{
				"source1": {
					Name:               "source1",
					MinNumNamesPerFlow: 269,
					MaxNumNamesPerFlow: 601,
					MinNumIDsPerFlow:   277,
					MaxNumIDsPerFlow:   613,
				},
				"source2": {
					Name:               "source2",
					MinNumNamesPerFlow: 617,
					MaxNumNamesPerFlow: 619,
					MinNumIDsPerFlow:   631,
					MaxNumIDsPerFlow:   641,
				},
			},
			Dest: map[string]GraphEndpointProcess{
				"dest1": {
					Name:               "dest1",
					MinNumNamesPerFlow: 283,
					MaxNumNamesPerFlow: 293,
					MinNumIDsPerFlow:   307,
					MaxNumIDsPerFlow:   311,
				},
			},
		},
		DNS: &GraphDNSStats{
			GraphLatencyStats: GraphLatencyStats{
				MeanRequestLatency: float64((269*10)+(1*1)) / float64(11),
				MaxRequestLatency:  293,
				MinRequestLatency:  5,
				LatencyCount:       11,
			},
			ResponseCodes: map[string]GraphDNSResponseCode{
				"NOERROR": {
					Code:  "NOERROR",
					Count: 2,
					GraphLatencyStats: GraphLatencyStats{
						MeanRequestLatency: 1,
						MaxRequestLatency:  3,
						MinRequestLatency:  5,
						LatencyCount:       1,
					},
				},
				"NXDOMAIN": {
					Code:  "NXDOMAIN",
					Count: 10,
					GraphLatencyStats: GraphLatencyStats{
						MeanRequestLatency: 269,
						MaxRequestLatency:  293,
						MinRequestLatency:  271,
						LatencyCount:       10,
					},
				},
			},
		},
	}
	firstSecondThirdCombinedStats = GraphStats{
		L3: &GraphL3Stats{
			Allowed: &GraphPacketStats{
				PacketsIn:  1 + 313,
				PacketsOut: 2 + 317,
				BytesIn:    3 + 331,
				BytesOut:   5 + 337,
			},
			DeniedAtSource: &GraphPacketStats{
				PacketsIn:  7 + 661,
				PacketsOut: 11 + 673,
				BytesIn:    13 + 677,
				BytesOut:   17 + 683,
			},
			DeniedAtDest: &GraphPacketStats{
				PacketsIn:  19 + 367,
				PacketsOut: 23 + 373,
				BytesIn:    29 + 379,
				BytesOut:   31 + 383,
			},
			Connections: GraphConnectionStats{
				TotalPerSampleInterval: 37 + 389 + 727,
				Started:                41 + 397 + 733,
				Completed:              43 + 401 + 739,
			},
			TCP: &GraphTCPStats{
				SumTotalRetransmissions:  47 + 743,
				SumLostPackets:           53 + 751,
				SumUnrecoveredTo:         59 + 757,
				MinSendCongestionWindow:  61,
				MinSendMSS:               67,
				MaxSmoothRTT:             773,
				MaxMinRTT:                787,
				MeanSendCongestionWindow: float64((79*1)+(797*3)) / float64(4),
				MeanSmoothRTT:            float64((83*1)+(809*3)) / float64(4),
				MeanMinRTT:               float64((89*1)+(811*3)) / float64(4),
				MeanMSS:                  float64((97*1)+(821*3)) / float64(4),
				Count:                    4,
			},
		},
		L7: &GraphL7Stats{
			NoResponse: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  136 + 826,
					BytesOut: 138 + 828,
				},
				MeanDuration: float64((148*1)+(838*3)) / float64(4),
				MinDuration:  150,
				MaxDuration:  856,
				Count:        4,
			},
			ResponseCode1xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  103 + 467,
					BytesOut: 107 + 469,
				},
				MeanDuration: ((109 * 1) + (487 * 2)) / 3,
				MinDuration:  113,
				MaxDuration:  499,
				Count:        3,
			},
			ResponseCode2xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  137 + 827,
					BytesOut: 139 + 829,
				},
				MeanDuration: float64((149*1)+(839*3)) / float64(4),
				MinDuration:  151,
				MaxDuration:  857,
				Count:        4,
			},
			ResponseCode3xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  167 + 509,
					BytesOut: 173 + 521,
				},
				MeanDuration: float64((179*1)+(523*2)) / float64(3),
				MinDuration:  181,
				MaxDuration:  547,
				Count:        3,
			},
			ResponseCode4xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  197 + 863,
					BytesOut: 199 + 877,
				},
				MeanDuration: float64((211*1)+(881*3)) / float64(4),
				MinDuration:  223,
				MaxDuration:  887,
				Count:        4,
			},
			ResponseCode5xx: GraphL7PacketStats{
				GraphByteStats: GraphByteStats{
					BytesIn:  233 + 563,
					BytesOut: 239 + 569,
				},
				MeanDuration: float64((241*1)+(571*2)) / float64(3),
				MinDuration:  251,
				MaxDuration:  587,
				Count:        3,
			},
		},
		Processes: &GraphProcesses{
			Source: map[string]GraphEndpointProcess{
				"source1": {
					Name:               "source1",
					MinNumNamesPerFlow: 269,
					MaxNumNamesPerFlow: 601,
					MinNumIDsPerFlow:   277,
					MaxNumIDsPerFlow:   613,
				},
				"source2": {
					Name:               "source2",
					MinNumNamesPerFlow: 617,
					MaxNumNamesPerFlow: 619,
					MinNumIDsPerFlow:   631,
					MaxNumIDsPerFlow:   641,
				},
			},
			Dest: map[string]GraphEndpointProcess{
				"dest1": {
					Name:               "dest1",
					MinNumNamesPerFlow: 283,
					MaxNumNamesPerFlow: 919,
					MinNumIDsPerFlow:   307,
					MaxNumIDsPerFlow:   937,
				},
				"dest2": {
					Name:               "dest2",
					MinNumNamesPerFlow: 941,
					MaxNumNamesPerFlow: 947,
					MinNumIDsPerFlow:   953,
					MaxNumIDsPerFlow:   967,
				},
			},
		},
		DNS: &GraphDNSStats{
			GraphLatencyStats: GraphLatencyStats{
				MeanRequestLatency: float64((269*10)+(1*1)+(10*2)) / float64(13),
				MaxRequestLatency:  293,
				MinRequestLatency:  5,
				LatencyCount:       13,
			},
			ResponseCodes: map[string]GraphDNSResponseCode{
				"NOERROR": {
					Code:  "NOERROR",
					Count: 6,
					GraphLatencyStats: GraphLatencyStats{
						MeanRequestLatency: float64((1*1)+(13*3)) / float64(4),
						MaxRequestLatency:  14,
						MinRequestLatency:  5,
						LatencyCount:       4,
					},
				},
				"NXDOMAIN": {
					Code:  "NXDOMAIN",
					Count: 11,
					GraphLatencyStats: GraphLatencyStats{
						MeanRequestLatency: float64((269*10)+(16*1)) / float64(11),
						MaxRequestLatency:  293,
						MinRequestLatency:  18,
						LatencyCount:       11,
					},
				},
			},
		},
	}
)

func expectStats(actual, expected GraphStats, desc string) {
	// Check individual sections of the stats for easier comparison when things go wrong.
	if expected.L3 == nil {
		Expect(actual.L3).To(BeNil())
	} else {
		Expect(actual.L3.Allowed).To(Equal(expected.L3.Allowed), desc)
		Expect(actual.L3.DeniedAtSource).To(Equal(expected.L3.DeniedAtSource), desc)
		Expect(actual.L3.DeniedAtDest).To(Equal(expected.L3.DeniedAtDest), desc)
		Expect(actual.L3.TCP).To(Equal(expected.L3.TCP), desc)
		Expect(actual.L3.Connections).To(Equal(expected.L3.Connections), desc)
	}

	if expected.L7 == nil {
		Expect(actual.L7).To(BeNil())
	} else {
		Expect(actual.L7.ResponseCode1xx).To(Equal(expected.L7.ResponseCode1xx), desc)
		Expect(actual.L7.ResponseCode2xx).To(Equal(expected.L7.ResponseCode2xx), desc)
		Expect(actual.L7.ResponseCode3xx).To(Equal(expected.L7.ResponseCode3xx), desc)
		Expect(actual.L7.ResponseCode4xx).To(Equal(expected.L7.ResponseCode4xx), desc)
		Expect(actual.L7.ResponseCode5xx).To(Equal(expected.L7.ResponseCode5xx), desc)
	}

	if expected.Processes == nil {
		Expect(actual.Processes).To(BeNil())
	} else {
		Expect(actual.Processes.Source).To(Equal(expected.Processes.Source), desc)
		Expect(actual.Processes.Dest).To(Equal(expected.Processes.Dest), desc)
	}

	if expected.DNS == nil {
		Expect(actual.DNS).To(BeNil())
	} else {
		Expect(actual.DNS.GraphLatencyStats).To(Equal(expected.DNS.GraphLatencyStats), desc)
		Expect(actual.DNS.ResponseCodes).To(Equal(expected.DNS.ResponseCodes), desc)
	}

	// Catch all - compare full struct
	Expect(actual).To(Equal(expected))
}

var _ = Describe("Graph API tests", func() {
	It("handles GraphEdge.IncludeStats", func() {
		edge := GraphEdge{}

		// Have 6 sets of stats, each is a cycle of the set of stats defined above. After including everything the
		// stats in each of the 6 positions should be equal.
		edge.IncludeStats([]GraphStats{
			firstStats,
			secondL3Stats,
			secondL7Stats,
			secondProcessStats,
			secondDNSStats,
			thirdStats,
		})
		edge.IncludeStats([]GraphStats{
			secondL3Stats,
			secondL7Stats,
			secondProcessStats,
			secondDNSStats,
			thirdStats,
			firstStats,
		})
		edge.IncludeStats([]GraphStats{
			secondL7Stats,
			secondProcessStats,
			secondDNSStats,
			thirdStats,
			firstStats,
			secondL3Stats,
		})
		edge.IncludeStats([]GraphStats{
			secondProcessStats,
			secondDNSStats,
			thirdStats,
			firstStats,
			secondL3Stats,
			secondL7Stats,
		})
		edge.IncludeStats([]GraphStats{
			secondDNSStats,
			thirdStats,
			firstStats,
			secondL3Stats,
			secondL7Stats,
			secondProcessStats,
		})

		// We have a checkpoint for the first and second set of stats.
		Expect(edge.Stats).To(HaveLen(6))
		expectStats(edge.Stats[0], firstSecondCombinedStats, "First and second combined stats")

		edge.IncludeStats([]GraphStats{
			thirdStats,
			firstStats,
			secondL3Stats,
			secondL7Stats,
			secondProcessStats,
			secondDNSStats,
		})
		edge.IncludeStats(nil)

		// All of the stats should be the same (in each time position)
		Expect(edge.Stats).To(HaveLen(6))
		for i, stats := range edge.Stats {
			expectStats(stats, firstSecondThirdCombinedStats, fmt.Sprintf("All stats, index %d", i))
		}

		By("checking the edge marshals correctly into json (reduce the time buckets to one bucket)")
		edge.Stats = edge.Stats[:1]
		js, err := json.Marshal(edge)
		Expect(err).NotTo(HaveOccurred())
		Expect(js).To(MatchJSON(`{
        "id": {
          "source_node_id": "",
          "dest_node_id": ""
        },
        "stats": [
          {
            "l3": {
              "allowed": {
                "packet_in": 314,
                "packet_out": 319,
                "bytes_in": 334,
                "bytes_out": 342
              },
              "denied_at_source": {
                "packet_in": 668,
                "packet_out": 684,
                "bytes_in": 690,
                "bytes_out": 700
              },
              "denied_at_dest": {
                "packet_in": 386,
                "packet_out": 396,
                "bytes_in": 408,
                "bytes_out": 414
              },
              "connections": {
                "total_per_sample_interval": 1153,
                "started": 1171,
                "completed": 1183
              },
              "tcp": {
                "sum_total_retransmissions": 790,
                "sum_lost_packets": 804,
                "sum_unrecovered_to": 816,
                "min_send_congestion_window": 61,
                "min_mss": 67,
                "max_smooth_rtt": 773,
                "max_min_rtt": 787,
                "mean_send_congestion_window": 617.5,
                "mean_smooth_rtt": 627.5,
                "mean_min_mss": 630.5,
                "mean_mss": 640,
                "count": 4
              }
            },
            "l7": {
              "no_response": {
                "bytes_in": 962,
                "bytes_out": 966,
                "mean_duration": 665.5,
                "min_duration": 150,
                "max_duration": 856,
                "count": 4
              },
              "response_code_1xx": {
                "bytes_in": 570,
                "bytes_out": 576,
                "mean_duration": 361,
                "min_duration": 113,
                "max_duration": 499,
                "count": 3
              },
              "response_code_2xx": {
                "bytes_in": 964,
                "bytes_out": 968,
                "mean_duration": 666.5,
                "min_duration": 151,
                "max_duration": 857,
                "count": 4
              },
              "response_code_3xx": {
                "bytes_in": 676,
                "bytes_out": 694,
                "mean_duration": 408.3333333333333,
                "min_duration": 181,
                "max_duration": 547,
                "count": 3
              },
              "response_code_4xx": {
                "bytes_in": 1060,
                "bytes_out": 1076,
                "mean_duration": 713.5,
                "min_duration": 223,
                "max_duration": 887,
                "count": 4
              },
              "response_code_5xx": {
                "bytes_in": 796,
                "bytes_out": 808,
                "mean_duration": 461,
                "min_duration": 251,
                "max_duration": 587,
                "count": 3
              }
            },
            "dns": {
              "mean_request_latency": 208.53846153846155,
              "max_request_latency": 293,
              "min_request_latency": 5,
              "latency_count": 13,
              "response_codes": [
                {
                  "code": "NOERROR",
                  "count": 6,
                  "mean_request_latency": 10,
                  "max_request_latency": 14,
                  "min_request_latency": 5,
                  "latency_count": 4
                },
                {
                  "code": "NXDOMAIN",
                  "count": 11,
                  "mean_request_latency": 246,
                  "max_request_latency": 293,
                  "min_request_latency": 18,
                  "latency_count": 11
                }
              ]
            },
            "processes": {
              "source": [
                {
                  "name": "source1",
                  "source": "",
                  "destination": "",
                  "min_num_names_per_flow": 269,
                  "max_num_names_per_flow": 601,
                  "min_num_ids_per_flow": 277,
                  "max_num_ids_per_flow": 613
                },
                {
                  "name": "source2",
                  "source": "",
                  "destination": "",
                  "min_num_names_per_flow": 617,
                  "max_num_names_per_flow": 619,
                  "min_num_ids_per_flow": 631,
                  "max_num_ids_per_flow": 641
                }
              ],
              "dest": [
                {
                  "name": "dest1",
                  "source": "",
                  "destination": "",
                  "min_num_names_per_flow": 283,
                  "max_num_names_per_flow": 919,
                  "min_num_ids_per_flow": 307,
                  "max_num_ids_per_flow": 937
                },
                {
                  "name": "dest2",
                  "source": "",
                  "destination": "",
                  "min_num_names_per_flow": 941,
                  "max_num_names_per_flow": 947,
                  "min_num_ids_per_flow": 953,
                  "max_num_ids_per_flow": 967
                }
              ]
            }
          }
        ],
        "selectors": {}
      }`))
	})

	It("handles GraphEdge.String", func() {
		edge := GraphEdge{ID: GraphEdgeID{SourceNodeID: "a", DestNodeID: "b"}}
		Expect(edge.String()).To(Equal("Edge(a -> b)"))
	})

	It("handles GraphNode.IncludeStatsWithin", func() {
		node := GraphNode{}

		// Have 6 sets of stats, each is a cycle of the set of stats defined above. After including everything the
		// stats in each of the 6 positions should be equal.
		node.IncludeStatsWithin([]GraphStats{
			firstStats,
			secondL3Stats,
			secondL7Stats,
			secondProcessStats,
			secondDNSStats,
			thirdStats,
		})
		node.IncludeStatsWithin([]GraphStats{
			secondL3Stats,
			secondL7Stats,
			secondProcessStats,
			secondDNSStats,
			thirdStats,
			firstStats,
		})
		node.IncludeStatsWithin([]GraphStats{
			secondL7Stats,
			secondProcessStats,
			secondDNSStats,
			thirdStats,
			firstStats,
			secondL3Stats,
		})
		node.IncludeStatsWithin([]GraphStats{
			secondProcessStats,
			secondDNSStats,
			thirdStats,
			firstStats,
			secondL3Stats,
			secondL7Stats,
		})
		node.IncludeStatsWithin([]GraphStats{
			secondDNSStats,
			thirdStats,
			firstStats,
			secondL3Stats,
			secondL7Stats,
			secondProcessStats,
		})

		// We have a checkpoint for the first and second set of stats.
		Expect(node.StatsWithin).To(HaveLen(6))
		expectStats(node.StatsWithin[0], firstSecondCombinedStats, "First and second combined stats")

		node.IncludeStatsWithin([]GraphStats{
			thirdStats,
			firstStats,
			secondL3Stats,
			secondL7Stats,
			secondProcessStats,
			secondDNSStats,
		})
		node.IncludeStatsWithin(nil)

		// All of the stats should be the same (in each time position)
		Expect(node.StatsWithin).To(HaveLen(6))
		for i, stats := range node.StatsWithin {
			expectStats(stats, firstSecondThirdCombinedStats, fmt.Sprintf("All stats, index %d", i))
		}
	})

	It("handles GraphNode.ServicePorts", func() {
		node := GraphNode{
			ID:   "a",
			Type: GraphNodeTypeHost,
		}
		node.IncludeServicePort(ServicePort{NamespacedName: NamespacedName{
			Namespace: "b",
			Name:      "c",
		}})
		node.IncludeServicePort(ServicePort{NamespacedName: NamespacedName{
			Namespace: "a",
			Name:      "b",
		}})
		node.IncludeServicePort(ServicePort{NamespacedName: NamespacedName{
			Namespace: "a",
			Name:      "b",
		}})
		node.IncludeServicePort(ServicePort{NamespacedName: NamespacedName{
			Namespace: "a",
			Name:      "c",
		}})

		js, err := json.Marshal(node)
		Expect(err).NotTo(HaveOccurred())
		Expect(js).To(MatchJSON(`{
			"id": "a",
			"type": "host",
			"selectors": {},
			"service_ports": [{"namespace":"a", "name":"b"}, {"namespace":"a", "name":"c"}, {"namespace":"b", "name":"c"}]
		}`))
	})

	It("handles GraphNode.String", func() {
		node := GraphNode{
			ID:         "rep/a/b",
			Expandable: true,
		}
		Expect(node.String()).To(Equal("Node(rep/a/b; expandable=true)"))

		node = GraphNode{
			ID:       "wep/a/c/b",
			ParentID: "rep/a/b",
		}
		Expect(node.String()).To(Equal("Node(wep/a/c/b; parent=rep/a/b; expandable=false)"))
	})

	It("handles GraphNode.IncludeAggregatedProtoPorts", func() {
		node := GraphNode{
			ID:   "a",
			Type: GraphNodeTypeHost,
		}

		By("including a nil proto ports")
		node.IncludeAggregatedProtoPorts(nil)

		By("including a set of tcp proto ports")
		node.IncludeAggregatedProtoPorts(&AggregatedProtoPorts{
			ProtoPorts: []AggregatedPorts{{
				Protocol: "tcp",
				PortRanges: []PortRange{{
					MinPort: 1, MaxPort: 20,
				}, {
					MinPort: 30, MaxPort: 39,
				}},
				NumOtherPorts: 0,
			}},
			NumOtherProtocols: 0,
		})

		By("including a nil proto ports")
		node.IncludeAggregatedProtoPorts(nil)

		By("checking the single set of tcp values is as configured")
		Expect(node.AggregatedProtoPorts).To(Equal(&AggregatedProtoPorts{
			ProtoPorts: []AggregatedPorts{{
				Protocol: "tcp",
				PortRanges: []PortRange{{
					MinPort: 1, MaxPort: 20,
				}, {
					MinPort: 30, MaxPort: 39,
				}},
				NumOtherPorts: 0,
			}},
			NumOtherProtocols: 0,
		}))

		By("including another tcp set with one of the ranges overlapping, and another separate range")
		node.IncludeAggregatedProtoPorts(&AggregatedProtoPorts{
			ProtoPorts: []AggregatedPorts{{
				Protocol: "tcp",
				PortRanges: []PortRange{{
					MinPort: 16, MaxPort: 25,
				}, {
					MinPort: 50, MaxPort: 59,
				}},
				NumOtherPorts: 1000,
			}},
			NumOtherProtocols: 1,
		})

		By("checking the ranges are ordered, complete and non-overlapping and other ports has been adjusted")
		Expect(node.AggregatedProtoPorts).To(Equal(&AggregatedProtoPorts{
			ProtoPorts: []AggregatedPorts{{
				Protocol: "tcp",
				PortRanges: []PortRange{{
					MinPort: 1, MaxPort: 25,
				}, {
					MinPort: 30, MaxPort: 39,
				}, {
					MinPort: 50, MaxPort: 59,
				}},
				NumOtherPorts: 1000 - 25,
			}},
			NumOtherProtocols: 1,
		}))

		By("including two other protocols")
		node.IncludeAggregatedProtoPorts(&AggregatedProtoPorts{
			ProtoPorts: []AggregatedPorts{{
				Protocol: "sctp",
				PortRanges: []PortRange{{
					MinPort: 16, MaxPort: 25,
				}},
				NumOtherPorts: 900,
			}, {
				Protocol: "udp",
				PortRanges: []PortRange{{
					MinPort: 1, MaxPort: 65535,
				}},
				NumOtherPorts: 0,
			}},
			NumOtherProtocols: 2,
		})

		By("checking the protocols and ranges are correct and the number of other protocols is adjusted")
		Expect(node.AggregatedProtoPorts).To(Equal(&AggregatedProtoPorts{
			ProtoPorts: []AggregatedPorts{{
				Protocol: "sctp",
				PortRanges: []PortRange{{
					MinPort: 16, MaxPort: 25,
				}},
				NumOtherPorts: 900,
			}, {
				Protocol: "tcp",
				PortRanges: []PortRange{{
					MinPort: 1, MaxPort: 25,
				}, {
					MinPort: 30, MaxPort: 39,
				}, {
					MinPort: 50, MaxPort: 59,
				}},
				NumOtherPorts: 1000 - 25,
			}, {
				Protocol: "udp",
				PortRanges: []PortRange{{
					MinPort: 1, MaxPort: 65535,
				}},
				NumOtherPorts: 0,
			}},
			NumOtherProtocols: 1,
		}))

		By("checking the node marshals correctly into json")
		js, err := json.Marshal(node)
		Expect(err).NotTo(HaveOccurred())
		Expect(js).To(MatchJSON(`{
			"id": "a",
			"type": "host",
			"selectors": {},
			"aggregated_proto_ports": {
				"num_other_protocols": 1,
				"proto_ports": [{
					"protocol": "sctp",
					"port_ranges": [{
						"min_port": 16,
						"max_port": 25
					}],
					"num_other_ports": 900
				}, {
					"protocol": "tcp",
					"port_ranges": [{
						"min_port": 1,
						"max_port": 25
					}, {
						"min_port": 30,
						"max_port": 39
					}, {
						"min_port": 50,
						"max_port": 59
					}],
					"num_other_ports": 975
				}, {
					"protocol": "udp",
					"port_ranges": [{
						"min_port": 1,
						"max_port": 65535
					}]
				}]
			}
		}`))
	})

	It("Can parse named selector", func() {
		By("Parsing a valid set of named selectors")
		var ns []NamedSelector
		err := json.Unmarshal([]byte(`[{
			"name": "name",
			"selector": "x == 'a'"
		}, {
			"name": "name2",
			"selector": "has(y)"
		}]`), &ns)

		Expect(err).NotTo(HaveOccurred())
		Expect(ns).To(HaveLen(2))
		Expect(ns[0].Name).To(Equal("name"))
		Expect(ns[0].Selector).NotTo(BeNil())
		Expect(ns[1].Name).To(Equal("name2"))
		Expect(ns[1].Selector).NotTo(BeNil())

		By("Parsing an invalid set of named selectors")
		// missing quotes around the "a"
		err = json.Unmarshal([]byte(`[{
			"name": "name",
			"selector": "x == a"
		}, {
			"name": "name2",
			"selector": "has(y)"
		}`), &ns)
		Expect(err).To(HaveOccurred())
	})

	It("Can parse the time range field", func() {
		By("Parsing now-X format")
		var tr lmav1.TimeRange
		err := json.Unmarshal([]byte(`{
				"from": "now-1h",
				"to": "now-30m"
			}`), &tr)
		Expect(err).NotTo(HaveOccurred())
		Expect(tr.To.Sub(tr.From)).To(Equal(30 * time.Minute))

		By("Parsing RFC3339 format")
		err = json.Unmarshal([]byte(`{
				"from": "`+tr.From.Format(time.RFC3339)+`",
				"to": "`+tr.To.Format(time.RFC3339)+`"
			}`), &tr)
		Expect(err).NotTo(HaveOccurred())
		Expect(tr.To.Sub(tr.From)).To(Equal(30 * time.Minute))

		By("Parsing incorrect now format")
		err = json.Unmarshal([]byte(`{
				"from": "now-2X",
				"to": "now-X"
			}`), &tr)
		Expect(err).To(HaveOccurred())

		By("Parsing inverted from and to")
		err = json.Unmarshal([]byte(`{
				"from": "now-1h",
				"to": "now-2h"
			}`), &tr)
		Expect(err).To(HaveOccurred())
	})
})
