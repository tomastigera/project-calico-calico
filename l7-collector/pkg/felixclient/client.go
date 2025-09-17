// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package felixclient

import (
	"context"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/l7-collector/pkg/api"
)

const (
	ProtocolTCP string = "tcp"
)

type FelixClient interface {
	SendStats(context.Context, api.EnvoyCollector)
	SendData(context.Context, proto.PolicySyncClient, api.EnvoyInfo) error
}

// felixClient provides the means to send data to Felix
type felixClient struct {
	target   string
	dialOpts []grpc.DialOption
}

func init() {
	resolver.SetDefaultScheme("passthrough")
}

func NewFelixClient(target string, opts []grpc.DialOption) FelixClient {
	return &felixClient{
		target:   target,
		dialOpts: opts,
	}
}

// SendStats listens for data from the collector and sends it.
func (fc *felixClient) SendStats(ctx context.Context, collector api.EnvoyCollector) {
	log.Info("Starting sending L7 Stats to Policy Sync server")
	conn, err := grpc.NewClient(fc.target, fc.dialOpts...)
	if err != nil {
		log.Warnf("fail to dial Policy Sync server: %v", err)
		return
	}
	log.Info("Successfully connected to Policy Sync server")
	defer conn.Close()
	client := proto.NewPolicySyncClient(conn)

	for {
		select {
		case data := <-collector.Report():
			if err := fc.SendData(ctx, client, data); err != nil {
				// Error reporting stats, exit now to start reconnection processing.
				log.WithError(err).Warning("Error reporting L7 stats")
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// SendData takes EnvoyLog data and sends the it with the
// protobuf client.
func (fc *felixClient) SendData(ctx context.Context, client proto.PolicySyncClient, logData api.EnvoyInfo) error {
	// Batch the data by 5 tuple
	data := fc.batchAndConvertEnvoyLogs(logData)

	// Send the batched data
	for _, d := range data {
		log.Debugf("Sending L7 Stats: %s", d)
		if r, err := client.Report(ctx, d); err != nil {
			// Error sending stats, must be a connection issue, so exit now to force a reconnect.
			return err
		} else if !r.Successful {
			// If the remote end indicates unsuccessful then the remote end is likely transitioning from having
			// stats enabled to having stats disabled. This should be transient, so log a warning, but otherwise
			// treat as a successful report.
			log.Warning("Remote end indicates L7 stats not processed successfully")
			return nil
		}
	}
	log.Info("Sent L7 stats to Policy Sync server")
	return nil
}

func (fc *felixClient) batchAndConvertEnvoyLogs(info api.EnvoyInfo) map[api.TupleKey]*proto.DataplaneStats {
	data := make(map[api.TupleKey]*proto.DataplaneStats)
	for _, l := range info.Logs {
		// Convert the EnvoyLog to DataplaneStats
		d := fc.dataplaneStatsFromL7Log(l)

		// Join the HttpData fields by 5 tuple
		tupleKey := api.TupleKeyFromEnvoyLog(l)
		if existing, ok := data[tupleKey]; ok {
			// Add the HttpData to the existing log
			existing.HttpData = append(existing.HttpData, d.HttpData...)
		} else {
			data[tupleKey] = d
		}

		// Add the count statistics
		httpStat := &proto.Statistic{
			Direction:  proto.Statistic_IN,
			Relativity: proto.Statistic_DELTA,
			Kind:       proto.Statistic_HTTP_DATA,
			Action:     proto.Action_ALLOWED,
			Value:      int64(info.Connections[tupleKey]),
		}
		d.Stats = append(d.Stats, httpStat)
	}

	// Create connection logs for connections which do not
	// include requests we have recorded.
	for key, count := range info.Connections {
		if _, ok := data[key]; !ok {
			l := api.EnvoyLogFromTupleKey(key)
			d := fc.dataplaneStatsFromL7Log(l)
			// Add the count statistics
			httpStat := &proto.Statistic{
				Direction:  proto.Statistic_IN,
				Relativity: proto.Statistic_DELTA,
				Kind:       proto.Statistic_HTTP_DATA,
				Action:     proto.Action_ALLOWED,
				Value:      int64(count),
			}
			d.Stats = append(d.Stats, httpStat)
			data[key] = d
		}
	}

	return data
}

func (fc *felixClient) dataplaneStatsFromL7Log(logData api.EnvoyLog) *proto.DataplaneStats {
	// policy syn server is already configured to consume DataplaneStats object
	// so we use the same object with envoy l7 data

	// Unless the protocol is specified, the protocol will be TCP
	if logData.Protocol == "" || logData.Protocol == "-" {
		logData.Protocol = ProtocolTCP
	}

	d := &proto.DataplaneStats{
		SrcIp:   logData.SrcIp,
		DstIp:   logData.DstIp,
		SrcPort: logData.SrcPort,
		DstPort: logData.DstPort,
		Protocol: &proto.Protocol{
			NumberOrName: &proto.Protocol_Name{
				Name: logData.Protocol,
			},
		},
	}

	d.HttpData = []*proto.HTTPData{
		{
			Duration:      logData.Duration,
			ResponseCode:  logData.ResponseCode,
			RouteName:     logData.RouteName,
			BytesSent:     logData.BytesSent,
			BytesReceived: logData.BytesReceived,
			UserAgent:     logData.UserAgent,
			RequestPath:   logData.RequestPath,
			RequestMethod: logData.RequestMethod,
			Count:         logData.Count,
			Domain:        logData.Domain,
			DurationMax:   logData.DurationMax,
			Type:          logData.Type,
			Latency:       logData.Latency,
		},
	}

	return d
}
