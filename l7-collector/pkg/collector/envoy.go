// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	"github.com/nxadm/tail"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/projectcalico/calico/l7-collector/pkg/config"
)

const (
	DestinationEnvoyReporter    = "destination"
	EnvoyGatewayReporter        = "gateway"
	EnvoyGatewayEdgeReporter    = "gateway-edge"
	EnvoyGatewayProxiedReporter = "gateway-proxied"
)

type connectionCounter struct {
	connectionCounts map[TupleKey]int
	mu               sync.Locker
}

func newConnectionCounter() *connectionCounter {
	return &connectionCounter{
		connectionCounts: make(map[TupleKey]int),
		mu:               &sync.Mutex{},
	}
}

func (instance *connectionCounter) incr(key TupleKey) {
	instance.mu.Lock()
	defer instance.mu.Unlock()
	instance.connectionCounts[key] = instance.connectionCounts[key] + 1
}

func (instance *connectionCounter) val() map[TupleKey]int {
	instance.mu.Lock()
	defer instance.mu.Unlock()
	return instance.connectionCounts
}

type envoyCollector struct {
	collectedLogs    chan EnvoyInfo
	config           *config.Config
	batch            *BatchEnvoyLog
	connectionCounts *connectionCounter
}

func EnvoyCollectorNew(cfg *config.Config, ch chan EnvoyInfo) EnvoyCollector {
	return &envoyCollector{
		collectedLogs:    ch,
		config:           cfg,
		batch:            NewBatchEnvoyLog(cfg.EnvoyRequestsPerInterval),
		connectionCounts: newConnectionCounter(),
	}
}

func stop(t *tail.Tail) {
	err := t.Stop()
	if err != nil {
		return
	}
}

func (ec *envoyCollector) ReadLogs(ctx context.Context) {
	// Tail the file
	// Currently this reads from the end of the tail file to prevent
	// rereading the file.

	// wait fo the log file to be created
	for {
		if _, err := os.Stat(ec.config.EnvoyLogPath); !errors.Is(err, os.ErrNotExist) {
			break
		}
	}

	t, err := tail.TailFile(ec.config.EnvoyLogPath, tail.Config{
		Follow: true,
		ReOpen: true,
		Location: &tail.SeekInfo{
			Whence: ec.config.TailWhence,
		},
	})
	defer func() {
		// Call stop from within a defered function so that
		// t can be reassigned if the tail is restarted.
		stop(t)
	}()
	if err != nil {
		// TODO: Figure out proper error handling
		log.Warnf("Failed to tail envoy logs: %v", err)
		return
	}
	defer log.Errorf("Tail stopped with error: %v", t.Err())

	// Open the file for  monitoring it's size
	file, _ := os.Open(ec.config.EnvoyLogPath)
	defer file.Close()

	// Set up the ticker for reading the log files
	ticker := time.NewTicker(time.Duration(ec.config.EnvoyLogIntervalSecs) * time.Second)
	defer ticker.Stop()

	// Read logs from the file, add them to the batch, and periodically send the batch.
	for {
		// Periodically send the batched logs to the collection channel.
		// Having the ticker channel in its own select clause forces
		// the ticker case to get precedence over reading lines.
		select {
		case <-ticker.C:
			ec.ingestLogs()

			// If a maximum tail lag amount is set, check to make sure
			// that the tail is not falling too far behind.
			if ec.config.EnvoyTailMaxLag > 0 {
				// Seek the current progress of the tail
				current, err := t.Tell()
				if err != nil {
					log.Errorf("Error in attempting to monitor tail progress: %s", err)
					continue
				}

				// Seek the location of the end of the file
				end, err := file.Seek(0, 2)
				if err != nil {
					log.Errorf("Error in attempting retrieve end of log file for monitoring tail progress: %s", err)
					continue
				}

				// Restart the tail if we have fallen behind the maximum offset while tailing the logs
				if end-current > int64(ec.config.EnvoyTailMaxLag) {
					log.Warn("Log ingestion has fallen behind creation by 100 MB. Skipping to the most recent logs")
					newTail, err := tail.TailFile(ec.config.EnvoyLogPath, tail.Config{
						Follow: true,
						ReOpen: true,
						Location: &tail.SeekInfo{
							Whence: ec.config.TailWhence,
						},
					})
					if err != nil {
						log.Errorf("Error creating new tail for the envoy logs: %s. Continuing with the behind tail.", err)
						continue
					}
					t = newTail
				}
			}
			continue
		default:
			// Leave an empty default case so select statement will not block and wait.
		}
		// Read logs from the file and add them to the batch
		select {
		case <-ticker.C:
			ec.ingestLogs()
			continue
		case line := <-t.Lines:
			log.Infof("Received line from envoy log: ", line.Text)
			ec.processLine(line)
		case <-ctx.Done():
			log.Info("Collector shut down")
			return
		}
	}
}

func (ec *envoyCollector) processLine(line *tail.Line) {
	envoyLog, err := ec.ParseRawLogs(line.Text)
	if err != nil {
		log.Error("error in parsing raw logs", err)
		// Log line does not have properly formatted envoy info
		// Skip writing a lot to record this error because it is too noisy.
		return
	}
	// Add this log to the batch
	ec.batch.Insert(envoyLog)

	// count connection statistics, this will contain connection counts even when batch is full
	tupleKey := TupleKeyFromEnvoyLog(envoyLog)
	ec.connectionCounts.incr(tupleKey)
}

func (ec *envoyCollector) ingestLogs() {
	intervalBatch := ec.batch.GetLogs()
	intervalCounts := ec.connectionCounts.val()
	ec.batch = NewBatchEnvoyLog(ec.config.EnvoyRequestsPerInterval)
	ec.connectionCounts = newConnectionCounter()

	// Send a batch if there is data.
	if len(intervalBatch) != 0 {
		log.Debugf("Sending batch of logs to the channel: %v, %v", intervalBatch, intervalCounts)
		ec.collectedLogs <- EnvoyInfo{Logs: intervalBatch, Connections: intervalCounts}
	}
}

func (ec *envoyCollector) Report() <-chan EnvoyInfo {
	return ec.collectedLogs
}

// ParseRawLogs takes a log in the format: {} // TODO: add final format of the logs. Recent version can be found in data_test.go in FVs
// and returns an EnvoyLog with the relevant information.
func (ec *envoyCollector) ParseRawLogs(text string) (EnvoyLog, error) {
	log.Debug("parsing raw envoy logs ")

	// Unmarshall the bytes into the EnvoyLog data
	var envoyLog EnvoyLog
	err := json.Unmarshal([]byte(text), &envoyLog)

	if err != nil {
		// TODO: Figure out proper error handling
		log.Warnf("Failed to unmarshal L7 logs. Logs may be formatted incorrectly: %v", err)
		return EnvoyLog{}, err
	}

	// calculate latency
	if ust, err := strconv.Atoi(envoyLog.UpstreamServiceTime); err == nil {
		envoyLog.Latency = envoyLog.Duration - int32(ust)
	}

	return ParseFiveTupleInformation(envoyLog)
}

func ParseFiveTupleInformation(envoyLog EnvoyLog) (EnvoyLog, error) {
	switch envoyLog.Reporter {
	case EnvoyGatewayProxiedReporter:
		firstXFFHost := ""
		xFFHosts := strings.Split(envoyLog.XForwardedFor, ",")
		if len(xFFHosts) > 0 {
			firstXFFHost = strings.TrimSpace(xFFHosts[0])
			if firstXFFHost != "" {
				// For XFF, we need to get the port from downstream_direct_remote_address
				_, sp, err := net.SplitHostPort(envoyLog.DSDirectRemoteAddress)
				if err != nil {
					return EnvoyLog{}, fmt.Errorf("error parsing port from downstream_direct_remote_address: %w", err)
				}
				srcWithPort := net.JoinHostPort(firstXFFHost, sp)
				return parseFiveTupleInformationFromFields(envoyLog, envoyLog.UpstreamHost, srcWithPort)
			}
		}
		fallthrough // if no XFF is present, we fall through to the next case which is the Gateway Edge Reporter
	case EnvoyGatewayReporter, EnvoyGatewayEdgeReporter:
		return parseFiveTupleInformationFromFields(envoyLog, envoyLog.UpstreamHost, envoyLog.DSDirectRemoteAddress)
	case DestinationEnvoyReporter:
		return parseFiveTupleInformationFromFields(envoyLog, envoyLog.DSLocalAddress, envoyLog.DSRemoteAddress)
	default:
		// If the reporter is not "gateway" or "destination", we do not process
		// the log at this time.
		log.Warnf("log of reporter type %v are not processed at this time", envoyLog.Reporter)
		return EnvoyLog{}, fmt.Errorf("log of reporter type %v are not processed at this time", envoyLog.Reporter)
	}
}

func parseFiveTupleInformationFromFields(envoyLog EnvoyLog, dest, src string) (EnvoyLog, error) {
	dh, dp, derr := net.SplitHostPort(dest)
	if derr != nil {
		return EnvoyLog{}, fmt.Errorf("error parsing five tuple from destination information: %w", derr)
	}

	sh, sp, serr := net.SplitHostPort(src)
	if serr != nil {
		return EnvoyLog{}, fmt.Errorf("error parsing five tuple from source information: %w", serr)
	}

	envoyLog.SrcIp = sh
	envoyLog.DstIp = dh
	sport, _ := strconv.Atoi(sp)
	dport, _ := strconv.Atoi(dp)
	envoyLog.SrcPort = int32(sport)
	envoyLog.DstPort = int32(dport)

	return envoyLog, nil
}

func (ec *envoyCollector) Start(ctx context.Context) {
	t := time.NewTicker(time.Second * time.Duration(ec.config.EnvoyLogIntervalSecs))
	defer t.Stop()
	for {
		select {
		case <-t.C:
			ec.ingestLogs()
		case <-ctx.Done():
			return
		}
	}
}

// gRPC functions
func (ec *envoyCollector) ReceiveLogs(logMsg *accesslogv3.HTTPAccessLogEntry) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithField("log", logMsg).Debug("Log received from envoy via gRPC")
	}
	log.WithField("log", logMsg).Info("Log received from envoy via gRPC")
	// Treat values
	timeToLastUpstreamTxByte := logMsg.GetCommonProperties().GetTimeToLastUpstreamTxByte()
	if timeToLastUpstreamTxByte == nil {
		timeToLastUpstreamTxByte = &durationpb.Duration{}
	}
	startTime := logMsg.GetCommonProperties().GetStartTime()
	duration := logMsg.GetCommonProperties().GetTimeToLastDownstreamTxByte()
	if duration == nil {
		duration = durationpb.New(time.Since(startTime.AsTime()))
	}
	responseCode := logMsg.Response.GetResponseCode()
	if responseCode == nil {
		responseCode = wrapperspb.UInt32(504)
	}

	entry := EnvoyLog{
		Reporter:              DestinationEnvoyReporter,
		StartTime:             startTime.String(),
		Duration:              int32(duration.Nanos / 1000000),
		ResponseCode:          int32(responseCode.Value),
		BytesSent:             int32(logMsg.Request.RequestBodyBytes + logMsg.Request.RequestHeadersBytes),
		BytesReceived:         int32(logMsg.Response.ResponseBodyBytes + logMsg.Response.ResponseHeadersBytes),
		UserAgent:             logMsg.Request.RequestHeaders["user-agent"],
		RequestPath:           logMsg.Request.GetPath(),
		RequestMethod:         logMsg.Request.GetRequestMethod().String(),
		RequestId:             logMsg.Request.RequestId,
		Type:                  "http",
		DSRemoteAddress:       logMsg.GetCommonProperties().GetDownstreamRemoteAddress().GetSocketAddress().GetAddress(),
		DSLocalAddress:        logMsg.GetCommonProperties().GetDownstreamLocalAddress().GetSocketAddress().GetAddress(),
		UpstreamHost:          logMsg.GetCommonProperties().GetUpstreamLocalAddress().GetSocketAddress().GetAddress(),
		UpstreamLocalAddress:  logMsg.GetCommonProperties().GetUpstreamLocalAddress().GetSocketAddress().GetAddress(),
		DSDirectRemoteAddress: logMsg.GetCommonProperties().GetDownstreamDirectRemoteAddress().GetSocketAddress().GetAddress(),
		XForwardedFor:         logMsg.Request.RequestHeaders["x-forwarded-for"],
		UpstreamServiceTime:   strconv.Itoa(int(timeToLastUpstreamTxByte.Nanos / 1000000)),
		Protocol:              "tcp", //log.ProtocolVersion.String(),
		SrcIp:                 logMsg.GetCommonProperties().GetDownstreamRemoteAddress().GetSocketAddress().GetAddress(),
		DstIp:                 logMsg.GetCommonProperties().GetDownstreamLocalAddress().GetSocketAddress().GetAddress(),
		SrcPort:               int32(logMsg.GetCommonProperties().GetDownstreamRemoteAddress().GetSocketAddress().GetPortValue()),
		DstPort:               int32(logMsg.GetCommonProperties().GetDownstreamLocalAddress().GetSocketAddress().GetPortValue()),
		Count:                 1,
		DurationMax:           int32(duration.Nanos / 1000000),
		Latency:               int32(duration.Nanos / 1000000),
	}
	ec.batch.Insert(entry)
	key := TupleKeyFromEnvoyLog(entry)
	ec.connectionCounts.incr(key)
}
