// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nxadm/tail"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/ingress-collector/pkg/config"
)

const INGRESSLOGJSONPREFIX = "tigera_secure_ee_ingress:"

type nginxCollector struct {
	collectedLogs    chan IngressInfo
	config           *config.Config
	batch            *BatchIngressLog
	seen             map[string]struct{}
	connectionCounts map[TupleKey]int
}

func NewNginxCollector(cfg *config.Config) IngressCollector {
	return &nginxCollector{
		collectedLogs:    make(chan IngressInfo),
		config:           cfg,
		batch:            NewBatchIngressLog(cfg.IngressRequestsPerInterval),
		connectionCounts: make(map[TupleKey]int),
		seen:             make(map[string]struct{}),
	}
}

func stop(t *tail.Tail) {
	err := t.Stop()
	if err != nil {
		return
	}
}

func (nc *nginxCollector) ReadLogs(ctx context.Context) {
	// Tail the file
	// Currently this reads from the end of the tail file to prevent
	// rereading the file.
	t, err := tail.TailFile(nc.config.IngressLogPath, tail.Config{
		Follow: true,
		ReOpen: true,
		Location: &tail.SeekInfo{
			Whence: nc.config.TailWhence,
		},
	})
	defer stop(t)
	if err != nil {
		// TODO: Figure out proper error handling
		log.Warnf("Failed to tail ingress logs: %v", err)
		return
	}
	defer log.Infof("Tail stopped with error: %v", t.Err())

	// Set up the ticker for reading the log files
	ticker := time.NewTicker(time.Duration(nc.config.IngressLogIntervalSecs) * time.Second)
	defer ticker.Stop()

	// Read logs from the file, add them to the batch, and periodically send the batch.
	for {
		// Periodically send the batched logs to the collection channel.
		// Having the ticker channel in its own select clause forces
		// the ticker case to get precedence over reading lines.
		select {
		case <-ticker.C:
			nc.ingestLogs()
			continue
		default:
			// Leave an empty default case so select statement will not block and wait.
		}
		// Read logs from the file and add them to the batch
		select {
		case <-ticker.C:
			nc.ingestLogs()
			continue
		case line := <-t.Lines:
			// Only inspect the tigera_secure_ee_ingress section of the logs
			ingressLog, err := nc.ParseRawLogs(line.Text)
			if err != nil {
				// Log line does not have properly formatted ingress info
				// Log error as a trace log, as the output might be too noisy.
				log.WithError(err).Trace("failed to parse line: ")
				continue
			}

			// Unless the protocol is specified, the protocol will be
			// TCP since the feature requires the user of HTTP headers
			// in order to function properly.
			if ingressLog.Protocol == "" {
				ingressLog.Protocol = "tcp"
			}

			// Add this ingress log to the batch
			nc.batch.Insert(ingressLog)

			// Count the unique IPs per connection
			logKey := IngressLogKey(ingressLog)
			if _, exists := nc.seen[logKey]; !exists {
				tupleKey := TupleKeyFromIngressLog(ingressLog)
				nc.connectionCounts[tupleKey] = nc.connectionCounts[tupleKey] + 1
				nc.seen[logKey] = struct{}{}
			}
		case <-ctx.Done():
			log.Info("Collector shut down")
			return
		}
	}
}

func (nc *nginxCollector) ingestLogs() {
	intervalBatch := nc.batch
	intervalCounts := nc.connectionCounts
	nc.batch = NewBatchIngressLog(nc.config.IngressRequestsPerInterval)
	nc.connectionCounts = make(map[TupleKey]int)
	nc.seen = make(map[string]struct{})

	// Send a batch if there is data.
	logs := intervalBatch.Logs()
	if len(logs) != 0 {
		nc.collectedLogs <- IngressInfo{Logs: logs, Connections: intervalCounts}
	}
}

func (nc *nginxCollector) Report() <-chan IngressInfo {
	return nc.collectedLogs
}

// ParseRawLogs takes a log in the format:
// <info> tigera_secure_ee_ingress: { <ingress info> } <more info>
// and returns an IngressLog with the relevant information.
func (nc *nginxCollector) ParseRawLogs(text string) (IngressLog, error) {
	keyIndex := strings.Index(text, INGRESSLOGJSONPREFIX+" ")
	if keyIndex == -1 {
		return IngressLog{}, fmt.Errorf("log information not found in this log line. The line is without the prefix: \"%s \"", INGRESSLOGJSONPREFIX)
	}

	numOpen := 0
	endIndex := 0
	for i := keyIndex; i < len(text); i++ {
		if text[i] == "{"[0] {
			numOpen++
		}

		if text[i] == "}"[0] {
			if numOpen == 1 {
				endIndex = i
				break
			}
			numOpen--
		}
	}

	// If the log is malformed (i.e. no closing "}") return
	// an empty string.
	var ingressText string
	if endIndex > keyIndex {
		ingressText = strings.Trim(text[keyIndex+len(INGRESSLOGJSONPREFIX):endIndex+1], " ")
	}

	// Skip lines of the log that do not include the logging
	// information we are looking for.
	if ingressText == "" {
		return IngressLog{}, errors.New("log information not properly formatted in this log line")
	}

	// TODO: Add something that will properly quote IPs for the users.
	// Unmarshall the bytes into the IngressLog data
	var ingressLog IngressLog
	err := json.Unmarshal([]byte(ingressText), &ingressLog)
	if err != nil {
		// TODO: Figure out proper error handling
		log.Warnf("Failed to unmarshal ingress logs. Logs may be formatted incorrectly: %v", err)
		return IngressLog{}, err
	}

	return ingressLog, nil
}
