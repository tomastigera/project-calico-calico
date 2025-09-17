// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package collector

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/l7-collector/pkg/api"
	"github.com/projectcalico/calico/l7-collector/pkg/config"
)

const (
	LogTypeTCP string = "tcp"
	LogTypeTLS string = "tls"
)

func NewEnvoyCollector(cfg *config.Config, ch chan api.EnvoyInfo) api.EnvoyCollector {
	// Currently it will only return a log file collector but
	// this should inspect the config to return other collectors
	// once they need to be implemented.
	return EnvoyCollectorNew(cfg, ch)
}

type BatchEnvoyLog struct {
	logs map[api.EnvoyLogKey]api.EnvoyLog
	size int
	mu   sync.Locker
}

func NewBatchEnvoyLog(size int) *BatchEnvoyLog {
	return &BatchEnvoyLog{
		logs: make(map[api.EnvoyLogKey]api.EnvoyLog),
		size: size,
		mu:   &sync.Mutex{},
	}
}

func (b *BatchEnvoyLog) Insert(entry api.EnvoyLog) {
	b.mu.Lock()
	defer b.mu.Unlock()

	log.Debugf("Inserting log into batch: %v", entry)

	logKey := api.GetEnvoyLogKey(entry)
	// for tcp and tls types we don't get much information so we treat this as a single connection and
	// add the duration, bytes_sent, bytes_received.
	// same goes for cases where http logs comes with same EnvoyLogKey (same l7 fields) for multiple requests
	// this happens even when the batch is full
	if val, ok := b.logs[logKey]; ok {
		// set max duration per request level
		if entry.Duration > val.DurationMax {
			val.DurationMax = entry.Duration
		}

		val.Duration = val.Duration + entry.Duration
		val.Latency = val.Latency + entry.Latency
		val.BytesReceived = val.BytesReceived + entry.BytesReceived
		val.BytesSent = val.BytesSent + entry.BytesSent
		val.Count++
		b.logs[logKey] = val
	} else {
		// add unique logs ony to the batch, if there is space otherwise we drop it
		if !b.full() {
			entry.Count = 1
			entry.DurationMax = entry.Duration
			b.logs[logKey] = entry
		}
	}
}

func (b *BatchEnvoyLog) GetLogs() map[api.EnvoyLogKey]api.EnvoyLog {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.logs
}

func (b *BatchEnvoyLog) full() bool {
	if b.size < 0 {
		return false
	}
	return len(b.logs) == b.size
}
