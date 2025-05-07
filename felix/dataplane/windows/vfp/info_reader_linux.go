// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
package vfp

import (
	"time"

	"github.com/projectcalico/calico/felix/calc"
	collector "github.com/projectcalico/calico/felix/collector/types"
)

// InfoReader implements collector.PacketInfoReader and collector.ConntrackInfoReader.
type InfoReader struct{}

func NewInfoReader(lookupsCache *calc.LookupsCache, period time.Duration) *InfoReader {
	return &InfoReader{}
}

func (r *InfoReader) Start() error {
	return nil
}

func (r *InfoReader) Stop() {
}

// PacketInfoChan returns the channel with converted PacketInfo.
func (r *InfoReader) PacketInfoChan() <-chan collector.PacketInfo {
	return nil
}

// ConntrackInfoChan returns the channel with converted ConntrackInfo.
func (r *InfoReader) ConntrackInfoChan() <-chan []collector.ConntrackInfo {
	return nil
}

// Endpoint
func (r *InfoReader) EndpointEventHandler() *InfoReader {
	return r
}

// Cache endpoint updates.
func (r *InfoReader) HandleEndpointsUpdate(ids []string) {
}

// Cache policy updates.
func (r *InfoReader) HandlePolicyUpdate(id string) {
}
