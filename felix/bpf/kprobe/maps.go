//go:build !windows

// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package kprobe

import (
	"github.com/projectcalico/calico/felix/bpf/maps"
)

const statsKeySize = 44
const statsValueSize = 16
const execPathKeySize = 4
const execPathValueSize = 460

var KpStatsMapParameters = maps.MapParameters{
	Type:       "lru_hash",
	KeySize:    statsKeySize,
	ValueSize:  statsValueSize,
	MaxEntries: 511000,
	Name:       "cali_kpstats",
	Version:    2,
}

var epathMapParameters = maps.MapParameters{
	Type:       "lru_hash",
	KeySize:    execPathKeySize,
	ValueSize:  execPathValueSize,
	MaxEntries: 64000,
	Name:       "cali_epath",
	Version:    2,
}

var execMapParameters = maps.MapParameters{
	Type:       "percpu_array",
	KeySize:    execPathKeySize,
	ValueSize:  execPathValueSize,
	MaxEntries: 1,
	Name:       "cali_exec",
	Version:    2,
}

func MapKpStats() maps.Map {
	return maps.NewPinnedMap(KpStatsMapParameters)
}

func MapEpath() maps.Map {
	return maps.NewPinnedMap(epathMapParameters)
}

func MapExec() maps.Map {
	return maps.NewPinnedMap(execMapParameters)
}
