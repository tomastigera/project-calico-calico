// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package v1

import (
	"encoding/json"
	"maps"
	"sort"

	"github.com/projectcalico/calico/ui-apis/pkg/math"
)

// GraphProcesses encapsulates the set of processes associated with a particular node or edge in the graph.
// The processes are split into source (opening connections) and dest (listening for connections).
type GraphProcesses struct {
	Source GraphEndpointProcesses `json:"source,omitempty"`
	Dest   GraphEndpointProcesses `json:"dest,omitempty"`
}

func (p *GraphProcesses) Combine(p2 *GraphProcesses) *GraphProcesses {
	if p == nil {
		return p2
	} else if p2 == nil {
		return p
	}

	return &GraphProcesses{
		Source: p.Source.Combine(p2.Source),
		Dest:   p.Dest.Combine(p2.Dest),
	}
}

// GraphEndpointProcesses stores a map of process info keyed off the process name.
//
// This is actually JSON marshalled as a slice, so the JSON will appear in the format:
// [
//
//	{
//	  "name": "p1",
//	  "min_num_names_per_flow": 1,
//	  "max_num_names_per_flow": 2,
//	  "min_num_ids_per_flow": 10,
//	  "max_num_ids_per_flow": 12
//	}, {
//	  "name": "p2"
//	  ...
//	}
//
// ]
type GraphEndpointProcesses map[string]GraphEndpointProcess

func (p GraphEndpointProcesses) Copy() GraphEndpointProcesses {
	pcopy := make(GraphEndpointProcesses)
	maps.Copy(pcopy, p)
	return pcopy
}

func (p GraphEndpointProcesses) MarshalJSON() ([]byte, error) {
	var names []string
	for name := range p {
		names = append(names, name)
	}
	sort.Strings(names)

	processes := make([]GraphEndpointProcess, len(names))
	for i, name := range names {
		processes[i] = p[name]
	}
	return json.Marshal(processes)
}

func (p *GraphEndpointProcesses) UnmarshalJSON(b []byte) error {
	var proceses []GraphEndpointProcess
	err := json.Unmarshal(b, &proceses)
	if err != nil {
		return err
	}

	*p = make(map[string]GraphEndpointProcess)
	for _, process := range proceses {
		(*p)[process.Name] = process
	}
	return nil
}

// Include combines the two sets of process infos.
func (p GraphEndpointProcesses) Combine(p2 GraphEndpointProcesses) GraphEndpointProcesses {
	if len(p) == 0 {
		return p2
	} else if len(p2) == 0 {
		return p
	}

	// Take a copy of p.
	p = p.Copy()

	for k, gp := range p2 {
		existing, ok := p[k]
		if !ok {
			p[k] = gp
			continue
		}
		p[k] = GraphEndpointProcess{
			Name:               gp.Name,
			Source:             gp.Source,
			Destination:        gp.Destination,
			MinNumNamesPerFlow: math.MinIntGtZero(existing.MinNumNamesPerFlow, gp.MinNumNamesPerFlow),
			MaxNumNamesPerFlow: math.MaxIntGtZero(existing.MaxNumNamesPerFlow, gp.MaxNumNamesPerFlow),
			MinNumIDsPerFlow:   math.MinIntGtZero(existing.MinNumIDsPerFlow, gp.MinNumIDsPerFlow),
			MaxNumIDsPerFlow:   math.MaxIntGtZero(existing.MaxNumIDsPerFlow, gp.MaxNumIDsPerFlow),
		}
	}

	return p
}

// GraphEndpointProcess contains useful details recorded about a process.
// Provided there is one pod per host, the number of processes (names and IDs) per flow is the same as the number of
// processes per pod - which for most pods should be fixed.  Large variations could be normal if, for example, the
// pod internally runs short-lived processes - but for most cases large variations could indicate a cyclically
// restarting pod (error) or additional commands being run from within a compromised pod.
type GraphEndpointProcess struct {
	// The process name. If aggregated it will be set to "*"
	Name string `json:"name"`

	// The aggregated source name
	Source string `json:"source"`

	// The aggregated destination name
	Destination string `json:"destination"`

	// The minimum number of process names per flow.
	MinNumNamesPerFlow int `json:"min_num_names_per_flow"`

	// The max number of process names per flow.
	MaxNumNamesPerFlow int `json:"max_num_names_per_flow"`

	// The minimum number of process IDs per flow.
	MinNumIDsPerFlow int `json:"min_num_ids_per_flow"`

	// The max number of process IDs per flow.
	MaxNumIDsPerFlow int `json:"max_num_ids_per_flow"`
}
