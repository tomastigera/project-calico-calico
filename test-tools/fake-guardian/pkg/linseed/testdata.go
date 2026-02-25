package linseed

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	linseedv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

var (
	//go:embed testdata/exampleFlows.ndjson
	exampleFlowLogData []byte
)

type DataGenerator struct {
	exampleFlows []linseedv1.FlowLog
}

func NewDataGenerator() (*DataGenerator, error) {
	flows, err := loadExampleFlows(exampleFlowLogData)
	if err != nil {
		return nil, fmt.Errorf("failed to load example flows: %w", err)
	}

	return &DataGenerator{
		exampleFlows: flows,
	}, nil
}

func (g *DataGenerator) GenerateFlows(total int) []linseedv1.FlowLog {
	flows := make([]linseedv1.FlowLog, 0, total)

	examples := g.exampleFlows

	for range total {
		flow := examples[rand.Intn(len(examples))]
		flow.EndTime = time.Now().Unix()
		flow.StartTime = flow.EndTime - int64(rand.Intn(60))
		flows = append(flows, flow)
	}

	return flows
}

func loadExampleFlows(data []byte) ([]linseedv1.FlowLog, error) {
	var flows = make([]linseedv1.FlowLog, 0, 100)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		var flow linseedv1.FlowLog
		if err := json.Unmarshal(scanner.Bytes(), &flow); err != nil {
			return nil, fmt.Errorf("failed to unmarshal flow log: %w", err)
		}

		flows = append(flows, flow)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read flow logs: %w", err)
	}

	return flows, nil
}
