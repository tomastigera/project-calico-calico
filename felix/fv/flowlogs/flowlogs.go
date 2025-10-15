// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

package flowlogs

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/file"
	"github.com/projectcalico/calico/felix/collector/flowlog"
)

func ReadFlowLogsFile(flowLogDir string) ([]flowlog.FlowLog, error) {
	var flowLogs []flowlog.FlowLog
	log.WithField("dir", flowLogDir).Info("Reading Flow Logs from file")
	filePath := filepath.Join(flowLogDir, file.FlowLogFilename)
	logFile, err := os.Open(filePath)
	if err != nil {
		return flowLogs, err
	}
	defer logFile.Close()

	s := bufio.NewScanner(logFile)
	for s.Scan() {
		var fljo flowlog.JSONOutput
		err = json.Unmarshal(s.Bytes(), &fljo)
		if err != nil {
			all, _ := os.ReadFile(filePath)
			return flowLogs, fmt.Errorf("error unmarshaling flow log: %v\nLog:\n%s\nFile:\n%s", err, string(s.Bytes()), string(all))
		}
		fl, err := fljo.ToFlowLog()
		if err != nil {
			return flowLogs, fmt.Errorf("error converting to flow log: %v\nLog: %s", err, string(s.Bytes()))
		}
		flowLogs = append(flowLogs, fl)
	}
	return flowLogs, nil
}
