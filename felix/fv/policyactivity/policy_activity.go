// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package policyactivity

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/file"
	"github.com/projectcalico/calico/felix/collector/policy"
)

func ReadPolicyActivityLogsFile(logDir string) ([]policy.ActivityLog, error) {
	var logs []policy.ActivityLog
	log.WithField("dir", logDir).Info("Reading Policy Activity Logs from file")
	filePath := filepath.Join(logDir, file.PolicyActivityLogFilename)
	logFile, err := os.Open(filePath)
	if err != nil {
		return logs, err
	}
	defer logFile.Close()

	s := bufio.NewScanner(logFile)
	for s.Scan() {
		var al policy.ActivityLog
		err = json.Unmarshal(s.Bytes(), &al)
		if err != nil {
			all, _ := os.ReadFile(filePath)
			return logs, fmt.Errorf("error unmarshaling policy activity log: %v\nLog:\n%s\nFile:\n%s", err, string(s.Bytes()), string(all))
		}
		logs = append(logs, al)
	}
	if err := s.Err(); err != nil {
		return logs, fmt.Errorf("error reading policy activity log: %w", err)
	}
	return logs, nil
}
