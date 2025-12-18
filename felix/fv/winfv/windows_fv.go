// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package winfv

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tigera/windows-networking/pkg/testutils"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/fv/flowlogs"
)

type CalicoBackEnd string

const (
	CalicoBackendBGP   CalicoBackEnd = "bgp"
	CalicoBackendVXLAN CalicoBackEnd = "vxlan"
)

type WinFV struct {
	rootDir    string
	flowLogDir string
	configFile string

	dnsCacheFile string

	// The original content of config.ps1.
	originalConfig string

	backend CalicoBackEnd
}

func NewWinFV(rootDir, flowLogDir, dnsCacheFile string) (*WinFV, error) {
	var b []byte
	configFile := filepath.Join(rootDir, "config.ps1")

	if IsRunningHPC() {
		log.Infof("Skip reading config file, running on HPC...")
	} else {
		var err error
		b, err = os.ReadFile(configFile) // just pass the file name
		if err != nil {
			return nil, err
		}
	}

	var backend CalicoBackEnd
	networkType, _ := testutils.Powershell(`Get-HnsNetwork | Where name -EQ Calico | Select Type`)
	log.Infof("Windows network type %s", networkType)
	if strings.Contains(strings.ToLower(networkType), "l2bridge") {
		backend = CalicoBackendBGP
	} else if strings.Contains(strings.ToLower(networkType), "overlay") {
		backend = CalicoBackendVXLAN
	} else {
		return nil, fmt.Errorf("wrong Windows network type")
	}

	return &WinFV{
		rootDir:        rootDir,
		flowLogDir:     flowLogDir,
		dnsCacheFile:   dnsCacheFile,
		configFile:     configFile,
		originalConfig: string(b),
		backend:        backend,
	}, nil
}

func (f *WinFV) GetBackendType() CalicoBackEnd {
	return f.backend
}

func (f *WinFV) Restart() {
	if IsRunningHPC() {
		log.Infof("Skip restarting Felix, running on HPC...")
		return
	}
	log.Infof("Restarting Felix...")
	testutils.Powershell(filepath.Join(f.rootDir, "restart-felix.ps1"))
	log.Infof("Felix Restarted.")
}

func (f *WinFV) RestartFelix() {
	if IsRunningHPC() {
		log.Infof("Skip restarting Felix, running on HPC...")
		return
	}
	log.Infof("Restarting Felix...")
	testutils.Powershell(filepath.Join(f.rootDir, "restart-felix.ps1"))
	log.Infof("Felix Restarted.")
}

func (f *WinFV) RestoreConfig() error {
	if IsRunningHPC() {
		log.Infof("Skip writing config file, running on HPC...")
		return nil
	}
	err := os.WriteFile(f.configFile, []byte(f.originalConfig), 0644)
	if err != nil {
		return err
	}
	return nil
}

// Add config items to config.ps1.
func (f *WinFV) AddConfigItems(configs map[string]interface{}) error {
	if IsRunningHPC() {
		log.Infof("Skip writing config file, running on HPC...")
		return nil
	}
	var entry, items string

	items = f.originalConfig
	// Convert config map to string
	for name, value := range configs {
		switch c := value.(type) {
		case int:
			entry = fmt.Sprintf("$env:FELIX_%s = %d", name, c)
		case string:
			entry = fmt.Sprintf("$env:FELIX_%s = %q", name, c)
		default:
			return fmt.Errorf("wrong config value type")
		}

		items = fmt.Sprintf("%s\n%s\n", items, entry)
	}

	err := os.WriteFile(f.configFile, []byte(items), 0644)
	if err != nil {
		return err
	}
	return nil
}

func (f *WinFV) FlowLogs() ([]flowlog.FlowLog, error) {
	return flowlogs.ReadFlowLogsFile(f.flowLogDir)
}

type JsonMappingV1 struct {
	LHS    string
	RHS    string
	Expiry string
	Type   string
}

func (f *WinFV) ReadDnsCacheFile() ([]JsonMappingV1, error) {
	result := []JsonMappingV1{}

	log.WithField("file", f.dnsCacheFile).Info("Reading DNS Cache from file")
	logFile, err := os.Open(f.dnsCacheFile)
	if err != nil {
		return result, err
	}
	defer logFile.Close()

	s := bufio.NewScanner(logFile)
	for s.Scan() {
		var m JsonMappingV1

		// filter out anything other than a valid entry
		if !strings.Contains(s.Text(), "LHS") {
			continue
		}
		err = json.Unmarshal(s.Bytes(), &m)
		if err != nil {
			all, _ := os.ReadFile(f.dnsCacheFile)
			return result, fmt.Errorf("error unmarshaling dns log: %v\nLog:\n%s\nFile:\n%s", err, string(s.Bytes()), string(all))
		}
		result = append(result, m)
	}
	return result, nil
}

// HPC env variable is set by the Windows FV tests (run-fv-full.ps1) runner during infra set up
func IsRunningHPC() bool {
	return os.Getenv("HPC") == "true"
}
