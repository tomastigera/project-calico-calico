// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package exec

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

const (
	SnortConfigFileLocation = "/usr/etc/snort/snort.lua"
	SnortRulesDirectory     = "/usr/etc/snort/rules/"
)

type Exec interface {
	Start() error
	Wait() error
	Stop()
}

type Snort func(podName string, iface string, namespace string, dpiName string, alertFileBasePath string, alertFileSize int) (Exec, error)

func NewExec(podName string,
	iface string,
	namespace string,
	dpiName string,
	alertFileBasePath string,
	alertFileSize int,
) (Exec, error) {
	s := &snort{}

	// -c <config path>		: configuration
	// -q					: quiet mode
	// -y					: include year in output
	// -k none				: checksum level
	// -y					: show year in timestamp
	// -i <iface>			: WEP interface
	// -l <path>			: alert output directory
	// --daq afpacket		: packet acquisition module
	// --lua <alert type>	: type/level of alert
	// -R <rules path>		: path to the rules
	logPath := fmt.Sprintf("%s/%s/%s/%s", alertFileBasePath, namespace, dpiName, podName)
	err := os.MkdirAll(logPath, os.ModePerm)
	if err != nil {
		return nil, err
	}

	snortArgs := append([]string{
		"-c", SnortConfigFileLocation,
		"-q",
		"-y",
		"-k", "none",
		"-i", iface,
		"-l", logPath,
		"--daq", "afpacket",
		"--lua", fmt.Sprintf("alert_fast={ file = true, limit = %d }", alertFileSize),
	}, detectRules()...)

	s.cmd = exec.Command("snort", snortArgs...)

	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr
	return s, nil
}

// snort implements the Exec interface
type snort struct {
	cmd *exec.Cmd
}

func (s *snort) Start() error {
	return s.cmd.Start()
}

func (s *snort) Wait() error {
	return s.cmd.Wait()
}

func (s *snort) Stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		// Shutdown snort normally by sending SIGTERM
		err := s.cmd.Process.Signal(syscall.SIGTERM)
		if err != nil && !errors.Is(err, os.ErrProcessDone) {
			log.WithError(err).Errorf("failed to kill process snort")
		}
	}
}

func detectRules() []string {
	args := []string{}

	if err := filepath.Walk(SnortRulesDirectory, func(path string, info fs.FileInfo, err error) error {
		switch {
		case err != nil:
			break
		case info.IsDir():
			break
		case !strings.HasSuffix(path, ".rules"):
			break
		default:
			log.WithField("file", path).Info("snort rules found")
			args = append(args, "-R", path)
		}
		return err
	}); err != nil {
		log.WithError(err).Error("unable to find snort rules")
	} else if len(args) == 0 {
		log.Warn("no snort rule files found")
	}

	return args
}

func ValidateSnortConfiguration() error {
	snortArgs := append([]string{"-c", SnortConfigFileLocation, "-T"}, detectRules()...)
	snortCmd := exec.Command("snort", snortArgs...)

	out, err := snortCmd.CombinedOutput()

	if err == nil {
		return nil
	}

	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 0 {
		return nil
	}

	return fmt.Errorf("snort configuration is invalid: %w\n%v", err, string(out))
}
