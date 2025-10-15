// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/capture"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const defaultCaptureDir = "/var/log/calico/pcap"

func Capture(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl captured-packets ( copy | clean ) <NAME>
                [--config=<CONFIG>] [--namespace=<NS>] [--all-namespaces] [--dest=<DEST>] [--allow-version-mismatch]

Examples:
  # Copies capture files for packet capture from default namespace in the current directory.
  calicoctl captured-packets copy my-capture
  # Delete capture files for packet capture from default namespace still left on the system
  calicoctl captured-packets clean my-capture

Options:
  -n --namespace=<NS>          Namespace of the packet capture.
                               Uses the default namespace if not specified. [default: default]
  -a --all-namespaces          If present, list the requested packet capture(s) across all namespaces.
  -d --dest=<DEST>             If present, uses the directory specified as the destination. [default: .]
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                               YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  Commands for accessing Capture related information.

  See 'calicoctl captured-packets <command> --help' to read about a specific subcommand.`

	var parser = &docopt.Parser{
		HelpHandler:   docopt.PrintHelpOnly,
		OptionsFirst:  false,
		SkipHelpFlags: false,
	}
	parsedArgs, err := parser.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand", strings.Join(args, " "))
	}

	if len(parsedArgs) == 0 {
		return nil
	}

	err = common.CheckVersionMismatch(parsedArgs["--config"], parsedArgs["--allow-version-mismatch"])
	if err != nil {
		return err
	}

	// List boolean parameters
	var isCopyCommand = argutils.ArgBoolOrFalse(parsedArgs, "copy")
	var isCleanCommand = argutils.ArgBoolOrFalse(parsedArgs, "clean")
	var allNamespaces = argutils.ArgBoolOrFalse(parsedArgs, "--all-namespaces")

	// List string parameters
	cfgStr, err := argutils.ArgString(parsedArgs, "--config")
	if err != nil {
		return nil
	}
	name, err := argutils.ArgString(parsedArgs, "<NAME>")
	if err != nil {
		return err
	}
	destination, err := argutils.ArgString(parsedArgs, "--dest")
	if err != nil {
		return err
	}
	namespace, err := argutils.ArgString(parsedArgs, "--namespace")
	if err != nil {
		return err
	}
	// Set the namespace to an empty string so that we can list all the locations for the capture
	if allNamespaces {
		namespace = ""
	}

	// Resolve capture dir location
	captureDir, err := resolveCaptureDir(cfgStr)
	if err != nil {
		return err
	}
	log.Debugf("Resolved capture directory to %s", captureDir)

	// Ensure kubectl command is available
	if err := common.KubectlExists(); err != nil {
		return fmt.Errorf("an error occurred checking if kubctl exists: %w", err)
	}
	// Extract kubeconfig variable
	cfg, err := clientmgr.LoadClientConfig(cfgStr)
	if err != nil {
		return err
	}

	// Create the capture commands
	captureCmd := capture.NewCommands(common.NewKubectlCmd(cfg.Spec.Kubeconfig))

	// List the locations of the capture files
	locations, err := captureCmd.List(captureDir, name, namespace)
	if err != nil {
		return err
	}

	var results int
	var errs []error

	// Run copy or clean
	if isCopyCommand {
		results, errs = captureCmd.Copy(locations, destination)
	} else if isCleanCommand {
		results, errs = captureCmd.Clean(locations)
	}

	// in case --all-namespaces is used and we have at least 1 successful result
	// we will return 0 exit code
	if allNamespaces {
		if results != 0 {
			return nil
		}
	}

	if errs != nil {
		var result []string
		for _, e := range errs {
			result = append(result, e.Error())
		}
		return errors.New(strings.Join(result, ";"))
	}

	return nil
}

func resolveCaptureDir(cfg string) (string, error) {
	client, err := clientmgr.NewClient(cfg)
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	felixConfig, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{ResourceVersion: ""})
	if err != nil {
		return "", err
	}

	if felixConfig.Spec.CaptureDir == nil {
		return defaultCaptureDir, nil
	}

	return *felixConfig.Spec.CaptureDir, nil
}
