// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package commands

import (
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/nonclusterhost"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

func NonClusterHost(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> nonclusterhost <command> [<args>...]

    generate-config  Generate non-cluster host configuration.

Options:
  -h --help          Show this screen.

Description:
  Non-cluster host management commands for Calico.

  See '<BINARY_NAME> nonclusterhost <command> --help' to read about a specific subcommand.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parser := &docopt.Parser{
		HelpHandler:   docopt.PrintHelpAndExit,
		OptionsFirst:  true,
		SkipHelpFlags: false,
	}
	parsedArgs, err := parser.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	if parsedArgs["<command>"] == nil {
		return nil
	}
	command := parsedArgs["<command>"].(string)
	args = append([]string{"nonclusterhost", command}, parsedArgs["<args>"].([]string)...)

	switch command {
	case "generate-config":
		return nonclusterhost.GenerateConfig(args)
	default:
		fmt.Println(doc)
	}

	return nil
}
