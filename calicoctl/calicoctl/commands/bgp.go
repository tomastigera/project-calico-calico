// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package commands

import (
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/bgp"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
)

// BGP contains switch for subcommands related to BGP peering.
func BGP(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl bgp <command> [<args>...]

    peers            Display information about BGP peers for a specific node.

Options:
  -h --help      Show this screen.

Description:
  Commands for accessing BGP related information.

  See 'calicoctl bgp <command> --help' to read about a specific subcommand.`

	var parser = &docopt.Parser{
		HelpHandler:   docopt.PrintHelpAndExit,
		OptionsFirst:  true,
		SkipHelpFlags: false,
	}
	arguments, err := parser.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand", strings.Join(args, " "))
	}
	if arguments["<command>"] == nil {
		return nil
	}

	command := arguments["<command>"].(string)
	args = append([]string{"bgp", command}, arguments["<args>"].([]string)...)

	switch command {
	case "peers":
		return bgp.Peers(args)
	default:
		fmt.Println(doc)
	}

	return nil
}
