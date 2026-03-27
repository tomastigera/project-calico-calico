// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package commands

import (
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/review"
)

// Review includes any review-level subcommands.
func Review(args []string) error {
	doc := `Usage:
  calicoctl review <command> [<args>...]

    unused-policies  List policies and rules with no activity in a given time window.

Options:
  -h --help      Show this screen.

Description:
  Commands for reviewing policy activity and identifying unused resources.

  See 'calicoctl review <command> --help' to read about a specific subcommand.`

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
	args = append([]string{"review", command}, arguments["<args>"].([]string)...)

	switch command {
	case "unused-policies":
		return review.UnusedPolicies(args)
	default:
		return fmt.Errorf("unknown command %q for 'calicoctl review'. Use '--help' to see available commands", command)
	}
}
