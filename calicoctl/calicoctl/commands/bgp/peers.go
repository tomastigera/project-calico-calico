// Copyright (c) 2020 Tigera, Inc. All rights reserved.
package bgp

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
)

var (
	// For more context on the below regex patterns, please see the corresponding peers_test
	// file. It help illustrates the BIRD output that we're trying to parse (which contains
	// BIRD specific reply codes that mark each section).

	// Determine whether BIRD protocol output contains reply code prefix for protocol list
	protocolListingRegex = regexp.MustCompile(`^1002-(.*)$`)

	// Determine whether BIRD protocol output contains reply code prefix for protocol details
	protocolDetailsRegex = regexp.MustCompile(`^1006-(.*)$`)

	// Determine whether BIRD protocol output contains row of data with no reply code prefix
	protocolDataRegex = regexp.MustCompile(`^[ ]{5}(.*)$`)
)

// Peers executes the BGP peers subcommand, which attempts to call the BIRD command interface on the
// Calico node instance given by the node name supplied by the user.
//
// We ask BIRD to filter down the results (i.e. routing protocols in BIRD terminology) to only those
// protocols that correspond to BGP peers. In other words, we want to exclude pseudo protocols like
// kernal, static, device, etc.
func Peers(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl bgp peers <NAME> [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                               YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The bgp peers command prints BGP related information about a given node's peers. For the
  NAME parameter, you can provide either the node name or pod name of the node instance.
`
	parsedArgs, err := docopt.ParseArgs(doc, args, "")
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

	name := parsedArgs["<NAME>"]
	return showPeers(name.(string))
}

// Internal function for BGP peers subcommand.
func showPeers(input string) error {
	// We ultimately need the pod name to remote exec into the pod and extract BGP stats
	var podName string
	// Ensure node name is valid format; we want to ensure user does not inject additional shell commands
	// using the node name argument
	nodeName := argutils.ValidateResourceName(input)

	// Ensure kubectl command is available (since we need it to access BGP information)
	if err := common.KubectlExists(); err != nil {
		return fmt.Errorf("missing dependency: %s", err)
	}

	// First, assume user supplied a host node name; attempt to locate corresponding pod name. We do this first
	// because we think users will more likely use host node name with this command. Use -o name to output just
	// the name.
	// If this command is successful it will simply output something like "pod/calico-node-pz6kx". If nothing was
	// found it will return empty output.
	log.Debugf("First attempt, assume user provided node name [%s] ... try to determine pod name", nodeName)
	output, err := common.ExecCmd(fmt.Sprintf(
		"kubectl get pods -n %s -l %s --field-selector spec.nodeName=%s -o name",
		common.CalicoNamespace,
		common.LabelCalicoNode,
		nodeName,
	))
	// Stop if we get an error
	if err != nil {
		return fmt.Errorf("could not retrieve node with host node name %s: %s", nodeName, err)
	}

	extractedPodName := extractPodName(output.String())
	// If above failed, determine whether user supplied a valid pod name directly
	if extractedPodName == "" {
		log.Debugln("Could not find pod name based on node name.")
		log.Debugf("Second attempt, assume user provided pod name [%s] ... verify it is valid", nodeName)
		_, err = common.ExecCmd(fmt.Sprintf("kubectl get pod %s -n %s", nodeName, common.CalicoNamespace))
		if err != nil {
			return fmt.Errorf("could not retrieve node with pod name %s: %s", nodeName, err)
		}
		podName = nodeName
	} else {
		podName = extractedPodName
	}

	// Connect to node and access BIRD command interface in order to extract BGP info.
	birdCmd := "birdcl -s /var/run/calico/bird.ctl -v -r show protocols all"
	output, err = common.ExecCmd(
		fmt.Sprintf("kubectl exec %s -n %s -- %s", podName, common.CalicoNamespace, birdCmd),
	)
	if err != nil {
		return fmt.Errorf("could not retrieve info for BGP peers: %s", err)
	}

	// Since BGP peers could be either Mesh, Node or Global we want to filter out all other pseudo-protocols
	// (e.g. kernel, device, etc.).
	var sb strings.Builder
	validateAndPrint(output.String(), &sb)
	fmt.Print(sb.String())

	return nil
}

// Extract the pod name from the provided output (expected to be from kubectl).
func extractPodName(output string) string {
	if len(output) > 0 {
		tokens := strings.Split(output, "/")
		n := len(tokens)
		// Expect output with format "pod/calico-node-6x5lx"
		if n >= 1 && tokens[0] == "pod" {
			return tokens[n-1]
		}
	}
	return ""
}

// Validate and transform output from BIRD according to our needs (e.g. filter out rows we don't want).
// Validation involves mostly looking at BIRD reply codes in the output:
// https://github.com/projectcalico/bird/blob/master/doc/reply_codes
func validateAndPrint(birdOutput string, w io.Writer) {
	// Do not print any output if it does not contain any protocols
	if strings.Contains("8003", birdOutput) {
		return
	}

	rows := strings.Split(birdOutput, "\n")
	skipLines := false
	n := len(rows)
	for i, row := range rows {
		// Each section for a Protocol listing is separated by newline; reset after each listing
		if strings.TrimSpace(row) == "" {
			log.Debugf("process row: [%s] ... reset", row)
			// Print explicit newline separator
			if !skipLines && i < n-1 {
				_, _ = fmt.Fprint(w, "\n")
			}
			skipLines = false
			continue
		}
		// If we're still skipping output, ignore current line
		if skipLines {
			log.Debugf("process row: [%s] ... skip (row is part of non-BGP protocol)", row)
			continue
		}
		// Print table header as is
		if strings.HasPrefix("2002", row) {
			_, _ = fmt.Fprintf(w, "%s\n", row)
			log.Debugf("process row: [%s] ... print (table header)", row)
			continue
		}
		// Beginning row of a procotol listing
		if protocolListingRegex.MatchString(row) {
			data := row[5:] // Remove reply code prefix
			// Determine whether this is a BGP peer. If not, then ignore all
			// subsequent lines related to it.
			if !common.BGPPeerRegex.MatchString(data) {
				skipLines = true
				log.Debugf("process row: [%s] ... skip non-BGP procotol listing [%s]", row, data)
			} else {
				_, _ = fmt.Fprintf(w, "%s\n", data)
				log.Debugf("process row: [%s] ... print (BGP procotol listing) [%s]", row, data)
			}
			continue
		}
		// Protocol details row
		if protocolDetailsRegex.MatchString(row) {
			// Trim off any BIRD reply code prefix from the row
			trimmed := protocolDetailsRegex.ReplaceAllString(row, "${1}")
			_, _ = fmt.Fprintf(w, "%s\n", trimmed)
			log.Debugf("process row: [%s] ... print (1st row of protocol details) [%s]", row, trimmed)
			continue
		}

		if protocolDataRegex.MatchString(row) {
			// Trim off any BIRD reply code prefix from the row
			trimmed := protocolDataRegex.ReplaceAllString(row, "${1}")
			_, _ = fmt.Fprintf(w, "%s\n", trimmed)
			log.Debugf("process row: [%s] ... print (follow-up row of protocol details) [%s]", row, trimmed)
			continue
		}

		// Ignore all other rows, e.g. row "0001" (BIRD version) or row "0016"
		// (restricted access header)
		log.Debugf("process row: [%s] ... skip", row)
	}
}
