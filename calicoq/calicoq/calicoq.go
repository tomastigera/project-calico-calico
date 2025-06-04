// Copyright (c) 2012,2015-2020 Tigera, Inc. All rights reserved.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/calicoq/calicoq/commands"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	licClient "github.com/projectcalico/calico/licensing/client"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

const usage = `Calico query tool.

Usage:
  calicoq [--debug|-d] [--config=<config>] eval <selector> [--output=<output>]
  calicoq [--debug|-d] [--config=<config>] policy <policy-name> [--hide-selectors|-s] [--hide-rule-matches|-r] [--output=<output>]
  calicoq [--debug|-d] [--config=<config>] endpoint <substring> [--hide-selectors|-s] [--hide-rule-matches|-r] [--output=<output>]
  calicoq [--debug|-d] [--config=<config>] host <hostname> [--hide-selectors|-s] [--hide-rule-matches|-r] [--output=<output>]
  calicoq [--debug|-d] version

Description:
  The calicoq command line tool is used to check Calico security policies.

  calicoq eval <selector> is used to display the endpoints that are matched by <selector>.

  calicoq policy <policy-name> shows the endpoints that are relevant to the named policy,
  comprising:
  - the endpoints that the policy applies to (for which ingress or egress traffic is policed
    according to the rules in that policy)
  - the endpoints that match the policy's rule selectors (that are allowed or disallowed as data
    sources or destinations).

  calicoq endpoint <substring> shows you the Calico policies and profiles that relate to endpoints
  whose full ID includes <substring>.

  calicoq host <hostname> shows you the endpoints that are hosted on <hostname> and all the Calico
  policies and profiles that relate to those endpoints.

Notes:
  When specifying a namespaced NetworkPolicy name, the namespace should also be included by
  specifying the <policy-name> in the format "<namespace>/<policy-name>". If the namespace is
  omitted it is assumed the name refers to a GlobalNetworkPolicy.

  When a Calico policy is mapped from a Kubernetes resource, the name will be prefixed with
  "knp.default". For example to query the Kubernetes NetworkPolicy "test-policy" in the Namespace
  "demo-ns" use the following command:
      calicoq policy demo-ns/knp.default.test-policy

  For an endpoint, the full Calico ID is "<host>/<orchestrator>/<workload-name>/<endpoint-name>".
  In the Kubernetes case "<orchestrator>" is always "k8s", "<workload-name>" is "<pod
  namespace>.<pod name>", and "<endpoint-name>" is always "eth0".

Options:
  -c <config> --config=<config>  Path to the file containing connection
                                 configuration in YAML or JSON format.
                                 [default: /etc/calico/calicoctl.cfg]
  -r --hide-rule-matches         Don't show the list of policies and profiles whose
                                 rule selectors match the specified endpoint (or an
                                 endpoint on the specified host) as an allowed or
                                 disallowed source/destination.
  -s --hide-selectors            Don't show the detailed selector expressions involved
                                 (that cause each displayed policy or profile to apply to or match
                                 various endpoints).
  -d --debug                     Log debugging information to stderr.
  -o <output> --output=<output>  Output format. Either yaml, json, or ps.
                                 [default: ps]
`

func main() {
	log.SetLevel(log.FatalLevel)

	//nolint:staticcheck // Ignore SA1019 deprecated
	arguments, err := docopt.Parse(usage, nil, true, buildinfo.Version, false)
	if err != nil {
		log.Fatalf("Failed to parse command line arguments: %v", err)
		os.Exit(1)
	}
	if arguments["--debug"].(bool) {
		log.SetLevel(log.DebugLevel)
	}
	log.Info("Command line arguments: ", arguments)

	outputFormat := arguments["--output"].(string)
	if outputFormat != "json" && outputFormat != "yaml" && outputFormat != "ps" && outputFormat != "" {
		fmt.Printf("Output Format: \"%s\" is not valid. Output Format must be one of json, yaml, or ps\n", outputFormat)
		os.Exit(1)
	}

	// Check for license before executing the command.
	// With the exception of version command.
	if !arguments["version"].(bool) {
		if err = checkLicense(arguments["--config"].(string)); err != nil {
			fmt.Printf("Failed to run the command: %s\n", err)
			os.Exit(1)
		}
	}

	for cmd, thunk := range map[string]func() error{
		"version": func() error {
			buildinfo.PrintVersion()
			return nil
		},
		"eval": func() error {
			// Show all the endpoints that match <selector>.
			return commands.EvalSelector(
				arguments["--config"].(string),
				arguments["<selector>"].(string),
				arguments["--output"].(string),
			)
		},
		"policy": func() error {
			// Show all the endpoints that are relevant to <policy-name>.
			return commands.EvalPolicySelectors(
				arguments["--config"].(string),
				arguments["<policy-name>"].(string),
				arguments["--hide-selectors"].(bool),
				arguments["--hide-rule-matches"].(bool),
				arguments["--output"].(string),
			)
		},
		"endpoint": func() error {
			// Show the policies and profiles that relate to <substring>.
			return commands.DescribeEndpointOrHost(
				arguments["--config"].(string),
				arguments["<substring>"].(string),
				"",
				arguments["--hide-selectors"].(bool),
				arguments["--hide-rule-matches"].(bool),
				arguments["--output"].(string),
			)
		},
		"host": func() error {
			// Show the policies and profiles that relate to all endpoints on
			// <hostname>.
			return commands.DescribeEndpointOrHost(
				arguments["--config"].(string),
				"",
				arguments["<hostname>"].(string),
				arguments["--hide-selectors"].(bool),
				arguments["--hide-rule-matches"].(bool),
				arguments["--output"].(string),
			)
		},
	} {
		if arguments[cmd].(bool) {
			err = thunk()
			break
		}
	}

	if err != nil {
		log.WithError(err).Error("Command failed")
		os.Exit(1)
	}
}

func checkLicense(configFile string) error {
	client, _ := commands.GetClient(configFile)
	ctx := context.Background()
	// Get the LicenseKey resource directly from the backend datastore client.
	lic, err := client.Get(ctx, model.ResourceKey{
		Kind: apiv3.KindLicenseKey,
		Name: "default",
	}, "")
	if err != nil {
		switch err.(type) {
		case cerrors.ErrorResourceDoesNotExist:
			return fmt.Errorf("not licensed for this feature. No valid license was found for your environment. Contact Tigera support or email licensing@tigera.io")
		default:
			return err
		}
	} else {
		log.Info("License resource found")
	}

	lk, ok := lic.Value.(*apiv3.LicenseKey)
	if !ok {
		log.WithFields(log.Fields{"kind": apiv3.KindLicenseKey, "KVPair": lic}).Error("Error asserting LicenseKey")
		return fmt.Errorf("error asserting LicenseKey")
	}

	// Decode the LicenseKey.
	claims, err := licClient.Decode(*lk)
	if err != nil {
		log.WithFields(log.Fields{"kind": apiv3.KindLicenseKey, "name": "default"}).WithError(err).Error("Corrupted LicenseKey")
		return fmt.Errorf("license is corrupted. Please contact Tigera support or email licensing@tigera.io")
	}

	// Check if the license is valid.
	status := claims.Validate()
	if status == licClient.Valid {
		log.Info("License is valid")
		return nil
	}
	fmt.Println("[WARNING] Your license has expired. Please update your license to restore normal operations.")
	fmt.Println("Contact Tigera support or email licensing@tigera.io")
	fmt.Println()
	if status == licClient.Expired {
		return fmt.Errorf("license expired")
	}
	if status == licClient.InGracePeriod {
		// Still in grace period, so don't return an error. We have already printed a message to the console.
		return nil
	}
	// If we get here, it means the license status was not one we understand how to handle.
	// Unknown should never be returned, and NoLicenseLoaded should already be handled above.
	return fmt.Errorf("unhandled license status: %v", status)
}
