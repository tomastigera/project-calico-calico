// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost

import (
	"context"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	"github.com/projectcalico/calico/pkg/nonclusterhost"
)

const (
	defaultServiceAccount = "tigera-noncluster-host"
)

func GenerateConfig(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> nonclusterhost generate-config [--config=<CONFIG>] [--namespace=<NAMESPACE>] [--serviceaccount=<SERVICEACCOUNT>] [--certfile=<CERTFILE>]

Options:
  -h --help                             Show this screen.
  -c --config=<CONFIG>                  Path to the file containing connection configuration
                                        in YAML or JSON format.
                                        [default: ` + constants.DefaultConfigPath + `]
     --namespace=<NAMESPACE>            The namespace where the service account for non-cluster hosts
                                        resides.
                                        [default: ` + common.CalicoNamespace + `]
     --serviceaccount=<SERVICEACCOUNT>  The service account used by non-cluster hosts to authenticate
                                        and securely access the cluster.
                                        [default: ` + defaultServiceAccount + `]
     --certfile=<CERTFILE>              Path to the file containing the PEM-encoded authority
                                        certificates.

Description:
  Generate non-cluster hosts configuration.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}

	// Load the client config and connect.
	cf := parsedArgs["--config"].(string)
	clientConfig, err := clientmgr.LoadClientConfig(cf)
	if err != nil {
		return err
	}

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", clientConfig.Spec.KubeConfig.Kubeconfig)
	if err != nil {
		return err
	}

	opts := &nonclusterhost.ConfigGeneratorOptions{
		KubeConfig: kubeConfig,
	}

	opts.Namespace = parsedArgs["--namespace"].(string)
	if opts.Namespace == "" {
		opts.Namespace = common.CalicoNamespace
	}
	opts.ServiceAccount = parsedArgs["--serviceaccount"].(string)
	if opts.ServiceAccount == "" {
		opts.ServiceAccount = defaultServiceAccount
	}
	var ok bool
	opts.CertFile, ok = parsedArgs["--certfile"].(string)
	if !ok {
		opts.CertFile = ""
	}

	gen, err := nonclusterhost.NewConfigGenerator(opts)
	if err != nil {
		return err
	}

	yaml, err := gen.Generate(context.TODO())
	if err != nil {
		return err
	}

	fmt.Print(string(yaml))
	return nil
}
