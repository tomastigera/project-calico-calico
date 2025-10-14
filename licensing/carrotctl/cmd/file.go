package cmd

import (
	"fmt"
	"os"

	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	yaml "sigs.k8s.io/yaml"
)

func WriteYAML(license api.LicenseKey, filePrefix string) error {
	output, err := yaml.Marshal(license)
	if err != nil {
		return err
	}

	if debug {
		fmt.Printf("\nLicense file contents: \n %s\n", string(output))
	}

	f, err := os.Create(fmt.Sprintf("./%s-license.yaml", filePrefix))
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(output)
	if err != nil {
		return err
	}

	fmt.Printf("\nCreated license file '%s-license.yaml'\n\n", filePrefix)

	return nil
}
