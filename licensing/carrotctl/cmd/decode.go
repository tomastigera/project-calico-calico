package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"go.yaml.in/yaml/v3"

	"github.com/projectcalico/calico/licensing/client"
)

var (
	lFile string
)

func init() {
	DecodeLicenseCmd.Flags().StringVarP(&lFile, "file", "f", "", "Decode a given license file")
	_ = DecodeLicenseCmd.MarkFlagRequired("file")
}

var DecodeLicenseCmd = &cobra.Command{
	Use:   "decode",
	Short: "Decode licenses",
	Run: func(cmd *cobra.Command, args []string) {
		f, err := os.ReadFile(lFile)
		if err != nil {
			log.Fatalf("error reading license file: %v", err)
		}

		lic := api.NewLicenseKey()

		err = yaml.Unmarshal(f, lic)
		if err != nil {
			log.Fatal(err)
		}

		cl, err := client.Decode(*lic)
		if err != nil {
			log.Fatal(err)
		}

		bits, err := json.Marshal(cl)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Print(string(bits))
	},
}
