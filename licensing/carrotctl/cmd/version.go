package cmd

import (
	"fmt"

	"github.com/projectcalico/calico/typha/pkg/buildinfo"
	"github.com/spf13/cobra"
)

var VersionCmd = &cobra.Command{
	Use:        "version",
	Aliases:    []string{"version", "ver", "who-dis"},
	SuggestFor: []string{"versio", "covfefe"},
	Short:      "carrotctl version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Build Version:    ", buildinfo.GitVersion)
		fmt.Println("Build date:       ", buildinfo.BuildDate)
		fmt.Println("Git commit:       ", buildinfo.GitRevision)
	},
}
