package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/pkg/buildinfo"
)

var VersionCmd = &cobra.Command{
	Use:        "version",
	Aliases:    []string{"version", "ver", "who-dis"},
	SuggestFor: []string{"versio", "covfefe"},
	Short:      "carrotctl version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Build Version:    ", buildinfo.Version)
		fmt.Println("Build date:       ", buildinfo.BuildDate)
		fmt.Println("Git commit:       ", buildinfo.GitRevision)
	},
}
