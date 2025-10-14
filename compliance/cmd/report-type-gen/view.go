package main

import (
	"fmt"
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	yaml "sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/libcalico-go/lib/compliance"
)

var viewCmd = &cobra.Command{
	Use:   "view report-type template-name",
	Short: "View a sample render",
	Long: `
View a sample render given report-type(e.g. inventory, cis-benchmark) and template-name (e.g. endpoints)`,
	Run: func(cmd *cobra.Command, args []string) {
		runViewCmd(args)
	},
	Args: cobra.MinimumNArgs(2),
}

func runViewCmd(args []string) {
	// Extract report type and template name.
	reportType, templateName := args[0], args[1]

	// Get list of yaml files inside the 1st level of given directories.
	if err := traverseDir(viewDir, true, ".yaml", func(f string) error {
		clog := log.WithField("file", f)
		if strings.Split(path.Base(f), ".yaml")[0] != reportType {
			clog.Debug("No match, passing")
			return nil
		}
		clog.Debug("Found file, opening")

		contents, err := os.ReadFile(f)
		if err != nil {
			return err
		}

		reportType := api.GlobalReportType{}
		if err := yaml.UnmarshalStrict(contents, &reportType); err != nil {
			return err
		}

		for _, tmpl := range append(reportType.Spec.DownloadTemplates, reportType.Spec.UISummaryTemplate) {
			clog2 := clog.WithField("tmpl", tmpl.Name)
			if strings.Split(tmpl.Name, ".")[0] != templateName {
				clog2.Debug("No match, passing")
				continue
			}

			clog2.Debug("Template found, rendering")
			rendered, err := compliance.RenderTemplate(tmpl.Template, &compliance.ReportDataSample)
			if err != nil {
				return err
			}

			fmt.Println(rendered)
			os.Exit(0)
		}

		log.Fatal("Requested template does not exist")
		return nil
	}); err != nil {
		log.WithError(err).Fatal("Fatal error occurred while attempting to view rendered manifest")
	}
}
