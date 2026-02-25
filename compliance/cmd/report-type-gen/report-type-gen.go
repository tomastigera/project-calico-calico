// Copyright (c) 2019 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"sigs.k8s.io/yaml"

	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

// TODO(bk): could probably extend this command to generate Global Report manifests as well.
var genCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"gen"},
	Short:   "Generate manifests",
	Long:    "Generate the full Global Report Type manifests using go-template definitions.",
	Run: func(cmd *cobra.Command, args []string) {
		runGenCmd(args)
	},
}

func runGenCmd(args []string) {
	// Get list of yaml files inside the 1st level of given directories.
	if err := traverseDir(inDir, true, ".yaml", func(f string) error {
		clog := log.WithField("file", f)
		clog.Info("Processing file")

		contents, err := os.ReadFile(f)
		if err != nil {
			return err
		}

		reportType := api.GlobalReportType{}
		if err := yaml.UnmarshalStrict(contents, &reportType); err != nil {
			return err
		}

		// get the directory for template files.
		inDirName := path.Join(path.Dir(f), reportType.Name)

		if templ, err := getTemplate(inDirName, reportType.Spec.UISummaryTemplate.Name); err == nil {
			reportType.Spec.UISummaryTemplate.Template = string(templ)
			maybeCompressJSON(&reportType.Spec.UISummaryTemplate)
		}

		for i := 0; i < len(reportType.Spec.DownloadTemplates); i++ {
			if templ, err := getTemplate(inDirName, reportType.Spec.DownloadTemplates[i].Name); err == nil {
				reportType.Spec.DownloadTemplates[i].Template = string(templ)
				maybeCompressJSON(&reportType.Spec.DownloadTemplates[i])
			}
		}

		// Validate the report type contents.
		if err := validator.Validate(reportType); err != nil {
			clog.WithError(err).Error("Failed to validate manifest: skipping...")
			return nil
		}

		// Generate manifest.
		manifestContent, err := yaml.Marshal(reportType)
		if err != nil {
			clog.WithError(err).Error("Failed to marshal resulting report type: skipping...")
			return nil
		}
		manifestFullPath := path.Join(outDir, "manifests", path.Base(f))
		if err := os.WriteFile(manifestFullPath, manifestContent, 0644); err != nil {
			log.WithError(err).Error("Failed to write report type to file: skipping...")
		}

		log.WithField("file", manifestFullPath).Info("Successfully generated manifest")

		// Generate manifest.
		jsonContent, err := json.MarshalIndent(reportType, "", " ")
		if err != nil {
			clog.WithError(err).Error("Failed to marshal resulting report type: skipping...")
			return nil
		}
		jsonFullPath := path.Join(outDir, "json", path.Base(f)+".json")
		if err := os.WriteFile(jsonFullPath, jsonContent, 0644); err != nil {
			log.WithError(err).Error("Failed to write report type to file: skipping...")
		}

		log.WithField("file", jsonFullPath).Info("Successfully generated json")
		return nil
	}); err != nil {
		log.WithError(err).Fatal("Fatal error occurred while attempting to generate manifests")
	}
}

// getTemplate returns the contents of the specified template file
func getTemplate(dirName string, templName string) (template []byte, err error) {
	templFullPath := path.Join(dirName, templName)
	template, err = os.ReadFile(templFullPath)
	if err != nil {
		return template, err
	}

	return template, nil
}

// maybeCompressJSON takes the json template and compresses it.
func maybeCompressJSON(template *api.ReportTemplate) {
	clog := log.WithField("template", template.Name)
	// Only attempt to compress if the format ends with .json.
	if !strings.HasSuffix(template.Name, ".json") {
		clog.Debug("Refusing to compress non-json file")
		return
	}

	// Start by removing tabs and newlines from the json.
	template.Template = strings.ReplaceAll(template.Template, "\n", "")
	template.Template = strings.ReplaceAll(template.Template, "\t", "")

	// The JSON should be convertable, if it isn't then print a warning and return the original JSON.
	v := new(any)
	err := json.Unmarshal([]byte(template.Template), v)
	if err != nil {
		clog.WithError(err).Warn("Failed to unmarshal json, refusing to compress")
		return
	}

	// Now convert the interface back to JSON
	j, err := json.Marshal(v)
	if err != nil {
		clog.WithError(err).Warn("Failed to marshal json, refusing to compress")
		return
	}

	// Remove any instances of `"@@@` and `@@@"` - these are put in around template directives which would not convert
	// as JSON.
	s := strings.ReplaceAll(string(j), "\"@@@", "")
	s = strings.ReplaceAll(s, "@@@\"", "")
	template.Template = s
}
