// Copyright (c) 2016, 2020 Tigera, Inc. All rights reserved.

package commands

import (
	"bytes"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

func EvalSelector(configFile, sel string, outputFormat string) (err error) {
	cbs := NewEvalCmd(configFile)
	cbs.AddSelector("the selector", sel)
	noopFilter := func(update api.Update) (filterOut bool) {
		return false
	}
	cbs.Start(noopFilter)

	matches := cbs.GetMatches()
	output := EvalSelectorPrintObjects(sel, matches)

	switch outputFormat {
	case "yaml":
		EvalSelectorPrintYAML(output)
	case "json":
		EvalSelectorPrintJSON(output)
	case "ps":
		EvalSelectorPrint(output)
	}

	// If there are any errors connecting to the remote clusters, report the errors and exit.
	cbs.rcc.CheckForErrorAndExit()

	return
}

func EvalSelectorPrint(output OutputList) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%v:\n", output.Description)
	for _, endpoint := range output.Endpoints {
		fmt.Fprintf(&buf, "  %v\n", endpoint.PrintName())
	}
	if _, err := buf.WriteTo(os.Stdout); err != nil {
		log.Errorf("Failed to write to Stdout: %v", err)
	}
}

func EvalSelectorPrintYAML(output OutputList) {
	err := printYAML([]OutputList{output})
	if err != nil {
		log.Errorf("Unexpected error printing to YAML: %s", err)
		fmt.Println("Unexpected error printing to YAML")
	}
}

func EvalSelectorPrintJSON(output OutputList) {
	err := printJSON([]OutputList{output})
	if err != nil {
		log.Errorf("Unexpected error printing to JSON: %s", err)
		fmt.Println("Unexpected error printing to JSON")
	}
}

func EvalSelectorPrintObjects(sel string, matches map[any][]string) OutputList {
	output := OutputList{
		Description: fmt.Sprintf("Endpoints matching selector %v", sel),
	}
	for endpoint := range matches {
		output.Endpoints = append(output.Endpoints, NewEndpointPrintFromKey(endpoint))
	}

	return output
}
