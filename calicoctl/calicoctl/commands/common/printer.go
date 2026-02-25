// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.

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

package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/safetext/yamltemplate"
	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	calicoErrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	licClient "github.com/projectcalico/calico/licensing/client"
)

type ResourcePrinter interface {
	Print(client client.Interface, resources []runtime.Object) error
}

// ResourcePrinterJSON implements the ResourcePrinter interface and is used to display
// a slice of resources in JSON format.
type ResourcePrinterJSON struct{}

func (r ResourcePrinterJSON) Print(client client.Interface, resources []runtime.Object) error {
	return r.FPrint(os.Stdout, client, resources)
}

func (r ResourcePrinterJSON) FPrint(w io.Writer, client client.Interface, resources []runtime.Object) error {
	// If the results contain a single entry then extract the only value.
	var rs any
	if len(resources) == 1 {
		rs = resources[0]
	} else {
		rs = resources
	}
	if output, err := json.MarshalIndent(rs, "", "  "); err != nil {
		return err
	} else {
		_, err := w.Write(output)
		return err
	}
}

// ResourcePrinterYAML implements the ResourcePrinter interface and is used to display
// a slice of resources in YAML format.
type ResourcePrinterYAML struct{}

func (r ResourcePrinterYAML) Print(client client.Interface, resources []runtime.Object) error {
	return r.FPrint(os.Stdout, client, resources)
}

func (r ResourcePrinterYAML) FPrint(w io.Writer, client client.Interface, resources []runtime.Object) error {
	// If the results contain a single entry then extract the only value.
	var rs any
	if len(resources) == 1 {
		rs = resources[0]
	} else {
		rs = resources
	}
	if output, err := yaml.Marshal(rs); err != nil {
		return err
	} else {
		_, err := w.Write(output)
		return err
	}
}

// ResourcePrinterTable implements the ResourcePrinter interface and is used to display
// a slice of resources in ps table format.
type ResourcePrinterTable struct {
	// The headings to display in the table.  If this is nil, the default headings for the
	// resource are used instead (in which case the `wide` boolean below is used to specify
	// whether wide or narrow format is required.
	Headings []string

	// Wide format.  When headings have not been explicitly specified, this is used to
	// determine whether to the resource-specific default wide or narrow headings.
	Wide bool

	// Namespace included. When a resource being printed is namespaced, this is used
	// to determine if the namespace column should be printed or not.
	PrintNamespace bool
}

func (r ResourcePrinterTable) Print(client client.Interface, resources []runtime.Object) error {
	log.Infof("Output in table format (wide=%v)", r.Wide)
	for _, resource := range resources {
		// Get the resource manager for the resource type.
		rm := resourcemgr.GetResourceManager(resource)

		// If no headings have been specified then we must be using the default
		// headings for that resource type.
		headings := r.Headings
		if r.Headings == nil {
			headings = rm.GetTableDefaultHeadings(r.Wide)
		}

		// Look up the template string for the specific resource type.
		tpls, err := rm.GetTableTemplate(headings, r.PrintNamespace)
		if err != nil {
			return err
		}
		log.WithField("template", tpls).Debug("Got resource template")

		// Convert the template string into a template - we need to include the join
		// function.
		fns := yamltemplate.FuncMap{
			"join":            join,
			"joinAndTruncate": joinAndTruncate,
			"config":          config(client),
			"localtime":       localTime,
		}
		tmpl, err := yamltemplate.New("get").Funcs(fns).Parse(tpls)
		if err != nil {
			panic(err)
		}

		// Use a tabwriter to write out the template - this provides better formatting.
		writer := tabwriter.NewWriter(os.Stdout, 5, 1, 3, ' ', 0)

		// LicenseKey resource can't be printed as it is since the information is encrypted in the token,
		// so we need to decode it first, make sure it's not corrupt then parse the license claims onto the
		// Go template to print the output. Same goes for LicenseKeyList resource, rest of the resources
		// can be sent to Go template directly (in the last else branch).
		if resource.GetObjectKind().GroupVersionKind().Kind == "LicenseKeyList" {
			for _, res := range resource.(*api.LicenseKeyList).Items {
				claims, err := licClient.Decode(res)
				if err != nil {
					return fmt.Errorf("LicenseKey is corrupted: %s", err)
				}
				err = tmpl.Execute(writer, claims)
				if err != nil {
					panic(err)
				}
			}
		} else if resource.GetObjectKind().GroupVersionKind().Kind == "LicenseKey" {
			claims, err := licClient.Decode(*resource.(*api.LicenseKey))
			if err != nil {
				return fmt.Errorf("LicenseKey is corrupted: %s", err)
			}
			err = tmpl.Execute(writer, claims)
			if err != nil {
				panic(err)
			}
		} else {
			err = tmpl.Execute(writer, resource)
			if err != nil {
				panic(err)
			}
		}

		// Templates for ps format are internally defined and therefore we should not
		// hit errors writing the table formats.
		if err != nil {
			panic(err)
		}
		_ = writer.Flush()

		// Leave a gap after each table.
		fmt.Printf("\n")
	}
	return nil
}

// ResourcePrinterTemplateFile implements the ResourcePrinter interface and is used to display
// a slice of resources using a user-defined go-lang template specified in a file.
type ResourcePrinterTemplateFile struct {
	TemplateFile string
}

func (r ResourcePrinterTemplateFile) Print(client client.Interface, resources []runtime.Object) error {
	template, err := os.ReadFile(r.TemplateFile)
	if err != nil {
		return err
	}
	rp := ResourcePrinterTemplate{Template: string(template)}
	return rp.Print(client, resources)
}

// ResourcePrinterTemplate implements the ResourcePrinter interface and is used to display
// a slice of resources using a user-defined go-lang template string.
type ResourcePrinterTemplate struct {
	Template string
}

func (r ResourcePrinterTemplate) Print(client client.Interface, resources []runtime.Object) error {
	// We include a join function in the template as it's useful for multi
	// value columns.
	fns := yamltemplate.FuncMap{
		"join":            join,
		"joinAndTruncate": joinAndTruncate,
		"config":          config(client),
		"localtime":       localTime,
	}
	tmpl, err := yamltemplate.New("get").Funcs(fns).Parse(r.Template)
	if err != nil {
		return err
	}

	err = tmpl.Execute(os.Stdout, resources)
	return err
}

// localTime takes jwt.NumericDate which is an alias for time.Unix (int64)
// and converts it to time.Time for the local timezone.
func localTime(t any) string {
	exp, ok := t.(*jwt.NumericDate)
	if !ok {
		return "unknown - license corrupted"
	}

	return exp.Time().Local().String()
}

// join is similar to strings.Join() but takes an arbitrary slice of interfaces and converts
// each to its string representation and joins them together with the provided separator
// string.
func join(items any, separator string) string {
	return joinAndTruncate(items, separator, 0)
}

// joinAndTruncate is similar to strings.Join() but takes an arbitrary slice of interfaces and converts
// each to its string representation, joins them together with the provided separator
// string and (if maxLen is >0) truncates the output at the given maximum length.
func joinAndTruncate(items any, separator string, maxLen int) string {
	// Nil types.
	if items == nil {
		return ""
	}

	// If it is a map, just convert key,value pairs into slice.
	if reflect.TypeOf(items).Kind() == reflect.Map {
		mapSlice := []string{}
		reflectMap := reflect.ValueOf(items)
		for _, key := range reflectMap.MapKeys() {
			k := key.Interface()
			v := reflectMap.MapIndex(key).Interface()
			s := fmt.Sprintf("%v=%v", k, v)
			mapSlice = append(mapSlice, s)
		}
		sort.Strings(mapSlice)
		items = mapSlice
	}

	if reflect.TypeOf(items).Kind() != reflect.Slice {
		// Input wasn't a slice, convert it to one so we can take advantage of shared
		// buffer/truncation logic...
		items = []any{items}
	}

	slice := reflect.ValueOf(items)
	buf := new(bytes.Buffer)
	for i := 0; i < slice.Len(); i++ {
		if i > 0 {
			buf.WriteString(separator)
		}
		fmt.Fprint(buf, slice.Index(i).Interface())
		if maxLen > 0 && buf.Len() > maxLen {
			// Break out early so that we don't have to stringify a long list, only to then throw it away.
			const truncationSuffix = "..."
			buf.Truncate(maxLen - len(truncationSuffix))
			buf.WriteString(truncationSuffix)
			break
		}
	}
	return buf.String()
}

// config returns a function that returns the current global named config
// value.
func config(client client.Interface) func(string) string {
	var asValue string
	return func(name string) string {
		switch strings.ToLower(name) {
		case "asnumber":
			if asValue == "" {
				if bgpConfig, err := client.BGPConfigurations().Get(context.Background(), "default", options.GetOptions{}); err != nil {
					// Check if it was an actual error accessing the data
					if _, ok := err.(calicoErrors.ErrorResourceDoesNotExist); !ok {
						asValue = "unknown"
					} else {
						// Use the default ASNumber of 64512 when there is none configured (first ASN reserved for private use).
						// https://en.m.wikipedia.org/wiki/Autonomous_system_(Internet)#ASN_Table
						asValue = "64512"
					}
				} else {
					if bgpConfig.Spec.ASNumber != nil {
						asValue = bgpConfig.Spec.ASNumber.String()
					} else {
						// Use the default ASNumber of 64512 when there is none configured (first ASN reserved for private use).
						// https://en.m.wikipedia.org/wiki/Autonomous_system_(Internet)#ASN_Table
						asValue = "64512"
					}
				}
			}
			return asValue
		}
		panic("unhandled config type")
	}
}
