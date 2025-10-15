// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/flows"
)

// This small tool is helpful for converting Elasticsearch aggregated search results into
// Linseed L3Flow output using the same logic that the L3Flow backend does. It was designed
// for converting large blobs of data into a format to be used in our unit tests.

var inputPath string

func init() {
	flag.StringVar(&inputPath, "infile", "", "Input composite aggregation result file")
}

func main() {
	flag.Parse()

	// Load the json file.
	f, err := os.ReadFile(inputPath)
	if err != nil {
		panic(fmt.Errorf("error opening file %s: %s", inputPath, err))
	}

	// Use the flow backend to convert it.
	esResult := elastic.SearchResult{}
	err = json.Unmarshal(f, &esResult)
	if err != nil {
		panic(err)
	}

	// Convert it to a v1.List the same way Linseed's backend would.
	buckets, found := esResult.Aggregations.Composite("flog_buckets")
	if !found {
		panic("flog_buckets not found!")
	}

	log := logrus.WithField("foo", "bar")
	fb := flows.NewBucketConverter()
	query := fb.BaseQuery()
	list := v1.List[v1.L3Flow]{
		Items: []v1.L3Flow{},
	}
	for _, bucket := range buckets.Buckets {
		cab, err := query.ConvertBucketHelper(bucket, true)
		if err != nil {
			panic(err)
		}
		flow := fb.ConvertBucket(log, cab)
		if flow != nil {
			list.Items = append(list.Items, *flow)
		}
	}

	// Print it out a JSON.
	out, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Print(string(out))
}
