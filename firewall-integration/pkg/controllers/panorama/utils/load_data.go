// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package utils

import (
	"encoding/json"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
)

// LoadData loads json file data from a given file name, and unmarshals the byte contents onto a
// generic structure. Expects the json file to be successfully opened. Returns empty data for an
// empty file name. Defers closing the file until after the end of the test.
func LoadData(fileName string, data interface{}) error {
	// Open the jsonFile.
	jsonFile, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer func() { _ = jsonFile.Close() }()

	// Read opened jsonFile as a byte array.
	byteValue, _ := io.ReadAll(jsonFile)
	// Unmarshal the byteArray which contains the jsonFile's content into 'data'.
	err = json.Unmarshal(byteValue, data)
	if err != nil {
		log.WithError(err).Debugf("failed to load data")
		return err
	}

	return nil
}
