package server

import (
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// writeJSON writes the supplied data as JSON into the HTTP response.
func writeJSON(response http.ResponseWriter, data any, prettyPrint bool) {
	// Write the response as a JSON encoded blob
	var b []byte
	var err error

	if prettyPrint {
		b, err = json.MarshalIndent(data, "", "  ")
	} else {
		b, err = json.Marshal(data)
	}
	if err != nil {
		log.WithError(err).Error("Unable to marshal JSON for response")
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	_, err = response.Write(b)
	if err != nil {
		log.WithError(err).Error("http response write failure")
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = response.Write([]byte{'\n'})
	if err != nil {
		log.WithError(err).Error("http response write failure")
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
}
