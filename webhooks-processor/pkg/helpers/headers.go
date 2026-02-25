// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package helpers

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	headerNameRegex  = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	headerValueRegex = regexp.MustCompile(`^[a-zA-Z0-9_ :;.,\/"'?!(){}\[\]@<>=\-+*#$&|~^%` + "`]+$")
)

func ProcessHeaders(rawHeaders string) (map[string]string, error) {
	headers := make(map[string]string)
	var err error
	for line := range strings.SplitSeq(rawHeaders, "\n") {
		if keyValue := strings.SplitN(line, ":", 2); len(keyValue) == 2 {
			if err := validateHeaderName(keyValue[0]); err != nil {
				return nil, err
			}
			if err := validateHeaderValue(keyValue[1]); err != nil {
				return nil, err
			}
			headers[keyValue[0]] = keyValue[1]
		}
	}
	return headers, err
}

func validateHeaderName(header string) (err error) {
	if !headerNameRegex.MatchString(header) {
		err = fmt.Errorf("HTTP header name contains invalid characters: %s", header)
	}
	return
}

func validateHeaderValue(value string) (err error) {
	if !headerValueRegex.MatchString(value) {
		err = fmt.Errorf("HTTP header value contains invalid characters: %s", value)
	}
	return
}
