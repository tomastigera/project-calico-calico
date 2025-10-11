// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package weputils

import (
	"fmt"
	"strings"
)

func ExtractNamespaceAndNameFromWepName(wepName string) (ns string, podName string, err error) {
	parts := strings.Split(wepName, "/")
	if len(parts) == 2 {
		return parts[0], parts[1], nil
	}
	return "", "", fmt.Errorf("could not parse name %v", wepName)
}
