// Copyright (c) 2023 Tigera, Inc. All rights reserved
package utils

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

const (
	// Default location for the resolv.conf file.
	DefaultResolveConfPath = "/etc/resolv.conf"

	// Default cluster domain value for k8s clusters.
	DefaultClusterDomain = "cluster.local"
)

// GetClusterDomain parses the path to resolv.conf to find the cluster domain.
func GetClusterDomain(resolvConfPath string) (string, error) {
	var clusterDomain string
	file, err := os.Open(resolvConfPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	reg := regexp.MustCompile(`^search.*?\ssvc\.([^\s]*)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := reg.FindStringSubmatch(scanner.Text())
		if len(match) > 0 {
			clusterDomain = match[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if clusterDomain == "" {
		return "", fmt.Errorf("failed to find cluster domain in resolv.conf")
	}

	return clusterDomain, nil
}

// GetServiceDNSNames returns the service name suffix:
// svc.<cluster-domain>.
func GetServiceNameSuffix(clusterDomain string) string {
	return fmt.Sprintf("svc.%s", clusterDomain)
}
