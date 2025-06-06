// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package daemon

import (
	"context"
	"net"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/pkg/nonclusterhost"
)

func bootstrapNonClusterHostTyphaAddress(ctx context.Context) (string, error) {
	extractor, err := newTyphaAddressExtractor(ctx)
	if err != nil {
		logrus.WithError(err).Error("Failed to create Typha address extractor")
		return "", err
	}

	addr, err := extractor.typhaAddress()
	if err != nil {
		logrus.WithError(err).Error("Failed to get Typha address for non-cluster hosts")
		return "", err
	}
	return addr, nil
}

type typhaAddressExtractor struct {
	ctx context.Context

	k8sDynamicClient dynamic.Interface
}

func newTyphaAddressExtractor(ctx context.Context) (*typhaAddressExtractor, error) {
	kubeConfigPath := os.Getenv("KUBECONFIG")
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, err
	}

	dynamicClient, err := dynamic.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	return &typhaAddressExtractor{
		ctx: ctx,

		k8sDynamicClient: dynamicClient,
	}, nil
}

func (e *typhaAddressExtractor) typhaAddress() (string, error) {
	nch, err := nonclusterhost.GetNonClusterHost(e.ctx, e.k8sDynamicClient)
	if err != nil {
		logrus.WithError(err).Error("Failed to get nonclusterhost resource")
		return "", err
	}

	endpoint, err := nonclusterhost.ExtractFromNonClusterHostSpec(nch, "typhaEndpoint", nil)
	if err != nil {
		logrus.WithError(err).Error("Failed to extract endpoint")
		return "", err
	}

	ip, port, err := e.parseAndLookupIP(endpoint)
	if err != nil {
		logrus.WithError(err).WithField("typhaEndpoint", endpoint).Error("Failed to lookup IP")
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func (e *typhaAddressExtractor) parseAndLookupIP(endpoint string) (net.IP, string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, "", err
	}

	// Typha endpoint is in ip:port format
	_, err = strconv.Atoi(port)
	if err != nil {
		return nil, "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip, port, nil
	}

	// Typha endpoint is in host:port format
	// We need to lookup the IP address
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, "", err
	}
	return ips[0], port, nil
}
