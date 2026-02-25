// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package config

import (
	"fmt"
	"os"
	"slices"
)

type Config struct {
	TLSCert, TLSKey       string
	EnvoyImg, DikastesImg string
	ListenAddr            string
	Dataplane             string // "iptables" or "nftables"
}

func FromEnv() (*Config, error) {
	tlsCert := os.Getenv("L7ADMCTRL_TLSCERTPATH")
	tlsKey := os.Getenv("L7ADMCTRL_TLSKEYPATH")
	envoyImg := os.Getenv("L7ADMCTRL_ENVOYIMAGE")
	dikastesImg := os.Getenv("L7ADMCTRL_DIKASTESIMAGE")
	listenAddr := os.Getenv("L7ADMCTRL_LISTENADDR")
	dataplane := os.Getenv("DATAPLANE")

	if listenAddr == "" {
		listenAddr = ":6443"
	}

	if slices.Contains([]string{tlsCert, tlsKey, envoyImg, dikastesImg}, "") {
		return nil, fmt.Errorf("one of required env vars not declared")
	}

	return &Config{
		TLSCert:     tlsCert,
		TLSKey:      tlsKey,
		EnvoyImg:    envoyImg,
		DikastesImg: dikastesImg,
		ListenAddr:  listenAddr,
		Dataplane:   dataplane,
	}, nil
}
