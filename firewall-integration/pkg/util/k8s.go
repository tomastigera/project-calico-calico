// Copyright 2019 Tigera Inc. All rights reserved.

package util

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
)

const (
	ZoneLabelKey = "zone"
)

// This util is to gather all label 'zone' values from k8s pods.
//
// returns a list of, possible duplicated, zone-names

func GetAllZonesFromK8s(cs datastore.ClientSet) ([]string, error) {
	zones := make([]string, 0)

	listOpts := metav1.ListOptions{LabelSelector: ZoneLabelKey}
	resources, err := cs.CoreV1().Pods("").List(context.Background(), listOpts)
	if err != nil {
		return zones, err
	}

	for idx := range resources.Items {
		log.Debugf("resource-name: %s", resources.Items[idx].Name)
		for key, val := range resources.Items[idx].Labels {
			log.Debugf("%s: %s", key, val)
			if key == ZoneLabelKey {
				zones = append(zones, val)
			}
		}
	}
	log.Infof("zones: %v", zones)

	return zones, nil
}

func GetAllPoliciesFromFwTier(cs datastore.ClientSet, tierName string) ([]string, error) {
	availableFWNetworkPolicies := make([]string, 0)

	selector := fmt.Sprintf("projectcalico.org/tier = %s", tierName)
	gnps, err := cs.GlobalNetworkPolicies().List(context.Background(), metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return availableFWNetworkPolicies, err
	}

	for _, gnp := range gnps.Items {
		log.Debugf("network-policy-name: %s", gnp.Name)
		availableFWNetworkPolicies = append(availableFWNetworkPolicies, gnp.Name)
	}
	return availableFWNetworkPolicies, nil
}
