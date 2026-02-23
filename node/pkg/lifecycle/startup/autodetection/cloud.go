// Copyright (c) 2018 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package autodetection

import (
	"errors"
	"io"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
)

const (
	awsInstanceIDURL = "http://169.254.169.254/latest/meta-data/instance-id"
	awsZoneURL       = "http://169.254.169.254/latest/meta-data/placement/availability-zone"
)

type CloudDetector interface {
	GetOrchRef() (internalapi.OrchRef, error)
}

type aws struct{}

var CloudDetectors = map[string]CloudDetector{"aws": aws{}}

// GetCloudOrchRef attempts to determine the cloud and instance ID for the node.
func GetCloudOrchRef() (internalapi.OrchRef, error) {
	for c, d := range CloudDetectors {
		ref, err := d.GetOrchRef()
		if err == nil {
			return ref, nil
		}
		log.WithError(err).WithField("cloud", c).Info("failed to get instance ID")
	}
	return internalapi.OrchRef{}, errors.New("no cloud metadata found")
}

// GetOrchRef attempts to query the EC2 metadata service to determine the instance ID.
func (a aws) GetOrchRef() (internalapi.OrchRef, error) {
	timeout := time.Duration(250 * time.Millisecond)
	client := http.Client{Timeout: timeout}

	resp, err := client.Get(awsInstanceIDURL)
	if err != nil {
		log.WithField("URL", awsInstanceIDURL).Infof("Unable to get AWS instance ID")
		return internalapi.OrchRef{}, err
	}
	instance, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Error while reading instance response body")
		return internalapi.OrchRef{}, err
	}
	resp, err = client.Get(awsZoneURL)
	if err != nil {
		log.WithField("URL", awsZoneURL).Infof("Unable to get AWS zone")
		return internalapi.OrchRef{}, err
	}
	zone, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Error while reading zone response body")
		return internalapi.OrchRef{}, err
	}
	return internalapi.OrchRef{Orchestrator: "aws", NodeName: "/" + string(zone) + "/" + string(instance)}, nil
}
