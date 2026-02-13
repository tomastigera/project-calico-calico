// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resourcemgr

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	licClient "github.com/projectcalico/calico/licensing/client"
)

func init() {
	registerResource(
		api.NewLicenseKey(),
		api.NewLicenseKeyList(),
		false,
		[]string{"license", "licensekey", "lic", "licenses", "licensekeys"},
		[]string{"LICENSEID", "EXPIRATION", "NODES"},
		[]string{"LICENSEID", "EXPIRATION", "NODES", "FEATURES"},
		map[string]string{
			"LICENSEID":  "{{.LicenseID}}",
			"EXPIRATION": "{{localtime .Claims.Expiry}}",
			"NODES":      "{{ if not .Nodes }}(Unlimited){{ else }}{{.Nodes}}{{ end }}",
			"FEATURES":   "{{.Features}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.LicenseKey)

			// Decode the license to make sure it's not corrupt.
			licClaims, err := licClient.Decode(*r)
			if err != nil {
				return nil, fmt.Errorf("license is corrupted: %s", err.Error())
			}

			// Validate the license before applying.
			licStatus := licClaims.Validate()
			if licStatus == licClient.NoLicenseLoaded {
				// License is empty or invalid. Don't apply it.
				return nil, errors.New("the license you're trying to create is empty or invalid")
			}
			expiryTime := licClaims.Expiry.Time()
			switch licStatus {
			case licClient.InGracePeriod:
				// License is already expired but in grace period.
				gracePeriodExpiryTime := expiryTime.Add(time.Duration(licClaims.GracePeriod) * time.Hour * 24)
				log.Warningf("The license you're trying to create is expired on %s but in grace period till %v", expiryTime.Local(), gracePeriodExpiryTime.Local())
			case licClient.Expired:
				log.Warningf("The license you're creating expired on %s. Cluster will run in limited mode.", expiryTime.Local())
			default:
				log.Debug("License is valid")
			}

			// License is not corrupt, so we create it.
			return client.LicenseKey().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.LicenseKey)

			// Decode the license to make sure it's not corrupt.
			licClaims, err := licClient.Decode(*r)
			if err != nil {
				return nil, fmt.Errorf("license is corrupted: %s", err.Error())
			}

			// Validate the license before applying.
			licStatus := licClaims.Validate()
			if licStatus == licClient.NoLicenseLoaded {
				// License is empty or invalid. Don't apply it.
				return nil, errors.New("the license you're trying to apply is empty or invalid")
			}
			expiryTime := licClaims.Expiry.Time()
			switch licStatus {
			case licClient.InGracePeriod:
				// License is already expired but in grace period.
				gracePeriodExpiryTime := expiryTime.Add(time.Duration(licClaims.GracePeriod) * time.Hour * 24)
				log.Warningf("The license you're trying to apply expired on %s but in grace period till %v", expiryTime.Local(), gracePeriodExpiryTime.Local())
			case licClient.Expired:
				log.Warningf("The license you're applying expired on %s. Cluster will run in limited mode.", expiryTime.Local())
			default:
				log.Debug("License is valid")
			}

			// See if there's already an existing license, if there is then compare it's expiry date with the one we're
			// about to apply, and only apply the new one if it's expiry is not sooner than the current one.
			currentLic, err := client.LicenseKey().Get(ctx, "default", options.GetOptions{})
			if err != nil {
				// We couldn't get the current licenseKey resource for whatever reason, that's fine, just log it and move on.
				// If it's a datastore issue then apply operation will fail.
				log.WithError(err).Debug("Failed to load the existing LicenseKey from datastore. Moving on")
			} else {
				log.Info("License resource found")
				// Decode and compare the current licenseKey with the one we're about to apply.
				currentLicClaims, err := licClient.Decode(*currentLic)
				if err != nil {
					// Existing license is likely corrupted.
					// Do nothing.
				} else if licClaims.Expiry.Time().Before(currentLicClaims.Expiry.Time()) {
					// The license we're applying expires sooner than the one that's already applied.
					// We reject this change so users don't shoot themselves in the foot.
					return nil, fmt.Errorf("the license you're applying expires on %s, which is sooner than "+
						"the one already applied %s", licClaims.Expiry.Time().Local(), currentLicClaims.Expiry.Time().Local())
				}
			}

			// All checked passed, so we apply the licenseKey.
			return client.LicenseKey().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			return nil, fmt.Errorf("deleting a license is not supported")
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.LicenseKey)
			return client.LicenseKey().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.LicenseKey)
			return client.LicenseKey().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}
