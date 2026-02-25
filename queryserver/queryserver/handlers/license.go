// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	licClient "github.com/projectcalico/calico/licensing/client"
)

// License type wraps libcalico API Client.
type License struct {
	Client clientv3.Interface
}

type UnixJSONTime time.Time

func (t UnixJSONTime) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, "\"%s\"", time.Time(t).Format(time.UnixDate)), nil
}

type licenseResponse struct {
	IsValid bool          `json:"is_valid"`
	Warning string        `json:"warning,omitempty"`
	Expiry  *UnixJSONTime `json:"expiry,omitempty"`
	Package string        `json:"package,omitempty"`
}

func (l License) LicenseHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	licResp := licenseResponse{
		IsValid: false,
	}

	// Get the LicenseKey resource from datastore Client.
	lic, err := l.Client.LicenseKey().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		switch err.(type) {
		case cerrors.ErrorResourceDoesNotExist:
			licResp.Warning = "No valid license was found for your environment. Please contact Tigera support or email licensing@tigera.io"
			writeResponse(w, licResp)
			return
		default:
			licResp.Warning = fmt.Sprintf("Error getting LicenseKey resource: %s", err)
			writeResponse(w, licResp)
			return
		}
	}

	// Decode the LicenseKey.
	claims, err := licClient.Decode(*lic)
	if err != nil {
		log.WithFields(log.Fields{"kind": apiv3.KindLicenseKey, "name": "default"}).WithError(err).Error("Corrupted LicenseKey")
		licResp.Warning = "License is corrupted. Please contact Tigera support or email licensing@tigera.io"
		writeResponse(w, licResp)
		return
	}

	exp := UnixJSONTime(claims.Expiry.Time())
	licResp.Expiry = &exp
	licResp.Package = string(lic.Status.Package)

	// Check if the license is valid.
	if licStatus := claims.Validate(); licStatus != licClient.Valid {
		// If the license is expired (but within grace period) then show this warning banner, but continue to work.
		// in Calico Enterprise v2.1, grace period is infinite.
		licResp.Warning = "[WARNING] Your license has expired. Please update your license to restore normal operations. Contact Tigera support or email licensing@tigera.io"
		writeResponse(w, licResp)
		return
	}

	licResp.IsValid = true
	writeResponse(w, licResp)
}

func writeResponse(w http.ResponseWriter, licResp licenseResponse) {
	js, err := json.MarshalIndent(licResp, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(js)
	_, _ = w.Write([]byte{'\n'})
}
