// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.

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

package model

import (
	"fmt"
	"reflect"
	"regexp"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var (
	matchLicenseKey = regexp.MustCompile("^/?calico/v1/licensekey/([^/]+)$")
	typeLicenseKey  = reflect.TypeFor[LicenseKey]()
)

type LicenseKeyKey struct {
	Name string `json:"-" validate:"required,name"`
}

func (key LicenseKeyKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[LicenseKey](key, rawData)
}

func (key LicenseKeyKey) defaultPath() (string, error) {
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	e := fmt.Sprintf("/calico/v1/licensekey/%s", escapeName(key.Name))
	return e, nil
}

func (key LicenseKeyKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key LicenseKeyKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key LicenseKeyKey) valueType() (reflect.Type, error) {
	return typeLicenseKey, nil
}

func (key LicenseKeyKey) String() string {
	return fmt.Sprintf("LicenseKey(name=%s)", key.Name)
}

type LicenseKeyListOptions struct {
	Name string
}

func (options LicenseKeyListOptions) defaultPathRoot() string {
	k := "/calico/v1/licensekey"
	if options.Name == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s", escapeName(options.Name))
	return k
}

func (options LicenseKeyListOptions) KeyFromDefaultPath(path string) Key {
	// The only supported license key name is default.
	log.Debugf("Get LicenseKey key from %s", path)
	return LicenseKeyKey{Name: "default"}
}

type LicenseKey struct {
	Token       string `json:"token"`
	Certificate string `json:"certificate,omitempty" validate:"omitempty"`
}
