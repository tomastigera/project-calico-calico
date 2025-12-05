// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package model

import (
	"fmt"
	"reflect"
)

//TODO(dimitrin): This definition is being used in firewall-integration. Once the Key interface is
// made public consider moving to firewall-integration project.

const PanoramaObjectKind = "PanoramaObjectKind"

type PanoramaObjectKey struct {
	Name string `json:"-" validate:"required,name"`
	Kind string `json:"-" validate:"required,name"`
}

func (key PanoramaObjectKey) defaultPath() (string, error) {
	return "", nil
}

func (key PanoramaObjectKey) defaultDeletePath() (string, error) {
	return "", nil
}

func (key PanoramaObjectKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key PanoramaObjectKey) valueType() (reflect.Type, error) {
	return reflect.TypeOf(PanoramaObjectKey{}), nil
}

func (key PanoramaObjectKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[PanoramaObjectKey](key, rawData)
}

func (key PanoramaObjectKey) String() string {
	return fmt.Sprintf("Object(name=%s)", key.Name)
}
