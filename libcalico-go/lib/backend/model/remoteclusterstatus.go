// Copyright (c) 2018,2020 Tigera, Inc. All rights reserved.

package model

import (
	"fmt"
	"reflect"
	"regexp"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var (
	matchRemoteClusterStatus = regexp.MustCompile("^/?calico/felix/v1/remotecluster/([^/]+)$")
	typeRemoteClusterStatus  = reflect.TypeFor[RemoteClusterStatus]()
)

// The RemoteClusterStatus is an ephemeral type that is returned by the Felix syncer. It is used to indicate
// the current status of the RemoteCluster connection. If a RemoteClusterConfiguration resource is deleted,
// the Felix syncer will return a deletion event for the RemoteClusterStatus.

type RemoteClusterStatusKey struct {
	Name string `json:"-" validate:"required,name"`
}

func (key RemoteClusterStatusKey) parseValue(rawData []byte) (any, error) {
	return parseJSONPointer[RemoteClusterStatus](key, rawData)
}

func (key RemoteClusterStatusKey) defaultPath() (string, error) {
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}

	// RemoteClusterStatusKey's default path is used by typha, to filter out remotecluster
	// messages. Actually Felix isn't interested in RemoteClusterStatus messages.
	// Hence any changes in default path must reflect in typha as well.
	e := fmt.Sprintf("/calico/felix/v1/remotecluster/%s", key.Name)
	return e, nil
}

func (key RemoteClusterStatusKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key RemoteClusterStatusKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key RemoteClusterStatusKey) valueType() (reflect.Type, error) {
	return typeRemoteClusterStatus, nil
}

func (key RemoteClusterStatusKey) String() string {
	return fmt.Sprintf("RemoteClusterStatus(name=%s)", key.Name)
}

type RemoteClusterStatusType int

const (
	RemoteClusterConnecting RemoteClusterStatusType = iota
	RemoteClusterConnectionFailed
	RemoteClusterResyncInProgress
	RemoteClusterInSync
	RemoteClusterConfigChangeRestartRequired
	RemoteClusterConfigIncomplete
)

func (r RemoteClusterStatusType) String() string {
	switch r {
	case RemoteClusterConnecting:
		return "Connecting"
	case RemoteClusterConnectionFailed:
		return "ConnectionFailed"
	case RemoteClusterResyncInProgress:
		return "ResyncInProgress"
	case RemoteClusterInSync:
		return "InSync"
	case RemoteClusterConfigChangeRestartRequired:
		return "ConfigChangeRestartRequired"
	case RemoteClusterConfigIncomplete:
		return "ConfigIncomplete"
	default:
		return "Unknown"
	}
}

type RemoteClusterStatus struct {
	Status RemoteClusterStatusType `json:"status,omitempty" validate:"omitempty"`
	Error  string                  `json:"error,omitempty" validate:"omitempty"`
}
