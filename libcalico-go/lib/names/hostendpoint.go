// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package names

type HostEndpointType string

const (
	HostEndpointTypeClusterNode    HostEndpointType = "clusternode"
	HostEndpointTypeNonClusterHost HostEndpointType = "nonclusterhost"

	HostEndpointTypeLabelKey = "hostendpoint.projectcalico.org/type"
)
