// Copyright 2019 Tigera Inc. All rights reserved.

package spyutil

import (
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

type Call struct {
	Method      string
	GNS         *v3.GlobalNetworkSet
	Name        string
	Value       any
	Version     *int64
	SeqNo       *int64
	PrimaryTerm *int64
}
