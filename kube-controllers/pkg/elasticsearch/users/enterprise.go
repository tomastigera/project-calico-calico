// Copyright (c) 2021 Tigera, Inc. All rights reserved.

//go:build !tesla

package users

import (
	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
)

func indexPattern(prefix, cluster, suffix string) string {
	return eeIndexPattern(prefix, cluster, suffix)
}

func formatRoleName(name, cluster string) string {
	return eeFormatRoleName(name, cluster)
}

func formatName(name ElasticsearchUserName, clusterName string, management, secureSuffix bool) string {
	return eeFormatName(name, clusterName, management, secureSuffix)
}

func GetGlobalAuthorizationRoles() []elasticsearch.Role {
	return eeGetGlobalAuthorizationRoles()
}
