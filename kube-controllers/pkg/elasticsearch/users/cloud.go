// Copyright (c) 2021 Tigera, Inc. All rights reserved.

//go:build tesla

package users

import (
	"fmt"
	"os"

	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
)

var tenantID = os.Getenv("TENANT_ID")

func indexPattern(prefix, cluster, suffix string) string {
	if tenantID != "" {
		return fmt.Sprintf("%s.%s.%s%s", prefix, tenantID, cluster, suffix)
	}

	return eeIndexPattern(prefix, cluster, suffix)
}

func formatRoleName(name, cluster string) string {
	if tenantID != "" {
		if cluster == "*" {
			return fmt.Sprintf("%s_%s", name, tenantID)
		}

		return fmt.Sprintf("%s_%s_%s", name, tenantID, cluster)
	}

	return eeFormatRoleName(name, cluster)
}

func formatName(name ElasticsearchUserName, clusterName string, management, secureSuffix bool) string {
	if tenantID != "" {
		var formattedName string
		if management {
			formattedName = string(name)
		} else {
			formattedName = fmt.Sprintf("%s-%s", string(name), clusterName)
		}
		if secureSuffix {
			formattedName = fmt.Sprintf("%s-%s-%s", formattedName, tenantID, ElasticsearchSecureUserSuffix)
		}
		return formattedName
	}

	return eeFormatName(name, clusterName, management, secureSuffix)
}

func GetGlobalAuthorizationRoles() []elasticsearch.Role {
	// For internal ES clusters the kibana role uses the default space
	space := "space:default"
	name := ElasticsearchRoleNameKibanaViewer
	if tenantID != "" {
		// For external ES clusters the kibana role uses the tenant specific space
		space = fmt.Sprintf("space:%s", tenantID)
		name = fmt.Sprintf("%s_%s", ElasticsearchRoleNameKibanaViewer, tenantID)
	}
	return []elasticsearch.Role{{
		Name: name,
		Definition: &elasticsearch.RoleDefinition{
			Indices: []elasticsearch.RoleIndex{},
			Applications: []elasticsearch.Application{{
				Application: "kibana-.kibana",
				Privileges: []string{
					"feature_discover.all",
					"feature_visualize.all",
					"feature_dashboard.all",
					"feature_dev_tools.all",
					"feature_savedObjectsManagement.all",
					"feature_savedObjectsTagging.all",
				},
				Resources: []string{space},
			}},
		},
	}}
}
