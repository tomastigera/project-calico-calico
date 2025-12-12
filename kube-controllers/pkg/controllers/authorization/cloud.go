// Copyright (c) 2024 Tigera, Inc. All rights reserved.

//go:build tesla

package authorization

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
	esusers "github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch/users"
)

var (
	tenantID = os.Getenv("TENANT_ID")

	// esUserPrefix is prefixed to usernames in ES for OIDC/IdP users that we create. A prefix can be used to make sure
	// a user in es does not collide with a user created by another (management) cluster.
	esUserPrefix = os.Getenv("TENANT_ID")
)

var resourceNameToElasticsearchRole = map[string]string{
	"flows":      formatRoleName(esusers.ElasticsearchRoleNameFlowsViewer),
	"audit*":     formatRoleName(esusers.ElasticsearchRoleNameAuditViewer),
	"audit_ee":   formatRoleName(esusers.ElasticsearchRoleNameAuditEEViewer),
	"audit_kube": formatRoleName(esusers.ElasticsearchRoleNameAuditKubeViewer),
	"events":     formatRoleName(esusers.ElasticsearchRoleNameEventsViewer),
	"dns":        formatRoleName(esusers.ElasticsearchRoleNameDNSViewer),
	"l7":         formatRoleName(esusers.ElasticsearchRoleNameL7Viewer),
	"waf":        formatRoleName(esusers.ElasticsearchRoleNameWafViewer),
	"runtime":    formatRoleName(esusers.ElasticsearchRoleNameRuntimeViewer),
}

var resourceNameToGlobalElasticsearchRoles = map[string]string{
	"kibana_login":            formatRoleName(esusers.ElasticsearchRoleNameKibanaViewer),
	"elasticsearch_superuser": formatRoleName(esusers.ElasticsearchRoleNameKibanaViewer),
	"kibana_admin":            formatRoleName(esusers.ElasticsearchRoleNameKibanaAdmin),
}

func formatRoleName(name string) string {
	if tenantID != "" {
		return fmt.Sprintf("%s_%s", name, tenantID)
	} else {
		return name
	}
}

// resync removes all elasticsearch native users that don't have an entry in user cache
// and also for every oidc user in cache it creates/overwrites corresponding elasticsearch native users.
// This is the Cloud/Tesla variant of this function which ignores any users that do not have the tenantID suffix
// in their role names to avoid overwriting another tenants oidc users.
func (n *nativeUserSynchronizer) resync() error {
	if tenantID != "" {
		users, err := n.esCLI.GetUsers()
		if err != nil {
			return err
		}

		for _, user := range users {
			rolesNames := user.RoleNames()
			// Exclude Tigera's system users from deletion.
			// Skip deleting this user if it does not contain roles specific to this tenant.
			if user.FullName == esusers.SystemUserFullName || !strings.HasSuffix(rolesNames[0], tenantID) {
				continue
			}
			subjectID := strings.TrimPrefix(user.Username, n.esUserPrefix)
			if !n.userCache.Exists(subjectID) {
				if err := n.esCLI.DeleteUser(elasticsearch.User{Username: user.Username}); err != nil {
					return err
				}
			}
		}

		subjects := n.userCache.SubjectIDs()
		return n.synchronizeOIDCUsers(subjects)
	}

	return n.eeResync()
}
