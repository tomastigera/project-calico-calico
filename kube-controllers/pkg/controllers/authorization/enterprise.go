// Copyright (c) 2024 Tigera, Inc. All rights reserved.

//go:build !tesla

package authorization

import (
	esusers "github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch/users"
)

// esUserPrefix is prefixed to usernames in ES for OIDC/IdP users that we create. A prefix can be used to make sure
// a user in es does not collide with a user created by another (management) cluster.
var esUserPrefix string

var resourceNameToElasticsearchRole = map[string]string{
	"flows":      esusers.ElasticsearchRoleNameFlowsViewer,
	"audit*":     esusers.ElasticsearchRoleNameAuditViewer,
	"audit_ee":   esusers.ElasticsearchRoleNameAuditEEViewer,
	"audit_kube": esusers.ElasticsearchRoleNameAuditKubeViewer,
	"events":     esusers.ElasticsearchRoleNameEventsViewer,
	"dns":        esusers.ElasticsearchRoleNameDNSViewer,
	"l7":         esusers.ElasticsearchRoleNameL7Viewer,
	"waf":        esusers.ElasticsearchRoleNameWafViewer,
	"runtime":    esusers.ElasticsearchRoleNameRuntimeViewer,
}

var resourceNameToGlobalElasticsearchRoles = map[string]string{
	"kibana_login":            esusers.ElasticsearchRoleNameKibanaViewer,
	"elasticsearch_superuser": esusers.ElasticsearchRoleNameSuperUser,
	"kibana_admin":            esusers.ElasticsearchRoleNameKibanaAdmin,
}

// resync removes all elasticsearch native users with prefix `tigera-k8s` that doesn't have an entry in user cache
// and also for every oidc user in cache it creates/overwrites corresponding elasticsearch native users.
func (n *nativeUserSynchronizer) resync() error {
	return n.eeResync()
}
