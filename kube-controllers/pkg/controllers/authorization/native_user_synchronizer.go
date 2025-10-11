// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package authorization

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	retryr "k8s.io/client-go/util/retry"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch/userscache"
	"github.com/projectcalico/calico/kube-controllers/pkg/rbaccache"
	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
)

// nativeUserSynchronizer is an implementation of k8sRBACSynchronizer interface, to keep Elasticsearch native users up-to-date.
type nativeUserSynchronizer struct {
	roleCache    rbaccache.ClusterRoleCache
	userCache    userscache.OIDCUserCache
	k8sCLI       kubernetes.Interface
	esCLI        elasticsearch.Client
	esUserPrefix string
}

func newNativeUserSynchronizer(stop chan struct{}, esCLI elasticsearch.Client, k8sCLI kubernetes.Interface) k8sRBACSynchronizer {
	var clusterRoleCache rbaccache.ClusterRoleCache
	var oidcUserCache userscache.OIDCUserCache
	var err error
	ctx := context.Background()

	log.Debug("Creating ConfigMap and Secret for OIDC Elasticsearch native users.")
	if err := retryUntilExists(func() error { return createOIDCUserConfigMap(context.Background(), k8sCLI) }); err != nil {
		log.WithError(err).Errorf("failed to create %s ConfigMap", resource.OIDCUsersConfigMapName)
		return nil
	}

	if err := retryUntilExists(func() error { return createOIDCUsersEsSecret(context.Background(), k8sCLI) }); err != nil {
		log.WithError(err).Errorf("failed to create %s Secret", resource.OIDCUsersEsSecreteName)
		return nil
	}

	log.Debug("Initializing ClusterRole cache.")
	// Initialize the cache so resync can calculate what Elasticsearch role mappings or native users should be removed and created/overwritten.
	stopped := retry(stop, 5*time.Second, "failed to initialize cache", func() error {
		clusterRoleCache, err = initializeRolesCache(ctx, k8sCLI)
		return err
	})
	if stopped {
		return nil
	}

	log.Debug("Initializing OIDCUserCache cache.")
	stopped = retry(stop, 5*time.Second, "failed to initialize cache", func() error {
		oidcUserCache, err = initializeOIDCUserCache(ctx, k8sCLI)
		return err
	})
	if stopped {
		return nil
	}

	log.Info("Synchronizing Elasticsearch native users")
	return createNativeUserSynchronizer(clusterRoleCache, oidcUserCache, k8sCLI, esCLI)
}

func createNativeUserSynchronizer(roleCache rbaccache.ClusterRoleCache,
	userCache userscache.OIDCUserCache,
	k8sCLI kubernetes.Interface,
	esCLI elasticsearch.Client) k8sRBACSynchronizer {
	prefix := esUserPrefix
	if prefix != "" {
		prefix = strings.TrimSuffix(prefix, "-") + "-"
	}
	return &nativeUserSynchronizer{
		roleCache:    roleCache,
		userCache:    userCache,
		k8sCLI:       k8sCLI,
		esCLI:        esCLI,
		esUserPrefix: prefix,
	}
}

// synchronize updates the cache with changes to k8s resource and also updates affected native users in Elasticsearch.
func (n *nativeUserSynchronizer) synchronize(update resourceUpdate) error {
	var oidcUsersUpdated []string
	switch update.resource.(type) {

	case *rbacv1.ClusterRole:
		clusterRole := update.resource.(*rbacv1.ClusterRole)
		clusterRoleName := update.name
		switch update.typ {
		case resourceUpdated:
			if n.roleCache.AddClusterRole(clusterRole) {
				oidcUsersUpdated = n.getOIDCUsersForClusterRole(clusterRole.Name)
			}
		case resourceDeleted:
			// get list of all the oidc uses affected before they are removed from the rolecache.
			bkpSubjectIDs := n.getOIDCUsersForClusterRole(clusterRoleName)
			if n.roleCache.RemoveClusterRole(clusterRoleName) {
				oidcUsersUpdated = bkpSubjectIDs
			}
		default:
			log.Errorf("unknown resource update type %s", update.typ)
		}

	case *rbacv1.ClusterRoleBinding:
		clusterRoleBinding := update.resource.(*rbacv1.ClusterRoleBinding)
		clusterRoleBindingName := update.name
		switch update.typ {
		case resourceUpdated:
			if n.roleCache.AddClusterRoleBinding(clusterRoleBinding) {
				oidcUsersUpdated = n.getOIDCUsersForClusterRole(clusterRoleBinding.RoleRef.Name)
			}
		case resourceDeleted:
			cachedRole := n.roleCache.ClusterRoleNameForBinding(clusterRoleBindingName)
			if cachedRole == "" {
				log.Errorf("couldn't find ClusterRole for ClusterRoleBinding %s", clusterRoleBindingName)
				return nil
			}
			// get list of all the oidc uses affected before they are removed from the rolecache.
			bkpSubjectIDs := n.getOIDCUsersForClusterRole(cachedRole)
			if n.roleCache.RemoveClusterRoleBinding(clusterRoleBindingName) {
				oidcUsersUpdated = bkpSubjectIDs
			}

		default:
			log.Errorf("unknown resource update type %s", update.typ)
		}

	case *corev1.ConfigMap:
		switch update.typ {
		case resourceUpdated:
			configMap := update.resource.(*corev1.ConfigMap)
			oidcUsers, err := configMapDataToOIDCUsers(configMap.Data)
			if err != nil {
				log.WithError(err).Errorf("error getting OIDC users from ConfigMap")
				return err
			}
			oidcUsersUpdated = n.userCache.UpdateOIDCUsers(oidcUsers)
		case resourceDeleted:
			// If ConfigMap is deleted, clear the user cache and delete the users from elasticsearch,
			// delete the Secret which is no longer valid (this will trigger reconciler also recreate Secret) and re-create ConfigMap.
			oidcUsersUpdated = n.userCache.SubjectIDs()
			n.userCache = userscache.NewOIDCUserCache()

			if err := retryUntilNotFound(func() error { return deleteOIDCUsersEsSecret(context.Background(), n.k8sCLI) }); err != nil {
				return err
			}

			if err := retryUntilExists(func() error { return createOIDCUserConfigMap(context.Background(), n.k8sCLI) }); err != nil {
				return err
			}

		default:
			log.Errorf("unknown resource update type %s", update.typ)
		}

	case *corev1.Secret:
		switch update.typ {
		case resourceDeleted:
			if err := retryUntilExists(func() error { return createOIDCUsersEsSecret(context.Background(), n.k8sCLI) }); err != nil {
				return err
			}

			// resync and generate new passwords based on cached OIDC users
			if err := n.resync(); err != nil {
				log.WithError(err).Errorf("error re-syncing OIDC Elasticsearch users %s", resource.OIDCUsersEsSecreteName)
				return err
			}
		case resourceUpdated:
			log.Debugf("Ignoring updates to Secret %s", resource.OIDCUsersEsSecreteName)
		default:
			log.Errorf("unknown resource update type %s", update.typ)
		}

	default:
		log.Errorf("unknown resource update type %s", update.typ)
	}

	if len(oidcUsersUpdated) != 0 {
		if err := n.synchronizeOIDCUsers(oidcUsersUpdated); err != nil {
			log.WithError(err).Errorf("failed to listenAndSynchronize %#v", oidcUsersUpdated)
			return err
		}
	}
	return nil
}

func (n *nativeUserSynchronizer) getOIDCUsersForClusterRole(clusterRoleName string) []string {
	var oidcSubjectIDs []string
	bindingsAffected := n.roleCache.ClusterRoleBindingsForClusterRole(clusterRoleName)
	for _, binding := range bindingsAffected {
		subjectNames := n.roleCache.SubjectNamesForBinding(binding)
		for _, subjectName := range subjectNames {
			oidcSubjectIDs = append(oidcSubjectIDs, n.userCache.UserOrGroupToSubjectIDs(subjectName)...)
		}
	}
	return oidcSubjectIDs
}

// synchronizeOIDCUsers updates or deletes Elasticsearch native users based on cache.
// If oidc user doesn't exist in the OIDCUserCache, delete the corresponding Elasticsearch native user.
// If oidc user exists in the OIDCUserCache,
//   - Get roles for the user based on the ClusterRoleBindings that the oidc user belongs to and create/update roles for Elasticsearch native user.
//   - If the Elasticsearch native user does not exist, generate password and update Elasticsearch native user and data in k8s Secret.
//   - If the Elasticsearch native user exist and also password for the user exists in the data of k8s Secret, do not update the password.
//   - If the Elasticsearch native user exist and password for the user does not exists in the data of k8s Secret, recreate password and update both Elasticsearch native user and data in k8s Secret.
func (n *nativeUserSynchronizer) synchronizeOIDCUsers(oidcUsersUpdated []string) error {
	var err error
	var updateEsUsers = make(map[string]elasticsearch.User)
	var deleteEsUsers = make(map[string]elasticsearch.User)

	for _, oidcSubjectID := range oidcUsersUpdated {
		esUsername := fmt.Sprintf("%s%s", n.esUserPrefix, oidcSubjectID)
		// if oidcSubjectID is not in cache, add user to deleteEsUsers list
		if !n.userCache.Exists(oidcSubjectID) {
			deleteEsUsers[oidcSubjectID] = elasticsearch.User{Username: esUsername}
			continue
		}

		esUser := elasticsearch.User{Username: esUsername}

		// Password is a mandatory field while creating new elasticsearch native user.
		// If user does not exist in elasticsearch generate and set password, else update the user without changing the password.
		if exists, _ := n.esCLI.UserExists(esUsername); !exists {
			esUser.Password = utils.GeneratePassword(32)
		}

		esUser.Roles = n.getEsRoleForOIDCSubjectID(oidcSubjectID)
		// If role is empty, do not update - as roles is required field in elasticserach.
		if esUser.Roles == nil {
			log.Infof("No roles for user %s, nothing to update", oidcSubjectID)
			// If there are no roles for the user, delete the user from cacahe and elasticsearch.
			if ok := n.userCache.DeleteOIDCUser(oidcSubjectID); !ok {
				// user not in cache. delete from elasticsearch
				log.Debugf("OIDC user %s not in cache", oidcSubjectID)
			}

			deleteEsUsers[oidcSubjectID] = elasticsearch.User{Username: esUsername}
			continue
		}

		updateEsUsers[oidcSubjectID] = esUser
	}

	for _, esUser := range updateEsUsers {
		log.WithField("esUser", esUser).Debug("Updating OIDC user.")
		if err = n.esCLI.UpdateUser(esUser); err != nil {
			return err
		}
	}

	for _, esUser := range deleteEsUsers {
		log.WithField("esUser", esUser).Debug("Deleting OIDC user.")
		if err = n.esCLI.DeleteUser(esUser); err != nil {
			return err
		}
	}

	if len(deleteEsUsers) != 0 || len(updateEsUsers) != 0 {
		err = retryr.RetryOnConflict(retryr.DefaultRetry, func() error {
			return n.setOIDCUsersPassword(context.Background(), updateEsUsers, deleteEsUsers)
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// setOIDCUsersPassword updates and deletes the data in k8s Secret with the given Elasticsearch user password.
// For an existing Elasticsearch user,
//   - If password is not available in the data of k8s Secret, generate password and update both the Elasticsearch native user and data of k8s Secret
//   - Else do noting [use existing password].
//
// For new Elasticsearch user, add/update the password in the data of k8s Secret.
func (n *nativeUserSynchronizer) setOIDCUsersPassword(ctx context.Context, updateEsUsers map[string]elasticsearch.User, deleteEsUsers map[string]elasticsearch.User) error {
	secret, err := n.k8sCLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Get(ctx, resource.OIDCUsersEsSecreteName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) && len(updateEsUsers) == 0 {
			// nothing to delete or update
			return nil
		}
		return err
	}
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	for subjectID, esUser := range updateEsUsers {
		if esUser.Password != "" {
			secret.Data[subjectID] = []byte(esUser.Password)
		} else if _, ok := secret.Data[subjectID]; !ok {
			esUser.Password = utils.GeneratePassword(32)
			if err := n.esCLI.SetUserPassword(esUser); err != nil {
				return err
			}
			secret.Data[subjectID] = []byte(esUser.Password)
		}
	}
	for subjectID := range deleteEsUsers {
		delete(secret.Data, subjectID)
	}
	_, err = n.k8sCLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

// getEsRoleForOIDCSubjectID retrieves list of elasticsearch roles for the give oidcSubjectID, by getting
// a list of username and group for the oidc user from OIDCUserCache, and then getting
// ClusterRoles that are linked to these username and groups from ClusterRoleCache.
func (n *nativeUserSynchronizer) getEsRoleForOIDCSubjectID(oidcSubjectID string) []elasticsearch.Role {
	var rolesStr []string
	var esRoles []elasticsearch.Role
	esRolesMap := make(map[string]elasticsearch.Role)

	// Get list of username and group for the oidc user, then get ClusterRoles that are linked to these username and groups.
	userOrGroups := n.userCache.SubjectIDToUserOrGroups(oidcSubjectID)
	for _, userOrGroup := range userOrGroups {
		roles := n.roleCache.ClusterRoleNamesForSubjectName(userOrGroup)
		for _, clusterRoleName := range roles {
			rules := n.roleCache.ClusterRoleRules(clusterRoleName)
			if len(rules) > 0 {
				rolesStr = append(rolesStr, rulesToElasticsearchRoles(rules...)...)
			}
		}
	}

	// Remove duplicate Roles.
	for _, role := range rolesStr {
		esRolesMap[role] = elasticsearch.Role{Name: role}
	}
	for _, role := range esRolesMap {
		esRoles = append(esRoles, role)
	}
	return esRoles
}
