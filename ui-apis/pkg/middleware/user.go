// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/ui-apis/pkg/user"
)

type ElasticsearchLicenseType string

const (
	ECKOperatorNamespace    = "tigera-eck-operator"
	ECKLicenseConfigMapName = "elastic-licensing"

	ElasticsearchNamespace = "tigera-elasticsearch"

	ElasticsearchLicenseTypeBasic ElasticsearchLicenseType = "basic"

	OIDCUsersConfigMapName = "tigera-known-oidc-users"
)

type esBasicUserHandler struct {
	k8sClient       datastore.ClientSet
	oidcAuthEnabled bool
	oidcAuthIssuer  string
	esLicenseType   ElasticsearchLicenseType
}

func NewUserHandler(k8sClient datastore.ClientSet, oidcAuthEnabled bool, oidcAuthIssuer, elasticLicenseType string) http.Handler {
	return &esBasicUserHandler{
		k8sClient:       k8sClient,
		oidcAuthEnabled: oidcAuthEnabled,
		oidcAuthIssuer:  oidcAuthIssuer,
		esLicenseType:   ElasticsearchLicenseType(elasticLicenseType),
	}
}

// ServeHTTP stores the OIDC user information in OIDCUsersConfigMapName configmap,
// if the request is authenticated by dex, and Elasticsearch uses basic license,
// else return 200 OK.
func (handler *esBasicUserHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Invalid http method", http.StatusMethodNotAllowed)
		return
	}

	log.WithFields(log.Fields{
		"OIDC Auth Enabled":     handler.oidcAuthEnabled,
		"OIDC Auth Issuer":      handler.oidcAuthIssuer,
		"Elasticsearch License": handler.esLicenseType,
	}).Debug("ServeHTTP called")

	ctx := context.Background()
	userInfo, ok := request.UserFrom(req.Context())
	if !ok {
		log.Error("failed to get userInfo from http request")
		http.Error(w, "Failed to get userInfo from http request", http.StatusInternalServerError)
		return
	}

	oidcUser, err := user.OIDCUserFromUserInfo(userInfo)
	if err != nil {
		log.WithError(err).Debug("failed to get OIDC user information")
		w.WriteHeader(http.StatusOK)
		return
	}

	if handler.oidcAuthEnabled && handler.esLicenseType == ElasticsearchLicenseTypeBasic && oidcUser.Issuer == handler.oidcAuthIssuer {
		if err := handler.addOIDCUserToConfigMap(ctx, oidcUser); err != nil {
			log.WithError(err).Debug("failed to add user to ConfigMap ", OIDCUsersConfigMapName)
		}
	}

	w.WriteHeader(http.StatusOK)
}

// addOIDCUserToConfigMap adds/updates a map into the data of OIDCUsersConfigMapName,
// where map key is the subject claim in JWT, this is a unique identifier within the Issuer
// and value contains username and all groups that the user belongs to
func (handler *esBasicUserHandler) addOIDCUserToConfigMap(ctx context.Context, oidcUser *user.OIDCUser) error {
	userGroupsStr, err := oidcUser.ToStr()
	if err != nil {
		return err
	}

	payload := map[string]any{
		"data": map[string]string{
			oidcUser.Base64EncodedSubjectID(): userGroupsStr,
		},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = handler.k8sClient.CoreV1().ConfigMaps(ElasticsearchNamespace).
		Patch(ctx, OIDCUsersConfigMapName, types.MergePatchType, payloadBytes, metav1.PatchOptions{})
	if err != nil {
		return err
	}
	return nil
}
