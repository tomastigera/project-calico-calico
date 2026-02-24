// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/lma/pkg/api"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

const recommendationsTier = "namespace-isolation"

type PagedRecommendationParams struct {
	StagedAction string `json:"stagedAction"`
	Page         int    `json:"page"`
	MaxItems     int    `json:"maxItems"`
}

type Recommendations struct {
	Count                 int                      `json:"count"`
	StagedNetworkPolicies []v3.StagedNetworkPolicy `json:"stagedNetworkPolicies"`
}

// PagedRecommendationsHandler returns a handler that updates the gets the list of policy
// recommendations as a paged response.
func PagedRecommendationsHandler(auth lmaauth.JWTAuth, clientSetk8sClientFactory lmak8s.ClientSetFactory, k8sClientFactory datastore.ClusterCtxK8sClientFactory) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Check that the request has the appropriate method.
		// TODO(dimitri): Update to allow only GET. The UI currently uses a POST call to retrieve the
		// paged recommendations response. This method should only allow for a GET, once the UI has
		// been updated.
		if req.Method != http.MethodGet && req.Method != http.MethodPost {
			msg := fmt.Sprintf("unsupported method type %s, only %s is supported", req.Method, http.MethodPost)
			createAndReturnError(fmt.Errorf("method: %s is not supported", req.Method), msg, http.StatusMethodNotAllowed, api.PolicyRec, w)

			return
		}

		// Extract the recommendation parameters
		params, err := extractPagedRecommendationParamsFromRequest(req)
		if err != nil {
			createAndReturnError(err, err.Error(), http.StatusBadRequest, api.PolicyRec, w)

			return
		}
		// Get the cluster id, used for getting the cluster client set
		clusterID := MaybeParseClusterNameFromRequest(req)
		log.WithField("cluster", clusterID).Debug("Cluster ID from request")
		// Authenticate user
		usr, stat, err := auth.Authenticate(req)
		if err != nil {
			// err http status one of: 401, 500
			msg := fmt.Sprintf("%d error authenticating user", stat)
			createAndReturnError(err, msg, stat, api.PolicyRec, w)

			return
		}
		// Get the k8s client set for this cluster
		clientSet, err := clientSetk8sClientFactory.NewClientSetForUser(usr, clusterID)
		if err != nil {
			msg := fmt.Sprintf("failed to get the k8s client set for usr: %s and cluster: %s", usr.GetName(), clusterID)
			createAndReturnError(err, msg, http.StatusInternalServerError, api.PolicyRec, w)

			return
		}

		// Get the policies as a paged response
		policies, count, err := getStageNetworkPoliciesPage(
			req.Context(), clientSet, params.StagedAction, params.MaxItems, params.Page)
		if err != nil {
			msg := "failed to get staged network policies"
			createAndReturnError(err, msg, http.StatusBadRequest, api.PolicyRec, w)

			return
		}

		recommendations := &Recommendations{
			Count:                 count,
			StagedNetworkPolicies: policies,
		}

		log.WithField("recommendation", recommendations).Debug("Policy recommendation response")
		resultJson, err := json.Marshal(recommendations)
		if err != nil {
			createAndReturnError(err, "Error marshalling recommendation to JSON",
				http.StatusInternalServerError, api.PolicyRec, w)
			return
		}
		_, err = w.Write(resultJson)
		if err != nil {
			msg := fmt.Sprintf("Error writing JSON recommendation: %v", recommendations)
			createAndReturnError(err, msg, http.StatusInternalServerError, api.PolicyRec, w)
			return
		}
	})
}

// extractPagedRecommendationParamsFromRequest extracts the staged action batch operation parameters from an http
// request, or an error if the request body fails while decoding.
func extractPagedRecommendationParamsFromRequest(req *http.Request) (*PagedRecommendationParams, error) {
	var params PagedRecommendationParams
	err := json.NewDecoder(req.Body).Decode(&params)
	if err != nil {
		log.WithError(err).Error("failed decode the staged action batch parameters parameters")

		return nil, err
	}

	ok, err := validatePagedRecommendationParams(params)
	if !ok {
		return nil, err
	}

	return &params, nil
}

// getStageNetworkPoliciesPage returns a list of staged network policies as a paged response, and
// the total count of items.
func getStageNetworkPoliciesPage(
	ctx context.Context, cs lmak8s.ClientSet, stagedAction string, maxItems, page int,
) ([]v3.StagedNetworkPolicy, int, error) {
	if maxItems < 0 {
		err := fmt.Errorf("maxItems: %d must be '>=0'", maxItems)
		log.WithError(err)

		return nil, 0, err
	} else if page < 0 {
		err := fmt.Errorf("index out of bounds, page: %d must be '>=0'", page)
		log.WithError(err)

		return nil, 0, err
	}

	tierLabelSelector := fmt.Sprintf("projectcalico.org/tier=%s", recommendationsTier)
	ownerReferenceKindLabelSelector := "projectcalico.org/ownerReference.kind=PolicyRecommendationScope"
	stagedActionLabelSelector := fmt.Sprintf("projectcalico.org/spec.stagedAction=%s", stagedAction)
	labelSelector := strings.Join([]string{tierLabelSelector, ownerReferenceKindLabelSelector, stagedActionLabelSelector}, ",")

	policies, err := cs.ProjectcalicoV3().StagedNetworkPolicies("").List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, 0, err
	}

	pagedPolicies := policies.Items
	sort.SliceStable(pagedPolicies, func(i, j int) bool {
		// Sort by namespace
		if pagedPolicies[i].Namespace != pagedPolicies[j].Namespace {
			return pagedPolicies[i].Namespace < pagedPolicies[j].Namespace
		}
		// If namespace is same, sort by name
		return pagedPolicies[i].Name < pagedPolicies[j].Name
	})

	count := len(pagedPolicies)

	if maxItems == 0 {
		// Return the entire list if the max items is equal to 0
		return policies.Items, count, nil
	}

	startIndex := page * maxItems
	endIndex := min(startIndex+maxItems, count)

	if startIndex >= count {
		return []v3.StagedNetworkPolicy{}, count, nil
	}

	return pagedPolicies[startIndex:endIndex], count, nil
}

// validatePagedRecommendationParams validates the staged action, page and maxItems parameters.
func validatePagedRecommendationParams(params PagedRecommendationParams) (bool, error) {
	if params.StagedAction != string(v3.StagedActionSet) &&
		params.StagedAction != string(v3.StagedActionLearn) &&
		params.StagedAction != string(v3.StagedActionIgnore) {
		err := fmt.Errorf("unsupported action: %s", params.StagedAction)
		log.WithError(err)

		return false, err
	}

	if params.Page < 0 || params.MaxItems < 0 {
		err := fmt.Errorf("invalid page: %d or max items: %d value. Values must '>=0'", params.Page, params.MaxItems)
		log.WithError(err)

		return false, err
	}

	return true, nil
}
