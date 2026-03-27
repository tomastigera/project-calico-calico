// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/lma/pkg/api"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

type StagedNetworkPolicy struct {
	Name            string
	Namespace       string
	Uid             string
	ResourceVersion string
}

type BatchStagedActionParams struct {
	StagedNetworkPolicies []StagedNetworkPolicy `json:"stagedNetworkPolicies"`
	StagedAction          string                `json:"stagedAction"`
}

type BatchResponse struct {
	Status int     `json:"status"`
	Error  *string `json:"error"`
}

// BatchStagedActionsHandler returns a handler that updates the stagedActions of a list of staged
// network policy recommendations.
func BatchStagedActionsHandler(auth lmaauth.JWTAuth, clientSetk8sClientFactory lmak8s.ClientSetFactory, k8sClientFactory datastore.ClusterCtxK8sClientFactory) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Check that the request has the appropriate method.
		// TODO(dimitrin): UI only uses POST to set requests containing a body. Once the UI is updated
		// to handle PATCH requests with a body, remove access to POST and only leave PATCH
		if req.Method != http.MethodPost && req.Method != http.MethodPatch {
			msg := fmt.Sprintf("unsupported method type %s, only %s is supported", req.Method, http.MethodPatch)
			createAndReturnError(fmt.Errorf("method: %s is not supported", req.Method), msg, http.StatusMethodNotAllowed, api.PolicyRec, w)

			return
		}
		// Extract the recommendation parameters
		params, err := extractParamsFromRequest(req)
		if err != nil {
			createAndReturnError(err, "failed to extract batch action parameters", http.StatusBadRequest, api.PolicyRec, w)

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

		// Update the spec.stagedAction for every batch item
		var wg sync.WaitGroup
		errs := make(chan error, len(params.StagedNetworkPolicies))
		for _, item := range params.StagedNetworkPolicies {
			snp := &v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:            item.Name,
					Namespace:       item.Namespace,
					ResourceVersion: item.ResourceVersion,
					UID:             types.UID(item.Uid),
				},
			}

			wg.Add(1)
			go patchSNP(req.Context(), clientSet, *snp, params.StagedAction, errs, &wg)
		}
		// Wait for all patch routines to complete
		wg.Wait()

		// Check for errors. Print all errors
		close(errs)
		var builder strings.Builder
		for err := range errs {
			if err != nil {
				// Create a comma separated list of errors
				if builder.Len() > 0 {
					builder.WriteString(", ")
				}
				builder.WriteString(err.Error())
			}
		}

		if builder.Len() > 0 {
			createAndReturnError(errors.New("failed to patch staged network policies"), builder.String(), http.StatusBadRequest, api.PolicyRec, w)

			return
		}

		resp := &BatchResponse{
			Status: http.StatusOK,
		}

		log.Info("Batch recommendations response")
		resultJson, err := json.Marshal(resp)
		if err != nil {
			createAndReturnError(err, "Error marshalling recommendation to JSON",
				http.StatusInternalServerError, api.PolicyRec, w)

			return
		}
		_, err = w.Write(resultJson)
		if err != nil {
			msg := fmt.Sprintf("Error writing JSON recommendation: %v", resp)
			createAndReturnError(err, msg, http.StatusInternalServerError, api.PolicyRec, w)

			return
		}
	})
}

// extractParamsFromRequest extracts the staged action batch operation parameters from an http
// request, or an error if the request body fails while decoding.
func extractParamsFromRequest(req *http.Request) (*BatchStagedActionParams, error) {
	var params BatchStagedActionParams
	err := json.NewDecoder(req.Body).Decode(&params)
	if err != nil {
		log.WithError(err).Error("failed decode the staged action batch parameters parameters")
		return nil, err
	}

	return &params, nil
}

// patchSNP updates the staged network policy stagedAction. Sends an error via channel, if one
// occurs. Errors are logged, not returned if the policy was not found or not owned by the expected
// owner
func patchSNP(ctx context.Context, cs lmak8s.ClientSet, snp v3.StagedNetworkPolicy, stagedAction string, errs chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	var patch map[string]any
	if v3.StagedAction(stagedAction) == v3.StagedActionSet {
		// Once a policy is activated, the PolicyRecommendationScope forfeits ownership by setting
		// the ownerReferences field to nil
		// Patch the spec.stagedAction label to "Set"
		patch = map[string]any{
			"metadata": map[string]any{
				"ownerReferences": nil,
				"labels": map[string]any{
					"projectcalico.org/spec.stagedAction": stagedAction,
				},
			},
			"spec": map[string]any{
				"stagedAction": stagedAction,
			},
		}
	} else if v3.StagedAction(stagedAction) == v3.StagedActionLearn || v3.StagedAction(stagedAction) == v3.StagedActionIgnore {
		// Patch the spec.stagedAction, when the staged action is "Learn" or "Ignore"
		patch = map[string]any{
			"metadata": map[string]any{
				"labels": map[string]any{
					"projectcalico.org/spec.stagedAction": stagedAction,
				},
			},
			"spec": map[string]any{
				"stagedAction": stagedAction,
			},
		}
	} else {
		// Send the error down the channel
		err := fmt.Errorf("unsupported staged action: %s", stagedAction)
		log.WithError(err)
		errs <- err

		return
	}

	patchData, err := json.Marshal(patch)
	if err != nil {
		// Send the error down the channel
		log.WithError(err).Errorf("failed to marshal staged action for stagednetworkpolicy name: %s, in namespace: %s", snp.Name, snp.Namespace)
		errs <- err

		return
	}

	// tigera-manager role must have Resource:stagednetworkpolicies Verb:patch defined
	if _, err = cs.ProjectcalicoV3().StagedNetworkPolicies(snp.Namespace).Patch(ctx, snp.Name, types.MergePatchType, patchData, metav1.PatchOptions{
		TypeMeta: snp.TypeMeta,
	}); err != nil {
		// Send the error down the channel
		log.WithError(err).Errorf("failed update staged network policy: %s, in namespace: %s", snp.Name, snp.Namespace)
		errs <- err
	}
}
