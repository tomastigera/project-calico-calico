// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package event

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware/search"
)

const (
	destInfoSelector = "type IN {'waf'}"
)

// EventStatisticsHandler handles event statistics requests.
func EventStatisticsHandler(k8sClient datastore.ClientSet, lsclient client.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For the most part, this handler is a pass through to linseed.
		// It takes in EventStatisticsParams as input and returns EventStatistics as result.
		// For most fields, linseed does the heavy lifting.
		// In a few cases this frontend API adds some extra logic that neither belongs to linseed or the UI.
		// Additional logic includes:
		// - Ignore events that match any AlertException
		// - Provide a "namespace" field value that corresponds to the Namespace column in the security events table.
		//   For most events, Namespace correspond to SourceNamespace. Except for WAF where DestNamespace is used.
		// - Provide a "mitre_technique" field value that adds a nice display name for MITRE techniques
		//   along with a corresponding URL.
		// This additional logic, handled in ui-apis, is captured in esParams.
		// The linseed-compatible logic is captured in lsParams.
		esParams, lsParams, err := parseEventStatisticsRequest(w, r)
		if err != nil {
			httputils.EncodeError(w, err)
			return
		}

		// Create a context with timeout to ensure we don't block for too long.
		ctx, cancelWithTimeout := context.WithTimeout(r.Context(), middleware.DefaultRequestTimeout)
		defer cancelWithTimeout()

		if k8sClient == nil {
			httputils.EncodeError(w, errors.New("k8sClient is nil"))
			return
		}

		// For security event search requests, we need to modify the Elastic query
		// to exclude events which match exceptions created by users.
		eventExceptionList, err := k8sClient.AlertExceptions().List(ctx, metav1.ListOptions{})
		if err != nil {
			logrus.WithError(err).Error("failed to list alert exceptions")
			httputils.EncodeError(w, err)
			return
		}
		combinedSelector := search.UpdateSelectorWithAlertExceptions(eventExceptionList, esParams.Selector)

		esParams.Selector = combinedSelector
		lsParams.Selector = combinedSelector

		// Get cluster name
		clusterName := middleware.MaybeParseClusterNameFromRequest(r)

		if esParams.FieldValues != nil {
			// Deal with MitreTechnique logic...
			if esParams.FieldValues.MitreTechniqueValues != nil {
				if lsParams.FieldValues == nil {
					lsParams.FieldValues = &lapi.FieldValuesParam{}
				}
				if lsParams.FieldValues.MitreIDsValues == nil {
					lsParams.FieldValues.MitreIDsValues = esParams.FieldValues.MitreTechniqueValues
				} else {
					// Just in case we have {count: false, group_by_severity: true}
					lsParams.FieldValues.MitreIDsValues.Count = esParams.FieldValues.MitreTechniqueValues.Count
					// Needs to be true if either one is true
					lsParams.FieldValues.MitreIDsValues.GroupBySeverity = lsParams.FieldValues.MitreIDsValues.GroupBySeverity || esParams.FieldValues.MitreTechniqueValues.Count
				}
			}
		}

		resp, err := lsclient.Events(clusterName).Statistics(ctx, *lsParams)

		if err != nil {
			httputils.EncodeError(w, err)
			return
		}

		esResp := v1.EventStatistics{}
		if resp.FieldValues != nil {
			esResp.FieldValues = &v1.FieldValues{
				FieldValues: resp.FieldValues,
			}
		}
		if resp.SeverityHistograms != nil {
			esResp.SeverityHistograms = resp.SeverityHistograms
		}

		// We have the params compatible with Linseed. In addition, we may have more data
		// we need to process to deal with namespaces for example.
		// If we do, we will need to setup multiple queries... If not stick with the one query.

		// Perform statistics request
		if esParams.FieldValues != nil {
			if esParams.FieldValues.MitreTechniqueValues != nil {
				// We know from previous logic that mitre_ids were requested in the linseed request.
				// We now need to update MitreTechniqueValues and optionally remove by_severity
				// values from mitre_ids if they were not originally requested.
				esResp.FieldValues.MitreTechniqueValues = []v1.MitreTechniqueValue{}
				for _, value := range resp.FieldValues.MitreIDsValues {
					mitreTechniqueValue := v1.MitreTechniqueValue{
						FieldValue: value,
					}
					mitreTechnique, err := GetMitreTechnique(value.Value)
					if err != nil {
						// We log the error but continue without the added metadata
						logrus.WithError(err).Error("Unknown MITRE ID")
					} else {
						mitreTechniqueValue.Value = mitreTechnique.DisplayName
						mitreTechniqueValue.Url = mitreTechnique.Url
					}
					if !esParams.FieldValues.MitreTechniqueValues.GroupBySeverity {
						mitreTechniqueValue.BySeverity = nil
					}
					esResp.FieldValues.MitreTechniqueValues = append(esResp.FieldValues.MitreTechniqueValues, mitreTechniqueValue)
					if esParams.FieldValues.MitreIDsValues == nil || !esParams.FieldValues.MitreIDsValues.Count {
						resp.FieldValues.MitreIDsValues = nil
					}
				}
			}
			if esParams.FieldValues.NamespaceValues != nil {
				// Get the data we need for events using source_namespace as namespace
				srcQueryParams := lapi.EventStatisticsParams{
					EventParams: lsParams.EventParams,
					FieldValues: &lapi.FieldValuesParam{
						SourceNamespaceValues: esParams.FieldValues.NamespaceValues,
					},
				}
				srcQueryParams.Selector = fmt.Sprintf("(%s) AND NOT %s", srcQueryParams.Selector, destInfoSelector)

				srcResp, err := lsclient.Events(clusterName).Statistics(ctx, srcQueryParams)

				if err != nil {
					httputils.EncodeError(w, err)
					return
				}

				// Can be empty if params is only requesting namespace
				if esResp.FieldValues == nil {
					esResp.FieldValues = &v1.FieldValues{}
				}

				// Initially empty, so use source_namespace values as a base
				esResp.FieldValues.NamespaceValues = srcResp.FieldValues.SourceNamespaceValues

				// Get the data we need for events using dest_namespace as namespace
				destQueryParams := lapi.EventStatisticsParams{
					EventParams: lsParams.EventParams,
					FieldValues: &lapi.FieldValuesParam{
						DestNamespaceValues: esParams.FieldValues.NamespaceValues,
					},
				}
				destQueryParams.Selector = fmt.Sprintf("(%s) AND %s", destQueryParams.Selector, destInfoSelector)

				destResp, err := lsclient.Events(clusterName).Statistics(ctx, destQueryParams)

				if err != nil {
					httputils.EncodeError(w, err)
					return
				}

				esResp.FieldValues.NamespaceValues = mergeValues(esResp.FieldValues.NamespaceValues, destResp.FieldValues.DestNamespaceValues) //, isSameFieldValue, updateFieldValue)
			}
		}

		httputils.Encode(w, esResp)
	})
}

// parseEventStatisticsRequest extracts statistics parameters from the request body and validates them.
// We return 2 param objects:
//   - esParams that captures all ui-apis compatible parameters
//   - lsParams that captures a subset of those parameters in order to be compatible with linseed
func parseEventStatisticsRequest(w http.ResponseWriter, r *http.Request) (*v1.EventStatisticsParams, *lapi.EventStatisticsParams, error) {
	// events handler
	if r.Method != http.MethodPost {
		logrus.WithError(middleware.ErrInvalidMethod).Infof("Invalid http method %s for /events/statistics.", r.Method)

		return nil, nil, &httputils.HttpStatusError{
			Status: http.StatusMethodNotAllowed,
			Msg:    middleware.ErrInvalidMethod.Error(),
			Err:    middleware.ErrInvalidMethod,
		}
	}

	// Decode the http request body into the struct.
	var esParams v1.EventStatisticsParams
	var lsParams lapi.EventStatisticsParams

	if err := httputils.Decode(w, r, &esParams); err != nil {
		var mr *httputils.HttpStatusError
		if errors.As(err, &mr) {
			logrus.WithError(mr.Err).Info(mr.Msg)
			return nil, nil, mr
		} else {
			logrus.WithError(mr.Err).Info("Error validating event statistics requests (ui-apis API format).")
			return nil, nil, &httputils.HttpStatusError{
				Status: http.StatusBadRequest,
				Msg:    http.StatusText(http.StatusInternalServerError),
				Err:    err,
			}
		}
	}

	if err := httputils.DecodeIgnoreUnknownFields(w, r, &lsParams); err != nil {
		var mr *httputils.HttpStatusError
		if errors.As(err, &mr) {
			logrus.WithError(mr.Err).Info(mr.Msg)
			return nil, nil, mr
		} else {
			logrus.WithError(mr.Err).Info("Error validating event statistics requests (linseed API format).")
			return nil, nil, &httputils.HttpStatusError{
				Status: http.StatusBadRequest,
				Msg:    http.StatusText(http.StatusInternalServerError),
				Err:    err,
			}
		}
	}

	return &esParams, &lsParams, nil
}

// mergeValues takes 2 list of values (FieldValues or SeverityValues)
// and combines them to make sure all the values are present and the
// number of occurrences for each value (Count property) is also combines.
// When applicable, severity values in BySeverity field are also combined similarly.
// isSameFn and mergeFn are required to allow a generic implementation in golang.
// isSameFn compares 2 field values and returns true if their Value property is equal.
// mergeFn encapsulates the type-specific logic of how 2 file values should be merged.
func mergeValues(l1, l2 []lapi.FieldValue) []lapi.FieldValue {
	combinedList := l1
	for _, currentItem := range l2 {
		existingItemIndex := indexOf[lapi.FieldValue](combinedList, func(item lapi.FieldValue) bool { return item.Value == currentItem.Value })
		if existingItemIndex != -1 {
			existingItem := combinedList[existingItemIndex]
			existingItem.Count += currentItem.Count
			existingItem.BySeverity = mergeSeverityValues(existingItem.BySeverity, currentItem.BySeverity)
			combinedList[existingItemIndex] = existingItem
		} else {
			combinedList = append(combinedList, currentItem)
		}
	}
	return combinedList
}

func mergeSeverityValues(l1, l2 []lapi.SeverityValue) []lapi.SeverityValue {
	combinedList := l1
	for _, currentItem := range l2 {
		newItem := currentItem
		existingItemIndex := indexOf[lapi.SeverityValue](combinedList, func(item lapi.SeverityValue) bool { return item.Value == currentItem.Value })
		if existingItemIndex != -1 {
			newItem = combinedList[existingItemIndex]
			newItem.Count += currentItem.Count
			combinedList[existingItemIndex] = newItem
		} else {
			combinedList = append(combinedList, newItem)
		}
	}
	return combinedList
}

func indexOf[T any](l []T, fn func(T) bool) int {
	for i, v := range l {
		if fn(v) {
			return i
		}
	}
	return -1
}
