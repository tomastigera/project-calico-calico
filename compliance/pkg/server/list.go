package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/compliance/pkg/api"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

// handleListReports returns a json list of the reports available to the credentials
func (s *server) handleListReports(response http.ResponseWriter, request *http.Request) {
	clusterID := request.Header.Get(lmak8s.XClusterIDHeader)
	if clusterID == "" {
		clusterID = lmak8s.DefaultCluster
	}

	log.Infof("Request url %v and x-cluster-id: %v ", request.URL, clusterID)

	authorizer, err := s.csFactory.RBACAuthorizerForCluster(clusterID)
	if err != nil {
		log.Errorf("Failed to create authorizer: %s", err.Error())
		http.Error(response, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Create an RBAC helper for determining which reports we should include in the returned list.
	rbacHelper := NewReportRbacHelper(authorizer, request)

	// First check if the user is able to List reports.
	if canList, err := rbacHelper.CanListReports(); err != nil {
		log.WithError(err).Error("Unable to determine access permissions for request")
		http.Error(response, err.Error(), http.StatusServiceUnavailable)
		return
	} else if !canList {
		log.Debug("Requester has insufficient permissions to list reports")
		http.Error(response, "Access denied", http.StatusUnauthorized)
		return
	}

	// Extract the query parameters from the request parameters.
	qparams, err := GetListReportsQueryParams(request.URL.Query())
	if err != nil {
		http.Error(response, fmt.Sprintf("Invalid query parameter: %v", err), http.StatusBadRequest)
	}

	// Initialize the report list to return.
	rl := &ReportList{
		Page:    qparams.Page,
		Reports: []Report{},
	}

	store := s.factory.NewStore(clusterID)

	// Query to determine the set of reportTypeName/reportName that match the filter.
	var filteredReportNameAndType []api.ReportTypeAndName
	reportNameAndTypes, err := store.RetrieveArchivedReportTypeAndNames(request.Context(), *qparams)
	if err != nil {
		log.WithError(err).Error("Unable to determine access permissions for request")
		http.Error(response, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Filter the full set of matching report type and names so that we only include those that the user is able to
	// view.
	for _, r := range reportNameAndTypes {
		log.Debugf("Checking user RBAC for Report Type '%s' and Report '%s'", r.ReportTypeName, r.ReportName)
		if include, err := rbacHelper.CanViewReportSummary(r.ReportName); err != nil {
			log.WithError(err).Error("Unable to determine access permissions for request")
			http.Error(response, err.Error(), http.StatusServiceUnavailable)
			return
		} else if include {
			log.Debug("User is able to list report")
			filteredReportNameAndType = append(filteredReportNameAndType, r)
		}
	}
	if len(filteredReportNameAndType) == 0 {
		// We are not able to view any of the reports, so return an empty response.
		log.Info("User is not able to list any reports matching any of the specified filters")
		writeJSON(response, rl, false)
		return
	}

	// Update the query params to include the filtered set of report name and types.
	qparams.Reports = filteredReportNameAndType

	// Obtain the current set of configured ReportTypes.
	rts, err := s.getReportTypes(clusterID)
	if err != nil {
		log.WithError(err).Error("Unable to query report types")
		http.Error(response, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Pull the report summaries from linseed
	reportSummaries, err := store.RetrieveArchivedReportSummaries(request.Context(), *qparams)
	if err != nil {
		errString := fmt.Sprintf("Unable to list reports: %v", err)
		http.Error(response, errString, http.StatusServiceUnavailable)
		log.WithError(err).Error(errString)
		return
	}

	// Set the number of pages from the linseed query.
	rl.Count = reportSummaries.Count

	// Turn each of the reportSummaries into Report objects that will marshal into a format for the documented API.
	for _, v := range reportSummaries.Reports {
		log.Debugf("Processing report. ReportType: %s, Report: %s", v.ReportTypeName, v.ReportName)

		// If user can list the report then include it in the list. This should not be necessary since we filter out
		// reports we can't view, but better to be safe here.
		if include, err := rbacHelper.CanViewReportSummary(v.ReportName); err != nil {
			log.WithError(err).Error("Unable to determine access permissions for request")
			http.Error(response, err.Error(), http.StatusServiceUnavailable)
			return
		} else if !include {
			log.Errorf("Requester has insufficient permissions to view report, but filter should only include "+
				"viewable reports.  ReportType: %s, Report: %s", v.ReportTypeName, v.ReportName)
			continue
		}

		// Look up the specific report type if it still exists.
		rt := rts[v.ReportTypeName]

		// ReportType is deleted, use ReportTypeSpec in the ReportData.
		if rt == nil {
			// If the report type has been deleted just use the one stored in the ReportData.
			log.Debugf("ReportType (%s) deleted from the configuration, using from ReportData", v.ReportTypeName)
			rt = &v.ReportTypeSpec
		}

		// Convert the JSON string UI summary into an object that we'll embed directly under the UISummary
		// field. To do this unmarshal the rendered string into a generic interface type.
		var uiSummary any
		var formats []Format
		if err = json.Unmarshal([]byte(v.UISummary), &uiSummary); err != nil {
			log.WithError(err).Debug("UI summary is not JSON")
		}

		// If the user can view the report then include the download url and formats.
		var downloadUrl string
		if include, err := rbacHelper.CanViewReport(v.ReportTypeName, v.ReportName); err != nil {
			log.WithError(err).Error("Unable to determine access permissions for request")
			http.Error(response, err.Error(), http.StatusServiceUnavailable)
			return
		} else if include {
			// Build the download url
			downloadUrl = strings.Replace(UrlDownload, QueryReport, v.UID(), 1)

			// Load report formats from download templates in the global report report type.
			for _, dlt := range rt.DownloadTemplates {
				log.Debugf("Including download format: %s", dlt.Name)
				f := Format{
					dlt.Name,
					dlt.Description,
				}
				formats = append(formats, f)
			}
		}

		// Package it up in a report and append to slice.
		r := Report{
			Id:              v.UID(),
			Name:            v.ReportName,
			Type:            v.ReportTypeName,
			StartTime:       v.StartTime,
			EndTime:         v.EndTime,
			UISummary:       uiSummary,
			DownloadURL:     downloadUrl,
			DownloadFormats: formats,
			GenerationTime:  v.GenerationTime,
		}
		rl.Reports = append(rl.Reports, r)
	}

	// Write the response as a JSON encoded blob
	writeJSON(response, rl, false)
}

// GetListReportsQueryParams extracts the query parameters for the report summary list.
func GetListReportsQueryParams(vals url.Values) (*api.ReportQueryParams, error) {
	page, maxItems, err := getPageQueryParams(vals)
	if err != nil {
		return nil, err
	}
	sortBy, err := getSortQueryParams(vals)
	if err != nil {
		return nil, err
	}

	var reports []api.ReportTypeAndName
	rp := getReportsQueryParams(vals)
	if rp != nil {
		reports = []api.ReportTypeAndName{*rp}
	}
	return &api.ReportQueryParams{
		Reports:  reports,
		FromTime: vals.Get(UrlParamFromTime),
		ToTime:   vals.Get(UrlParamToTime),
		Page:     page,
		MaxItems: maxItems,
		SortBy:   sortBy,
	}, nil
}

// getReportsQueryParams extracts the requested report type and report name from the query parameters.
// It returns a pointer to api.ReportTypeAndName by combining the first reportTypeName and first reportName if present.
// If both ReportTypeName and ReportName are empty, it returns nil.
func getReportsQueryParams(vals url.Values) *api.ReportTypeAndName {
	var r api.ReportTypeAndName

	if typeVals, ok := vals[UrlParamReportTypeName]; ok && len(typeVals) > 0 {
		r.ReportTypeName = typeVals[0]
	}
	if nameVals, ok := vals[UrlParamReportName]; ok && len(nameVals) > 0 {
		r.ReportName = nameVals[0]
	}

	if r.ReportTypeName == "" && r.ReportName == "" {
		return nil
	}
	return &r
}

// getPageQueryParams extracts the page number and max items from the query.
func getPageQueryParams(vals url.Values) (page int, maxItems *int, err error) {
	// If the max items is set to all, leave the maxItems as nil, otherwise parse the value.
	if vals.Get(UrlParamMaxItems) != AllResults {
		maxItemsVal, err := getIntQueryParam(vals, UrlParamMaxItems, DefaultMaxItems)
		if err != nil {
			log.Debugf("Error parsing query parameter %s: value is not an integer", UrlParamMaxItems)
			return 0, nil, err
		} else if maxItemsVal <= 0 {
			log.Debugf("Error parsing query parameter %s: value is less than 0", UrlParamMaxItems)
			return 0, nil, fmt.Errorf("number of results must be >0, requested number: %d", maxItemsVal)
		}
		log.Debugf("Parsed %s = %d", UrlParamMaxItems, maxItemsVal)
		maxItems = &maxItemsVal
	}

	// Get the page value, and sanity check it's >=0.
	page, err = getIntQueryParam(vals, UrlParamPage, 0)
	if err != nil {
		log.Debugf("Error parsing query parameter %s: value is not an integer", UrlParamPage)
		return 0, nil, err
	}
	if page < 0 {
		log.Debugf("Error parsing query parameter %s: value is less than 0", UrlParamPage)
		return 0, nil, fmt.Errorf("page number should be an integer >=0: page=%d", page)
	}
	log.Debugf("Parsed %s = %d", UrlParamPage, page)

	// If we are returning *all* items, page should be set to 0.
	if maxItems == nil && page != 0 {
		log.Debugf("Error parsing query parameter %s: page number should be 0 when enumerating all results", UrlParamPage)
		return 0, nil, fmt.Errorf("page number should be 0 if enumerating all results: page=%d", page)
	}

	return
}

// getSortQueryParams extracts the sortBy and reverseSort values from the query parameters.
func getSortQueryParams(vals url.Values) (sortBy []api.ReportSortBy, err error) {
	sortByFields := vals[UrlParamSortBy]
	fields := make(map[string]bool)
	for _, field := range sortByFields {
		// Check if the field contains the ascending/descending suffix, defaults to not ascending if not present.
		// Remove the suffix to obtain the field name.
		var ascending bool
		if strings.HasSuffix(field, SortAscendingSuffix) {
			ascending = true
			field = strings.TrimSuffix(field, SortAscendingSuffix)
		} else {
			field = strings.TrimSuffix(field, SortDescendingSuffix)
		}

		// Validate the field is a valid sortBy option.
		if !stringSliceContains(field, ValidSortBy) {
			return nil, fmt.Errorf("invalid sortBy query parameter value: %s", field)
		}

		// Track whether or not we have a start time sortBy field.
		fields[field] = true
		sortBy = append(sortBy, api.ReportSortBy{
			Field:     field,
			Ascending: ascending,
		})

		log.Debugf("Parsed %s = %s (ascending = %v)", UrlParamSortBy, field, ascending)
	}
	// Add the default sort fields if not explicitly specified.
	for _, sb := range DefaultSortBy {
		if !fields[sb.Field] {
			log.Debugf("Adding implicit sort by %s", sb.Field)
			sortBy = append(sortBy, sb)
		}
	}
	return
}

// getIntQueryParam extracts an int parameter from the query parms.
func getIntQueryParam(vals url.Values, queryParm string, def int) (int, error) {
	qp := vals.Get(queryParm)
	if len(qp) == 0 {
		return def, nil
	}
	val, err := strconv.ParseInt(qp, 0, 0)
	if err != nil {
		return 0, err
	}
	return int(val), nil
}

// stringSliceContains returns true if the string `val` is in the slice of strings `vals`.
func stringSliceContains(val string, vals []string) bool {
	return slices.Contains(vals, val)
}
