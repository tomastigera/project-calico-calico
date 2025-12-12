package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/elastic"
	"github.com/projectcalico/calico/lma/pkg/rbac"
	"github.com/projectcalico/calico/lma/pkg/timeutils"
)

var namespaceTimeout = 10 * time.Second

type FlowLogNamespaceParams struct {
	Limit         int32    `json:"limit"`
	Actions       []string `json:"actions"`
	ClusterName   string   `json:"cluster"`
	Prefix        string   `json:"prefix"`
	Unprotected   bool     `json:"unprotected"`
	StartDateTime string   `json:"startDateTime"`
	EndDateTime   string   `json:"endDateTime"`
	Strict        bool     `json:"strict"`

	// Parsed timestamps
	startDateTimeParm *time.Time
	endDateTimeParm   *time.Time
}

type Namespace struct {
	Name string `json:"name"`
}

func FlowLogNamespaceHandler(k8sClientFactory datastore.ClusterCtxK8sClientFactory, lsclient client.Client, impersonationEnabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// validate request
		params, err := validateFlowLogNamespacesRequest(req)
		if err != nil {
			logrus.WithError(err).Info("Error validating request")
			switch err {
			case ErrInvalidMethod:
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
			case ErrParseRequest:
				http.Error(w, err.Error(), http.StatusBadRequest)
			case errInvalidAction:
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			}
			return
		}

		k8sCli, err := k8sClientFactory.ClientSetForCluster(params.ClusterName)
		if err != nil {
			logrus.WithError(err).Error("failed to get k8s cli")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		user, ok := k8srequest.UserFrom(req.Context())
		if !ok {
			logrus.WithError(err).Error("user not found in context")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		var flowHelper rbac.FlowHelper
		if impersonationEnabled {
			// We only check the user's RBAC permissions if impersonation is enabled in the
			// managed cluster. Otherwise, per-user RBAC permissions are not propagated to the managed cluster.
			flowHelper = rbac.NewCachedFlowHelper(user, lmaauth.NewRBACAuthorizer(k8sCli))
		}

		response, err := getNamespacesFromLinseed(params, lsclient, flowHelper)
		if err != nil {
			logrus.WithError(err).Info("Error getting namespaces from linseed")
			http.Error(w, errGeneric.Error(), http.StatusInternalServerError)
		}

		// return namespace components array
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			logrus.WithError(err).Info("Encoding namespaces array failed")
			http.Error(w, errGeneric.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func validateFlowLogNamespacesRequest(req *http.Request) (*FlowLogNamespaceParams, error) {
	// Validate http method
	if req.Method != http.MethodGet {
		return nil, ErrInvalidMethod
	}

	// extract params from request
	url := req.URL.Query()
	limit, err := extractLimitParam(url)
	if err != nil {
		return nil, ErrParseRequest
	}
	actions := lowerCaseParams(url["actions"])
	cluster := strings.ToLower(url.Get("cluster"))
	prefix := strings.ToLower(url.Get("prefix"))
	unprotected := false
	if unprotectedValue := url.Get("unprotected"); unprotectedValue != "" {
		if unprotected, err = strconv.ParseBool(unprotectedValue); err != nil {
			return nil, ErrParseRequest
		}
	}

	startDateTimeString := url.Get("startDateTime")
	endDateTimeString := url.Get("endDateTime")

	// Parse the start/end time to validate the format. We don't need the resulting time struct.
	now := time.Now()
	startDateTimeParm, _, err := timeutils.ParseTime(now, &startDateTimeString)
	if err != nil {
		logrus.WithError(err).Info("Error extracting start date time")
		return nil, ErrParseRequest
	}
	endDateTimeParm, _, err := timeutils.ParseTime(now, &endDateTimeString)
	if err != nil {
		logrus.WithError(err).Info("Error extracting end date time")
		return nil, ErrParseRequest
	}
	strict := false
	if strictValue := url.Get("strict"); strictValue != "" {
		if strict, err = strconv.ParseBool(strictValue); err != nil {
			return nil, ErrParseRequest
		}
	}

	params := &FlowLogNamespaceParams{
		Actions:           actions,
		Limit:             limit,
		ClusterName:       cluster,
		Prefix:            prefix,
		Unprotected:       unprotected,
		StartDateTime:     startDateTimeString,
		EndDateTime:       endDateTimeString,
		startDateTimeParm: startDateTimeParm,
		endDateTimeParm:   endDateTimeParm,
		Strict:            strict,
	}

	// Check whether the params are provided in the request and set default values if not
	if params.ClusterName == "" {
		params.ClusterName = MaybeParseClusterNameFromRequest(req)
	}
	valid := validateActions(params.Actions)
	if !valid {
		return nil, errInvalidAction
	}
	valid = validateActionsAndUnprotected(params.Actions, params.Unprotected)
	if !valid {
		return nil, errInvalidActionUnprotected
	}

	return params, nil
}

func buildFlowNamespaceParams(params *FlowLogNamespaceParams) *lapi.L3FlowParams {
	fp := &lapi.L3FlowParams{}

	for _, action := range params.Actions {
		fp.Actions = append(fp.Actions, lapi.FlowAction(action))
	}

	if params.Unprotected {
		// Only include flows that are allowed by a profile.
		allow := lapi.FlowActionAllow
		fp.PolicyMatches = []lapi.PolicyMatch{
			{
				Tier:   "__PROFILE__",
				Action: &allow,
			},
		}
	}

	if params.startDateTimeParm != nil || params.endDateTimeParm != nil {
		tr := lmav1.TimeRange{}
		if params.startDateTimeParm != nil {
			tr.From = *params.startDateTimeParm
		}
		if params.endDateTimeParm != nil {
			tr.To = *params.endDateTimeParm
		}
		fp.TimeRange = &tr
	}

	return fp
}

func getNamespacesFromLinseed(params *FlowLogNamespaceParams, lsclient client.Client, rbacHelper rbac.FlowHelper) ([]Namespace, error) {
	ctx, cancel := context.WithTimeout(context.Background(), namespaceTimeout)
	defer cancel()

	// Store the retrieved namespaces.
	nsSet := set.New[string]()
	namespaces := make([]Namespace, 0)

	// Perform the query with composite aggregation
	flowParams := buildFlowNamespaceParams(params)

	// TODO: Right now we use Flows to determine namespaces. We could alternatively use
	// flow logs, or the k8s Namespace API, or even implement a new /namespaces API in Linseed. Unclear which of these
	// will perform best.
	opts := []client.ListPagerOption[lapi.L3Flow]{}
	pager := client.NewListPager(flowParams, opts...)
	pages, errors := pager.Stream(ctx, lsclient.L3Flows(params.ClusterName).List)
	for page := range pages {
		for _, flow := range page.Items {
			sourceNS := elastic.EmptyToDash(flow.Key.Source.Namespace)
			destNS := elastic.EmptyToDash(flow.Key.Destination.Namespace)

			// Check if the set length hits the requested limit
			if nsSet.Len() >= int(params.Limit) {
				break
			}

			// Add namespaces to the set
			if params.Strict {
				// If we strictly enforce RBAC, then we will only return namespaces we have RBAC
				// permissions for and match the query parameters.
				if allowedNamespace(params, sourceNS, rbacHelper) && checkNamespaceRBAC(rbacHelper, sourceNS) {
					nsSet.Add(sourceNS)
				}
				if allowedNamespace(params, destNS, rbacHelper) && checkNamespaceRBAC(rbacHelper, destNS) {
					nsSet.Add(destNS)
				}
			} else {
				// If we are not strictly enforcing RBAC, we will return both namespaces as long we
				// have the permissions to view one namespace in the flow and they match the query
				// parameters.
				if checkNamespaceRBAC(rbacHelper, sourceNS) || checkNamespaceRBAC(rbacHelper, destNS) {
					if allowedNamespace(params, sourceNS, rbacHelper) {
						nsSet.Add(sourceNS)
					}
					if allowedNamespace(params, destNS, rbacHelper) {
						nsSet.Add(destNS)
					}
				}
			}
		}
	}

	// Convert the set to the namespace slice
	i := 0
	for item := range nsSet.All() {
		// Only add items up to the limit
		if i < int(params.Limit) {
			namespaces = append(namespaces, Namespace{Name: item})
			i++
		}
	}

	// Sort the namespaces for nice display purposes
	sort.Slice(namespaces, func(i, j int) bool {
		return namespaces[i].Name < namespaces[j].Name
	})

	// Check for an error after all the namespaces have been processed. This should be fine
	// since an error should stop pages from being received.
	if err, ok := <-errors; ok {
		logrus.WithError(err).Warning("Error processing the flow logs for finding valid namespaces")
		return namespaces, err
	}

	return namespaces, nil
}

func allowedNamespace(params *FlowLogNamespaceParams, namespace string, rbacHelper rbac.FlowHelper) bool {
	if rbacHelper == nil {
		logrus.Debug("No RBAC helper provided, allowing all namespaces")
		return true
	}

	if params.Prefix != "" && !strings.HasPrefix(namespace, params.Prefix) {
		return false
	}

	return true
}

func checkNamespaceRBAC(rbacHelper rbac.FlowHelper, namespace string) bool {
	if rbacHelper == nil {
		logrus.Debug("No RBAC helper provided, allowing all namespaces")
		return true
	}

	var allowed bool
	var err error

	if namespace == "-" {
		// Check the global namespace permissions
		allowed, err = rbacHelper.IncludeGlobalNamespace()
		if err != nil {
			logrus.WithError(err).Info("Error checking RBAC permissions for the cluster scope")
		}
	} else {
		// Check if the user has access to all namespaces first
		if allowed, err = rbacHelper.IncludeNamespace(""); err != nil {
			logrus.WithError(err).Info("Error checking namespace RBAC permissions for all namespaces")
			return false
		} else if allowed {
			return true
		}

		// Check the namespace permissions
		allowed, err = rbacHelper.IncludeNamespace(namespace)
		if err != nil {
			logrus.WithError(err).Info("Error checking namespace RBAC permissions")
		}
	}
	return allowed
}
