package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/rbac"
	"github.com/projectcalico/calico/lma/pkg/timeutils"
)

const (
	flowLogEndpointTypeNs  = "ns"
	flowLogEndpointTypeWep = "wep"
	flowLogEndpointTypeHep = "hep"
)

var namesTimeout = 10 * time.Second

type FlowLogNamesParams struct {
	Limit         int32           `json:"limit"`
	Actions       []string        `json:"actions"`
	ClusterName   string          `json:"cluster"`
	Namespace     string          `json:"namespace"`
	Prefix        string          `json:"prefix"`
	Unprotected   bool            `json:"unprotected"`
	StartDateTime string          `json:"startDateTime"`
	EndDateTime   string          `json:"endDateTime"`
	Strict        bool            `json:"bool"`
	SourceType    []string        `json:"srcType"`
	SourceLabels  []LabelSelector `json:"srcLabels"`
	DestType      []string        `json:"dstType"`
	DestLabels    []LabelSelector `json:"dstLabels"`

	// Parsed timestamps
	startDateTimeESParm *time.Time
	endDateTimeESParm   *time.Time
}

type EndpointInfo struct {
	Namespace string
	Name      string
	Type      string
}

func FlowLogNamesHandler(k8sClientFactory datastore.ClusterCtxK8sClientFactory, lsclient client.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// validate request
		params, err := validateFlowLogNamesRequest(req)
		if err != nil {
			log.WithError(err).Info("Error validating request")
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
			log.WithError(err).Error("failed to get k8s cli")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		user, ok := k8srequest.UserFrom(req.Context())
		if !ok {
			log.WithError(err).Error("user not found in context")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		flowHelper := rbac.NewCachedFlowHelper(user, lmaauth.NewRBACAuthorizer(k8sCli))

		response, err := getNamesFromLinseed(params, lsclient, flowHelper)
		if err != nil {
			log.WithError(err).Info("Error getting names from linseed")
			http.Error(w, errGeneric.Error(), http.StatusInternalServerError)
		}

		// return array of strings with unique names
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			log.WithError(err).Info("Encoding names array failed")
			http.Error(w, errGeneric.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func validateFlowLogNamesRequest(req *http.Request) (*FlowLogNamesParams, error) {
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
	namespace := strings.ToLower(url.Get("namespace"))
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
	startDateTimeESParm, _, err := timeutils.ParseTime(now, &startDateTimeString)
	if err != nil {
		log.WithError(err).Info("Error extracting start date time")
		return nil, ErrParseRequest
	}
	endDateTimeESParm, _, err := timeutils.ParseTime(now, &endDateTimeString)
	if err != nil {
		log.WithError(err).Info("Error extracting end date time")
		return nil, ErrParseRequest
	}
	strict := false
	if strictValue := url.Get("strict"); strictValue != "" {
		if strict, err = strconv.ParseBool(strictValue); err != nil {
			return nil, ErrParseRequest
		}
	}

	srcType := lowerCaseParams(url["srcType"])
	srcLabels, err := getLabelSelectors(url["srcLabels"])
	if err != nil {
		log.WithError(err).Info("Error extracting srcLabels")
		return nil, ErrParseRequest
	}
	dstType := lowerCaseParams(url["dstType"])
	dstLabels, err := getLabelSelectors(url["dstLabels"])
	if err != nil {
		log.WithError(err).Info("Error extracting dstLabels")
		return nil, ErrParseRequest
	}

	params := &FlowLogNamesParams{
		Actions:             actions,
		Limit:               limit,
		ClusterName:         cluster,
		Prefix:              prefix,
		Namespace:           namespace,
		Unprotected:         unprotected,
		StartDateTime:       startDateTimeString,
		EndDateTime:         endDateTimeString,
		startDateTimeESParm: startDateTimeESParm,
		endDateTimeESParm:   endDateTimeESParm,
		Strict:              strict,
		SourceType:          srcType,
		SourceLabels:        srcLabels,
		DestType:            dstType,
		DestLabels:          dstLabels,
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

	srcTypeValid := validateFlowTypes(params.SourceType)
	if !srcTypeValid {
		return nil, errInvalidFlowType
	}
	dstTypeValid := validateFlowTypes(params.DestType)
	if !dstTypeValid {
		return nil, errInvalidFlowType
	}

	srcLabelsValid := validateLabelSelector(params.SourceLabels)
	if !srcLabelsValid {
		return nil, errInvalidLabelSelector
	}
	dstLabelsValid := validateLabelSelector(params.DestLabels)
	if !dstLabelsValid {
		return nil, errInvalidLabelSelector
	}

	return params, nil
}

func buildNamesQuery(params *FlowLogNamesParams) *lapi.L3FlowParams {
	fp := lapi.L3FlowParams{}
	if len(params.Actions) > 0 {
		for _, action := range params.Actions {
			fp.Actions = append(fp.Actions, lapi.FlowAction(action))
		}
	}

	if params.Unprotected {
		// Only include flows that are allowed by a profile.
		allow := lapi.FlowActionAllow
		fp.PendingPolicyMatches = []lapi.PolicyMatch{
			{
				Tier:   "__PROFILE__",
				Action: &allow,
			},
		}
	}

	if params.startDateTimeESParm != nil || params.endDateTimeESParm != nil {
		tr := lmav1.TimeRange{}
		if params.startDateTimeESParm != nil {
			tr.From = *params.startDateTimeESParm
		}
		if params.endDateTimeESParm != nil {
			tr.To = *params.endDateTimeESParm
		}
		fp.TimeRange = &tr
	}

	// Collect all the different filtering queries based on the specified parameters.
	if params.Prefix != "" {
		fp.NameAggrMatches = []lapi.NameMatch{
			{Type: lapi.MatchTypeAny, Names: []string{params.Prefix}},
		}
	}
	if params.Namespace != "" {
		fp.NamespaceMatches = []lapi.NamespaceMatch{
			{Type: lapi.MatchTypeAny, Namespaces: []string{params.Namespace}},
		}
	}
	if len(params.SourceType) > 0 {
		for _, t := range params.SourceType {
			fp.SourceTypes = append(fp.SourceTypes, lapi.EndpointType(t))
		}
	}
	if len(params.SourceLabels) > 0 {
		for _, lab := range params.SourceLabels {
			fp.SourceSelectors = append(fp.SourceSelectors, lapi.LabelSelector{
				Key:      lab.Key,
				Values:   lab.Values,
				Operator: lab.Operator,
			})
		}
	}
	if len(params.DestType) > 0 {
		for _, t := range params.DestType {
			fp.DestinationTypes = append(fp.DestinationTypes, lapi.EndpointType(t))
		}
	}
	if len(params.DestLabels) > 0 {
		for _, lab := range params.DestLabels {
			fp.DestinationSelectors = append(fp.DestinationSelectors, lapi.LabelSelector{
				Key:      lab.Key,
				Values:   lab.Values,
				Operator: lab.Operator,
			})
		}
	}

	return &fp
}

func getNamesFromLinseed(params *FlowLogNamesParams, lsclient client.Client, rbacHelper rbac.FlowHelper) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), namesTimeout)
	defer cancel()

	nameSet := set.New[string]()
	names := make([]string, 0)

	flowParams := buildNamesQuery(params)

	// TODO: Right now we use Flows to determine names. We could alternatively use
	// flow logs, or the k8s Namespace API, or even implement a new /namespaces API in Linseed. Unclear which of these
	// will perform best.
	opts := []client.ListPagerOption[lapi.L3Flow]{}
	pager := client.NewListPager(flowParams, opts...)
	pages, errors := pager.Stream(ctx, lsclient.L3Flows(params.ClusterName).List)
	for page := range pages {
		for _, flow := range page.Items {
			source := EndpointInfo{
				Namespace: flow.Key.Source.Namespace,
				Name:      flow.Key.Source.AggregatedName,
				Type:      string(flow.Key.Source.Type),
			}
			dest := EndpointInfo{
				Namespace: flow.Key.Destination.Namespace,
				Name:      flow.Key.Destination.AggregatedName,
				Type:      string(flow.Key.Destination.Type),
			}

			// Check if the set length hits the requested limit
			if nameSet.Len() >= int(params.Limit) {
				break
			}

			// Add names to the set
			if params.Strict {
				// If we strictly enforce RBAC, then we will only return endpoints we have RBAC
				// permissions for and match the query parameters.
				if allowedName(params, source, rbacHelper) && checkEndpointRBAC(rbacHelper, source) {
					nameSet.Add(source.Name)
				}
				if allowedName(params, dest, rbacHelper) && checkEndpointRBAC(rbacHelper, dest) {
					nameSet.Add(dest.Name)
				}
			} else {
				// If we are not strictly enforcing RBAC, we will return both endpoints as long as we
				// have the RBAC permissions to view one endpoint in a flow and they match the query
				// parameters.
				if checkEndpointRBAC(rbacHelper, source) || checkEndpointRBAC(rbacHelper, dest) {
					if allowedName(params, source, rbacHelper) {
						nameSet.Add(source.Name)
					}
					if allowedName(params, dest, rbacHelper) {
						nameSet.Add(dest.Name)
					}
				}
			}
		}
	}

	// Convert the set to the name slice
	i := 0
	for item := range nameSet.All() {
		// Only add items up to the limit
		if i < int(params.Limit) {
			names = append(names, item)
			i++
		}
	}

	// Sort the names for nice display purposes
	sort.Strings(names)

	// Check for an error after all the namespaces have been processed. This should be fine
	// since an error should stop more buckets from being received.
	if err, ok := <-errors; ok {
		log.WithError(err).Warning("Error processing the flow logs for finding valid names")
		return names, err
	}

	return names, nil
}

func allowedName(params *FlowLogNamesParams, ep EndpointInfo, rbacHelper rbac.FlowHelper) bool {
	if params.Prefix != "" && !strings.HasPrefix(ep.Name, params.Prefix) {
		return false
	}

	// If a specific namespace is specified, filter out endpoints that are not from that namespace.
	if params.Namespace != "" && params.Namespace != ep.Namespace {
		return false
	}

	return true
}

func checkEndpointRBAC(rbacHelper rbac.FlowHelper, ep EndpointInfo) bool {
	switch ep.Type {
	case flowLogEndpointTypeNs:
		// Check if this is a global networkset
		if ep.Namespace == "" {
			//nolint:staticcheck // Ignore SA1019 deprecated
			allowGlobalNs, err := rbacHelper.CanListGlobalNetworkSets()
			if err != nil {
				log.WithError(err).Info("Error checking global network set list permissions")
			}
			return allowGlobalNs
		} else {
			// Check if access to networksets across all namespaces is granted.
			//nolint:staticcheck // Ignore SA1019 deprecated
			allowAllNs, err := rbacHelper.CanListNetworkSets("")
			if err != nil {
				log.WithError(err).Info("Error checking networkset list permissions across all namespaces")
			}

			// If access is granted across all namespaces, no need to check specific namespace permissions
			if allowAllNs {
				return allowAllNs
			}

			// Check the permissions against the specific namespace
			//nolint:staticcheck // Ignore SA1019 deprecated
			allowNs, err := rbacHelper.CanListNetworkSets(ep.Namespace)
			if err != nil {
				log.WithError(err).Infof("Error checking networkset list permissions for namespace %s", ep.Namespace)
			}
			return allowNs
		}
	case flowLogEndpointTypeWep:
		// Check if access to pods across all namespaces is granted
		//nolint:staticcheck // Ignore SA1019 deprecated
		allowAllWep, err := rbacHelper.CanListPods("")
		if err != nil {
			log.WithError(err).Info("Error checking pod list permissions across all namespaces")
		}

		// If access is granted across all namespaces, no need to check the specific namespace permissions
		if allowAllWep {
			return allowAllWep
		}

		// Check the permissions against the specific namespace
		//nolint:staticcheck // Ignore SA1019 deprecated
		allowWep, err := rbacHelper.CanListPods(ep.Namespace)
		if err != nil {
			log.WithError(err).Infof("Error checking pod list permissions for namespace %s", ep.Namespace)
		}
		return allowWep
	case flowLogEndpointTypeHep:
		//nolint:staticcheck // Ignore SA1019 deprecated
		allowHep, err := rbacHelper.CanListHostEndpoints()
		if err != nil {
			log.WithError(err).Info("Error checking host endpoint list permissions")
		}
		return allowHep
	default:
		// This is not a valid endpoint type (external network)
		return false
	}
}
