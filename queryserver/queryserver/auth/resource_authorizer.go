package auth

import (
	"context"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	"github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
)

const (
	ResourceServiceAccount  = "serviceaccount"
	ResourceServiceAccounts = "serviceaccounts"
	ResourceTier            = "tier"
	ResourceTiers           = "tiers"
	ResourceNamespace       = "namespace"
	ResourceNamespaces      = "namespaces"
	ResourcePod             = "pod"
	ResourcePods            = "pods"

	ResourceNetworkPolicy                   = "networkpolicy"
	ResourceNetworkPolicies                 = "networkpolicies"
	ResourceGlobalNetworkPolicy             = "globalnetworkpolicy"
	ResourceGlobalNetworkPolicies           = "globalnetworkpolicies"
	ResourceAdminNetworkPolicy              = "adminnetworkpolicy"
	ResourceAdminNetworkPolicies            = "adminnetworkpolicies"
	ResourceBaselineAdminNetworkPolicy      = "baselineadminnetworkpolicy"
	ResourceBaselineAdminNetworkPolicies    = "baselineadminnetworkpolicies"
	ResourceStageNetworkPolicy              = "stagednetworkpolicy"
	ResourceStageNetworkPolicies            = "stagednetworkpolicies"
	ResourceStagedGlobalNetworkPolicy       = "stagedglobalnetworkpolicy"
	ResourceStagedGlobalNetworkPolicies     = "stagedglobalnetworkpolicies"
	ResourceStagedKubernetesNetworkPolicy   = "stagedkubernetesnetworkpolicy"
	ResourceStagedKubernetesNetworkPolicies = "stagedkubernetesnetworkpolicies"
	ResourceNetworkSet                      = "networkset"
	ResourceNetworkSets                     = "networksets"
	ResourceGlobalNetworkSet                = "globalnetworkset"
	ResourceGlobalNetworkSets               = "globalnetworksets"
	ResourceManagedCluster                  = "managedcluster"
	ResourceManagedClusters                 = "managedclusters"
	ResourceGlobalThreatFeed                = "globalthreatfeed"
	ResourceGlobalThreatFeeds               = "globalthreatfeeds"

	ApiGroupK8sNetworking       = "networking.k8s.io"
	ApiGroupK8sPolicyNetworking = "policy.networking.k8s.io"
)

type Permission interface {
	IsAuthorized(res api.Resource, tier *string, verbs []rbac.Verb) bool
}
type permission struct {
	APIGroupsResourceNamePermissions map[APIGroupResourceName]VerbPermissions
}

type VerbPermissions map[rbac.Verb][]v3.AuthorizedResourceGroup // verb string --> []ResourceGroup
type APIGroupResourceName string

func getCombinedName(apiGroup string, resourceName string) APIGroupResourceName {
	return APIGroupResourceName(strings.Join([]string{apiGroup, resourceName}, "/"))
}

// IsAuthorized is checking if current users' permissions allows either of the verbs passed in the param on the resource passed in.
func (p *permission) IsAuthorized(res api.Resource, tier *string, verbs []rbac.Verb) bool {
	combinedName := getCombinedName(
		getAPIGroup(res.GetObjectKind().GroupVersionKind().Group),
		convertV1KindToResourceType(res.GetObjectKind().GroupVersionKind().Kind, res.GetObjectMeta().GetName()))

	verbsMap, ok := p.APIGroupsResourceNamePermissions[combinedName]
	if !ok {
		return false
	}

	for _, v := range verbs {
		resourceGrps, ok := verbsMap[v]
		if !ok {
			return false
		}

		for _, resourceGrp := range resourceGrps {
			if namespaceMatch(resourceGrp.Namespace, res.GetObjectMeta().GetNamespace()) &&
				tierMatch(resourceGrp.Tier, tier) {
				return true
			}
		}
	}
	return false
}

func namespaceMatch(authzNS, rscNS string) bool {
	return authzNS == "" || (authzNS == rscNS)
}

func tierMatch(authzTier string, rscTier *string) bool {
	if authzTier == "" {
		return true
	}
	if rscTier != nil && (authzTier == *rscTier) {
		return true
	}
	return false
}

func getAPIGroup(apigroup string) string {
	return strings.ToLower(apigroup)
}

// convertV1KindToResourceType converts the kind stored in the V1 resource to the actual type present
// in the authorizationreview response.
func convertV1KindToResourceType(kind string, name string) string {
	kind = strings.ToLower(kind)

	// needs to be checked to determine if the policy is of type "Staged"
	if strings.HasPrefix(name, "staged:") && !strings.HasPrefix(kind, "staged") {
		kind = "staged" + kind
	}

	switch kind {
	case ResourceStagedGlobalNetworkPolicy, ResourceStagedGlobalNetworkPolicies:
		return ResourceStagedGlobalNetworkPolicies
	case ResourceStageNetworkPolicy, ResourceStageNetworkPolicies:
		return ResourceStageNetworkPolicies
	case ResourceStagedKubernetesNetworkPolicy, ResourceStagedKubernetesNetworkPolicies:
		return ResourceStagedKubernetesNetworkPolicies
	case ResourceGlobalNetworkPolicy, ResourceGlobalNetworkPolicies:
		return ResourceGlobalNetworkPolicies
	case ResourceNetworkPolicy, ResourceNetworkPolicies:
		return ResourceNetworkPolicies
	case ResourceAdminNetworkPolicy, ResourceAdminNetworkPolicies:
		return ResourceAdminNetworkPolicies
	case ResourceBaselineAdminNetworkPolicy, ResourceBaselineAdminNetworkPolicies:
		return ResourceBaselineAdminNetworkPolicies
	case ResourceGlobalNetworkSet, ResourceGlobalNetworkSets:
		return ResourceGlobalNetworkSets
	case ResourceNetworkSet, ResourceNetworkSets:
		return ResourceNetworkSets
	case ResourceTier, ResourceTiers:
		return ResourceTiers
	case ResourcePod, ResourcePods:
		return ResourcePods
	case ResourceNamespace, ResourceNamespaces:
		return ResourceNamespaces
	case ResourceServiceAccount, ResourceServiceAccounts:
		return ResourceServiceAccounts
	case ResourceManagedCluster, ResourceManagedClusters:
		return ResourceManagedClusters
	case ResourceGlobalThreatFeed, ResourceGlobalThreatFeeds:
		return ResourceGlobalThreatFeeds
	default:
		return kind
	}

}

type Authorizer interface {
	PerformUserAuthorizationReview(ctx context.Context,
		authreviewList []v3.AuthorizationReviewResourceAttributes) (Permission, error)
}

type authorizer struct {
	clientSetFactory k8s.ClientSetFactory
}

func NewAuthorizer(clsfactory k8s.ClientSetFactory) Authorizer {
	return &authorizer{
		clientSetFactory: clsfactory,
	}
}

// PerformUserAuthorizationReview, creates an authorizationreview for the passed in authreviewattributes and
// build permission based on the results.
//
// returns permission, error
func (authz *authorizer) PerformUserAuthorizationReview(ctx context.Context,
	authReviewattributes []v3.AuthorizationReviewResourceAttributes) (Permission, error) {

	user, ok := request.UserFrom(ctx)
	if !ok {
		// There should be user info in the request context. If not this is server error since an earlier handler
		// should have authenticated.
		log.Debug("No user information on request")
		return nil, &httputils.HttpStatusError{
			Status: http.StatusInternalServerError,
			Msg:    "No user information on request",
		}
	}

	// since each cluster has its own queryserver, we do not need to pass clusterID to get the clientSet.
	cs, err := authz.clientSetFactory.NewClientSetForApplication("")
	if err != nil {
		return nil, err
	}

	// we cannot use the current context to PerformAuthorizationReviewContext because it contains the userInfo and queryserver
	// does not have impersonate rbac to execute calls on behalf of users. However, we still need to run AuthorizationReview
	// for the user. Thus, we use PerformAuthroizationReviewWithUser which is using the background context to execute the request
	// and allows us to pass in user info to be used in the authorization.
	authorizedResourceVerbs, err := auth.PerformAuthorizationReviewWithUser(user, cs, authReviewattributes)

	if err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusInternalServerError,
			Msg:    "Unable to perform authorization review",
		}
	}

	return convertAuthorizationReviewStatusToPermissions(authorizedResourceVerbs)
}

// function convertAuthorizationReviewStatusToPermissions converts AuthorizedResourceVerbs to Permission (map of resource groups / name -> verb -> authorizedResourceGroup) for
// faster lookup.
func convertAuthorizationReviewStatusToPermissions(authorizedResourceVerbs []v3.AuthorizedResourceVerbs) (Permission, error) {
	permMap := permission{
		APIGroupsResourceNamePermissions: map[APIGroupResourceName]VerbPermissions{},
	}
	for _, rAtt := range authorizedResourceVerbs {
		combinedName := getCombinedName(rAtt.APIGroup, rAtt.Resource)
		if _, ok := permMap.APIGroupsResourceNamePermissions[combinedName]; !ok {
			permMap.APIGroupsResourceNamePermissions[combinedName] = VerbPermissions{}
		}
		for _, verb := range rAtt.Verbs {
			resourceGroups := make([]v3.AuthorizedResourceGroup, 0)
			if _, ok := permMap.APIGroupsResourceNamePermissions[combinedName][rbac.Verb(verb.Verb)]; ok {
				resourceGroups = permMap.APIGroupsResourceNamePermissions[combinedName][rbac.Verb(verb.Verb)]
			}
			resourceGroups = append(resourceGroups, verb.ResourceGroups...)
			permMap.APIGroupsResourceNamePermissions[combinedName][rbac.Verb(verb.Verb)] = resourceGroups
		}
	}

	return &permMap, nil
}

var PolicyAuthReviewAttrList = []v3.AuthorizationReviewResourceAttributes{
	{
		APIGroup: v3.Group,
		Resources: []string{
			ResourceStageNetworkPolicies, ResourceStagedGlobalNetworkPolicies, ResourceStagedKubernetesNetworkPolicies,
			ResourceGlobalNetworkPolicies, ResourceNetworkPolicies, ResourceNetworkSets, ResourceGlobalNetworkSets,
			ResourceTiers,
		},
		Verbs: []string{string(rbac.VerbWatch), string(rbac.VerbGet), string(rbac.VerbList)},
	},
	{
		APIGroup:  ApiGroupK8sNetworking,
		Resources: []string{ResourceNetworkPolicies},
		Verbs:     []string{string(rbac.VerbWatch), string(rbac.VerbGet), string(rbac.VerbList)},
	},
	{
		APIGroup:  ApiGroupK8sPolicyNetworking,
		Resources: []string{ResourceAdminNetworkPolicies},
		Verbs:     []string{string(rbac.VerbWatch), string(rbac.VerbGet), string(rbac.VerbList)},
	},
	{
		APIGroup:  ApiGroupK8sPolicyNetworking,
		Resources: []string{ResourceBaselineAdminNetworkPolicies},
		Verbs:     []string{string(rbac.VerbWatch), string(rbac.VerbGet), string(rbac.VerbList)},
	},
}
