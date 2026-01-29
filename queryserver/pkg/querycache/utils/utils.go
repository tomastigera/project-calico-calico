package utils

import (
	"errors"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
)

// BuildSubstringRegexMatcher creates a regex from a list to help with faster substring searching.
//
// the list should contain at least one value. If the list is empty it fails to create regex pattern.
func BuildSubstringRegexMatcher(list []string) (*regexp.Regexp, error) {
	if len(list) > 0 {
		regexPattern := strings.Join(list, "|")
		epListRegex, err := regexp.Compile(regexPattern)
		if err != nil {
			return nil, err
		}

		return epListRegex, nil
	}
	return nil, errors.New("vague input: cannot create regex pattern from empty list")
}

// GetActualResourceAndTierFromCachedPolicyForRBAC returns the proper resource version/kind and tier for non-tiered
// policies. Kubernetes, StageKubernetes, Admin, and BaselineAdmin network policies are technically non-tiered specially when it comes
// to checking RBAC against them. Before checking authorization to these policies we need to get the correct tier and
// resource type values.
func GetActualResourceAndTierFromCachedPolicyForRBAC(p api.Policy) (api.Resource, string) {
	resource := p.GetResource()
	tier := p.GetTier()
	kind := p.Kind()

	switch kind {
	case model.KindKubernetesNetworkPolicy:
		resource = &v1.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "NetworkPolicy",
				APIVersion: "networking.k8s.io/v1",
			},
		}
		tier = ""
	case apiv3.KindStagedKubernetesNetworkPolicy:
		resource = &apiv3.StagedKubernetesNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "StagedKubernetesNetworkPolicy",
				APIVersion: "projectcalico.org/v3",
			},
		}
		tier = ""
	case "AdminNetworkPolicy":
		resource = &v1alpha1.AdminNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "AdminNetworkPolicy",
				APIVersion: "policy.networking.k8s.io/v1alpha1",
			},
		}
		tier = ""
	case "BaselineAdminNetworkPolicy":
		resource = &v1alpha1.AdminNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "BaselineAdminNetworkPolicy",
				APIVersion: "policy.networking.k8s.io/v1alpha1",
			},
		}
	case "":
		// This shouldn't happen.
		logrus.WithFields(logrus.Fields{
			"res": p.GetResource(),
		}).Warn("Empty kind found on cached policy when determining RBAC resource and tier")
	}

	return resource, tier
}
