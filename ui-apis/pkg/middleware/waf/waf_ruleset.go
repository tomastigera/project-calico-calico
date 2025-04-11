package waf

import (
	"context"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	parser "github.com/projectcalico/calico/ui-apis/pkg/middleware/waf/parser"
)

const (
	defaultRuleset = "coreruleset-default"
)

type Rulesets interface {
	GetRulesets(context.Context) ([]*v1.WAFRuleset, error)
	GetRuleset(context.Context, string) (*v1.WAFRuleset, error)
	GetRule(context.Context, string, string) (*v1.Rule, error)
}

type rulesets struct {
	client lmak8s.ClientSet
}

type rulesetInfo struct {
	name        string
	namespace   string
	displayName string
}

var (
	builtinRulesets = map[string]rulesetInfo{
		defaultRuleset: {
			name:        defaultRuleset,
			namespace:   "calico-system",
			displayName: "OWASP Top 10",
		},
	}
)

func (rs rulesets) GetRulesets(ctx context.Context) ([]*v1.WAFRuleset, error) {

	var rulesets []*v1.WAFRuleset

	for id := range builtinRulesets {
		ruleset, err := rs.GetRuleset(ctx, id)
		if err != nil {
			return nil, err
		}
		rulesets = append(rulesets, ruleset)
	}

	return rulesets, nil
}

func (rs rulesets) GetRuleset(ctx context.Context, id string) (*v1.WAFRuleset, error) {
	rsInfo := builtinRulesets[id]
	if len(rsInfo.name) == 0 {
		return nil, fmt.Errorf("WAF ruleset %s not found", id)
	}

	config, err := rs.client.CoreV1().ConfigMaps(rsInfo.namespace).Get(ctx, rsInfo.name, metav1.GetOptions{})
	if err != nil {
		return &v1.WAFRuleset{}, err
	}

	wrs := v1.WAFRuleset{
		ID:   rsInfo.name,
		Name: rsInfo.displayName,
	}
	for fileName, data := range config.Data {
		if strings.HasSuffix(fileName, ".conf") {
			parsedData, err := parser.Parse(data)
			if err != nil {
				return nil, err
			}

			convertedRules := convertToRules(parsedData)
			if len(convertedRules) == 0 {
				// file contains no rules with 'msg' field
				continue
			}

			cat := v1.File{
				ID:    fileName,
				Name:  fileName,
				Rules: convertedRules,
			}

			wrs.Files = append(wrs.Files, cat)
		}

	}

	slices.SortFunc(wrs.Files, func(i v1.File, j v1.File) int {
		return strings.Compare(i.Name, j.Name)
	})

	return &wrs, nil
}

func (rs rulesets) GetRule(ctx context.Context, rulesetID string, ruleID string) (*v1.Rule, error) {

	rsInfo := builtinRulesets[rulesetID]
	if len(rsInfo.name) == 0 {
		return nil, fmt.Errorf("WAF ruleset %s not found", rulesetID)
	}

	rulesMap, err := rs.client.CoreV1().ConfigMaps(rsInfo.namespace).Get(ctx, rsInfo.name, metav1.GetOptions{})
	if err != nil {
		return &v1.Rule{}, err
	}

	for _, data := range rulesMap.Data {
		parsedData, err := parser.Parse(data)
		if err != nil {
			return &v1.Rule{}, err
		}
		for _, rule := range parsedData {
			if rule.Id == ruleID {
				return &v1.Rule{
					ID:   ruleID,
					Name: rule.Message,
					Data: rule.Raw,
				}, nil
			}
		}
	}
	return &v1.Rule{}, fmt.Errorf("error rule id not found")

}

func convertToRules(parsedRules []parser.Rule) []v1.Rule {
	rules := []v1.Rule{}
	for _, r := range parsedRules {
		if r.Message != "" && r.Id != "" {
			rule := v1.Rule{
				ID:   r.Id,
				Name: r.Message,
			}

			rules = append(rules, rule)
		}
	}

	return rules
}
