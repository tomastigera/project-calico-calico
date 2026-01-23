package policy

import (
	"strings"
)

type key struct {
	PolicyKind      string
	PolicyNamespace string
	PolicyName      string
	Rule            string
}

// aggregate accepts a slice of ActivityLogs and returns a deduplicated slice,
// keeping only the latest log for each unique (Policy, Rule) tuple.
func aggregate(logs []*ActivityLog) []*ActivityLog {
	if len(logs) == 0 {
		return nil
	}

	// Use a map to track the latest log entry for each unique key.
	dedupedMap := make(map[key]*ActivityLog)

	for _, log := range logs {
		if log == nil {
			continue
		}
		k := key{
			PolicyKind:      normalize(log.Policy.Kind),
			PolicyNamespace: normalize(log.Policy.Namespace),
			PolicyName:      normalize(log.Policy.Name),
			Rule:            normalize(log.Rule),
		}

		// Keep the log if it's the first one we've seen for this key,
		// or if it's newer than the existing one.
		if existing, ok := dedupedMap[k]; !ok || log.LastEvaluated.After(existing.LastEvaluated) {
			dedupedMap[k] = log
		}
	}

	result := make([]*ActivityLog, 0, len(dedupedMap))
	for _, l := range dedupedMap {
		result = append(result, l)
	}
	return result
}

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
