package waf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func TestAggregation(t *testing.T) {
	t.Run("basic aggreagation", func(t *testing.T) {
		a, err := NewAggregator([]string{"path", "method"})
		require.NoError(t, err)

		now := time.Now()

		a.AddLog(&v1.WAFLog{
			Timestamp: now,
			Path:      "/test",
			Method:    "GET",
			RequestId: "1",
			Protocol:  "HTTP/1.1",
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(1 * time.Second),
			Path:      "/test",
			Method:    "GET",
			RequestId: "2",
			Protocol:  "HTTP/1.1",
		})

		aggregatedLogs := a.EndAggregationPeriod()
		require.Len(t, aggregatedLogs, 1)
		require.Equal(t, 2, aggregatedLogs[0].Count)
		require.Equal(t, now, aggregatedLogs[0].Timestamp)
		require.Equal(t, "/test", aggregatedLogs[0].Path)
		require.Equal(t, "GET", aggregatedLogs[0].Method)
		require.Equal(t, "-", aggregatedLogs[0].RequestId)
		require.Equal(t, "HTTP/1.1", aggregatedLogs[0].Protocol)
	})

	t.Run("special logic: rules merging", func(t *testing.T) {
		a, err := NewAggregator([]string{"path", "method"})
		require.NoError(t, err)

		now := time.Now()

		a.AddLog(&v1.WAFLog{
			Timestamp: now,
			Path:      "/test",
			Method:    "GET",
			RequestId: "1",
			Protocol:  "HTTP/1.1",
			Rules: []v1.WAFRuleHit{
				{
					Id:         "9992",
					Message:    "WAF rules, rule WAF",
					Severity:   "2",
					File:       "JOJO-000.conf",
					Line:       "666",
					Disruptive: false,
				},
			},
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(1 * time.Second),
			Path:      "/test",
			Method:    "GET",
			RequestId: "2",
			Protocol:  "HTTP/1.1",
			Rules: []v1.WAFRuleHit{
				{
					Id:         "9993",
					Message:    "WAF rules, rule, rule WAF",
					Severity:   "4",
					File:       "JOJO-001.conf",
					Line:       "6669",
					Disruptive: true,
				},
			},
		})

		aggregatedLogs := a.EndAggregationPeriod()
		require.Len(t, aggregatedLogs, 1)
		require.Equal(t, 2, aggregatedLogs[0].Count)
		require.Equal(t, now, aggregatedLogs[0].Timestamp)
		require.Equal(t, "/test", aggregatedLogs[0].Path)
		require.Equal(t, "GET", aggregatedLogs[0].Method)
		require.Equal(t, "-", aggregatedLogs[0].RequestId)
		require.Equal(t, "HTTP/1.1", aggregatedLogs[0].Protocol)
		require.Equal(t, []v1.WAFRuleHit{
			{
				Id:         "9992",
				Message:    "WAF rules, rule WAF",
				Severity:   "2",
				File:       "JOJO-000.conf",
				Line:       "666",
				Disruptive: false,
			},
			{
				Id:         "9993",
				Message:    "WAF rules, rule, rule WAF",
				Severity:   "4",
				File:       "JOJO-001.conf",
				Line:       "6669",
				Disruptive: true,
			},
		}, aggregatedLogs[0].Rules)
	})

	t.Run("aggreagate per rules", func(t *testing.T) {
		a, err := NewAggregator([]string{"rules"})
		require.NoError(t, err)

		now := time.Now()

		a.AddLog(&v1.WAFLog{
			Timestamp: now,
			Path:      "/test",
			Method:    "GET",
			RequestId: "1",
			Protocol:  "HTTP/1.1",
			Rules: []v1.WAFRuleHit{
				{
					Id:         "9992",
					Message:    "WAF rules, rule WAF",
					Severity:   "2",
					File:       "JOJO-000.conf",
					Line:       "666",
					Disruptive: false,
				},
			},
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(1 * time.Second),
			Path:      "/test",
			Method:    "GET",
			RequestId: "2",
			Protocol:  "HTTP/1.1",
			Rules: []v1.WAFRuleHit{
				{
					Id:         "9993",
					Message:    "WAF rules, rule, rule WAF",
					Severity:   "4",
					File:       "JOJO-001.conf",
					Line:       "6669",
					Disruptive: true,
				},
			},
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(2 * time.Second),
			Path:      "/test",
			Method:    "GET",
			RequestId: "3",
			Protocol:  "HTTP/1.1",
			Rules: []v1.WAFRuleHit{
				{
					Id:         "9992",
					Message:    "WAF rules, rule WAF",
					Severity:   "2",
					File:       "JOJO-000.conf",
					Line:       "666",
					Disruptive: false,
				},
				{
					Id:         "9993",
					Message:    "WAF rules, rule, rule WAF",
					Severity:   "4",
					File:       "JOJO-001.conf",
					Line:       "6669",
					Disruptive: true,
				},
			},
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(3 * time.Second),
			Path:      "/test",
			Method:    "GET",
			RequestId: "3",
			Protocol:  "HTTP/1.1",
			Rules: []v1.WAFRuleHit{
				{
					Id:         "9992",
					Message:    "WAF rules, rule WAF",
					Severity:   "2",
					File:       "JOJO-000.conf",
					Line:       "666",
					Disruptive: false,
				},
			},
		})

		aggregatedLogs := a.EndAggregationPeriod()
		require.Len(t, aggregatedLogs, 3)
		require.Equal(t, 2, aggregatedLogs[0].Count)
		require.Equal(t, 1, aggregatedLogs[1].Count)
		require.Equal(t, 1, aggregatedLogs[2].Count)
		require.Equal(t, now, aggregatedLogs[0].Timestamp)
		require.Equal(t, now.Add(1*time.Second), aggregatedLogs[1].Timestamp)
		require.Equal(t, "/test", aggregatedLogs[0].Path)
		require.Equal(t, "/test", aggregatedLogs[1].Path)
		require.Equal(t, "GET", aggregatedLogs[0].Method)
		require.Equal(t, "GET", aggregatedLogs[1].Method)
		require.Equal(t, "-", aggregatedLogs[0].RequestId)
		require.Equal(t, "2", aggregatedLogs[1].RequestId)
		require.Equal(t, "3", aggregatedLogs[2].RequestId)
		require.Equal(t, "HTTP/1.1", aggregatedLogs[0].Protocol)
		require.Equal(t, []v1.WAFRuleHit{
			{
				Id:         "9992",
				Message:    "WAF rules, rule WAF",
				Severity:   "2",
				File:       "JOJO-000.conf",
				Line:       "666",
				Disruptive: false,
			},
		}, aggregatedLogs[0].Rules)
		require.Len(t, aggregatedLogs[1].Rules, 1)
		require.Len(t, aggregatedLogs[2].Rules, 2)
	})
}

func TestMustKeepFieldsValidation(t *testing.T) {
	t.Run("valid fields", func(t *testing.T) {
		_, err := NewAggregator([]string{"path", "method", "rules"})
		require.NoError(t, err)
	})
	t.Run("invalid field", func(t *testing.T) {
		_, err := NewAggregator([]string{"rules", "unknownfield"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown mustKeepField")
	})
	t.Run("empty fields (no aggregation)", func(t *testing.T) {
		_, err := NewAggregator([]string{})
		require.NoError(t, err)
	})
}

func TestNoAggregation(t *testing.T) {
	a, err := NewAggregator([]string{})
	require.NoError(t, err)

	now := time.Now()

	a.AddLog(&v1.WAFLog{
		Timestamp: now,
		Path:      "/foo",
		Method:    "POST",
		RequestId: "abc",
		Protocol:  "HTTP/2",
		Rules: []v1.WAFRuleHit{
			{Id: "1"},
		},
	})
	a.AddLog(&v1.WAFLog{
		Timestamp: now.Add(1 * time.Second),
		Path:      "/bar",
		Method:    "GET",
		RequestId: "def",
		Protocol:  "HTTP/1.1",
		Rules: []v1.WAFRuleHit{
			{Id: "2"},
		},
	})

	aggregatedLogs := a.EndAggregationPeriod()
	require.Len(t, aggregatedLogs, 2)
	require.Equal(t, "abc", aggregatedLogs[0].RequestId)
	require.Equal(t, "def", aggregatedLogs[1].RequestId)
}

func TestAggregateOnlyIfNeeded(t *testing.T) {
	t.Run("default aggregation - no source/destination", func(t *testing.T) {
		a, err := NewAggregator([]string{"rules"})
		require.NoError(t, err)

		now := time.Now()

		a.AddLog(&v1.WAFLog{
			Timestamp: now,
			Path:      "/test",
			Method:    "GET",
			RequestId: "1",
			Protocol:  "HTTP/1.1",
			Rules: []v1.WAFRuleHit{
				{
					Id:         "9992",
					Message:    "WAF rules, rule WAF",
					Severity:   "2",
					File:       "JOJO-000.conf",
					Line:       "666",
					Disruptive: false,
				},
				{
					Id:         "9993",
					Message:    "WAF rules, rule, rule WAF",
					Severity:   "4",
					File:       "JOJO-001.conf",
					Line:       "6669",
					Disruptive: true,
				},
			},
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(1 * time.Second),
			Path:      "/test",
			Method:    "POST",
			RequestId: "2",
			Protocol:  "HTTP/1.1",
			Rules: []v1.WAFRuleHit{
				{
					Id:         "9992",
					Message:    "WAF rules, rule WAF",
					Severity:   "2",
					File:       "JOJO-000.conf",
					Line:       "666",
					Disruptive: false,
				},
				{
					Id:         "9993",
					Message:    "WAF rules, rule, rule WAF",
					Severity:   "4",
					File:       "JOJO-001.conf",
					Line:       "6669",
					Disruptive: true,
				},
			},
		})

		aggregatedLogs := a.EndAggregationPeriod()
		require.Len(t, aggregatedLogs, 1)
		require.Equal(t, 2, aggregatedLogs[0].Count)
		require.Equal(t, now, aggregatedLogs[0].Timestamp)
		require.Equal(t, "/test", aggregatedLogs[0].Path)
		require.Equal(t, "-", aggregatedLogs[0].Method)
		require.Equal(t, "-", aggregatedLogs[0].RequestId)
		require.Equal(t, "HTTP/1.1", aggregatedLogs[0].Protocol)
	})

	t.Run("default aggregation - different source IP, same port", func(t *testing.T) {
		a, err := NewAggregator([]string{"rules"})
		require.NoError(t, err)

		now := time.Now()

		a.AddLog(&v1.WAFLog{
			Timestamp: now,
			Path:      "/test",
			Source: &v1.WAFEndpoint{
				IP:      "1.1.1.1",
				PortNum: 1234,
			},
			Rules: []v1.WAFRuleHit{
				{
					Id: "9992",
				},
				{
					Id: "9993",
				},
			},
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(1 * time.Second),
			Path:      "/test",
			Source: &v1.WAFEndpoint{
				IP:      "1.1.1.2",
				PortNum: 1234,
			},
			Rules: []v1.WAFRuleHit{
				{
					Id: "9992",
				},
				{
					Id: "9993",
				},
			},
		})

		aggregatedLogs := a.EndAggregationPeriod()
		require.Len(t, aggregatedLogs, 1)
		require.Equal(t, 2, aggregatedLogs[0].Count)
		require.Equal(t, now, aggregatedLogs[0].Timestamp)
		require.Equal(t, "/test", aggregatedLogs[0].Path)
		require.Equal(t, "-", aggregatedLogs[0].Source.IP)
		require.Equal(t, int32(1234), aggregatedLogs[0].Source.PortNum)
	})

	t.Run("default aggregation - same source IP, different port", func(t *testing.T) {
		a, err := NewAggregator([]string{"rules"})
		require.NoError(t, err)

		now := time.Now()

		a.AddLog(&v1.WAFLog{
			Timestamp: now,
			Path:      "/test",
			Source: &v1.WAFEndpoint{
				IP:      "1.1.1.1",
				PortNum: 1234,
			},
			Rules: []v1.WAFRuleHit{
				{
					Id: "9992",
				},
				{
					Id: "9993",
				},
			},
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(1 * time.Second),
			Path:      "/test",
			Source: &v1.WAFEndpoint{
				IP:      "1.1.1.1",
				PortNum: 5678,
			},
			Rules: []v1.WAFRuleHit{
				{
					Id: "9992",
				},
				{
					Id: "9993",
				},
			},
		})

		aggregatedLogs := a.EndAggregationPeriod()
		require.Len(t, aggregatedLogs, 1)
		require.Equal(t, 2, aggregatedLogs[0].Count)
		require.Equal(t, now, aggregatedLogs[0].Timestamp)
		require.Equal(t, "/test", aggregatedLogs[0].Path)
		require.Equal(t, "1.1.1.1", aggregatedLogs[0].Source.IP)
		require.Equal(t, int32(0), aggregatedLogs[0].Source.PortNum)
	})

	t.Run("default aggregation - different source IP, same port", func(t *testing.T) {
		a, err := NewAggregator([]string{"rules"})
		require.NoError(t, err)

		now := time.Now()

		a.AddLog(&v1.WAFLog{
			Timestamp: now,
			Path:      "/test",
			Source: &v1.WAFEndpoint{
				IP:      "1.1.1.1",
				PortNum: 1234,
			},
			Rules: []v1.WAFRuleHit{
				{
					Id: "9992",
				},
				{
					Id: "9993",
				},
			},
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(1 * time.Second),
			Path:      "/test",
			Source: &v1.WAFEndpoint{
				IP:      "1.1.1.2",
				PortNum: 1234,
			},
			Rules: []v1.WAFRuleHit{
				{
					Id: "9992",
				},
				{
					Id: "9993",
				},
			},
		})

		aggregatedLogs := a.EndAggregationPeriod()
		require.Len(t, aggregatedLogs, 1)
		require.Equal(t, 2, aggregatedLogs[0].Count)
		require.Equal(t, now, aggregatedLogs[0].Timestamp)
		require.Equal(t, "/test", aggregatedLogs[0].Path)
		require.Equal(t, "-", aggregatedLogs[0].Source.IP)
		require.Equal(t, int32(1234), aggregatedLogs[0].Source.PortNum)
	})

	t.Run("default aggregation - same dest IP, different port", func(t *testing.T) {
		a, err := NewAggregator([]string{"rules"})
		require.NoError(t, err)

		now := time.Now()

		a.AddLog(&v1.WAFLog{
			Timestamp: now,
			Path:      "/test",
			Destination: &v1.WAFEndpoint{
				IP:      "1.1.1.1",
				PortNum: 1234,
			},
			Rules: []v1.WAFRuleHit{
				{
					Id: "9992",
				},
				{
					Id: "9993",
				},
			},
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(1 * time.Second),
			Path:      "/test",
			Destination: &v1.WAFEndpoint{
				IP:      "1.1.1.1",
				PortNum: 5678,
			},
			Rules: []v1.WAFRuleHit{
				{
					Id: "9992",
				},
				{
					Id: "9993",
				},
			},
		})

		aggregatedLogs := a.EndAggregationPeriod()
		require.Len(t, aggregatedLogs, 1)
		require.Equal(t, 2, aggregatedLogs[0].Count)
		require.Equal(t, now, aggregatedLogs[0].Timestamp)
		require.Equal(t, "/test", aggregatedLogs[0].Path)
		require.Equal(t, "1.1.1.1", aggregatedLogs[0].Destination.IP)
		require.Equal(t, int32(0), aggregatedLogs[0].Destination.PortNum)
	})
	t.Run("default aggregation - missing fields in one log", func(t *testing.T) {
		a, err := NewAggregator([]string{"rules"})
		require.NoError(t, err)

		now := time.Now()

		a.AddLog(&v1.WAFLog{
			Timestamp: now,
			Path:      "/test",
			// No source info for some obscure reason
			Rules: []v1.WAFRuleHit{
				{
					Id: "9992",
				},
				{
					Id: "9993",
				},
			},
			// No request id either (deep in edge case territory)
		})
		a.AddLog(&v1.WAFLog{
			Timestamp: now.Add(1 * time.Second),
			Path:      "/test",
			Source: &v1.WAFEndpoint{
				IP:      "1.1.1.1",
				PortNum: 1234,
			},
			Rules: []v1.WAFRuleHit{
				{
					Id: "9992",
				},
				{
					Id: "9993",
				},
			},
			RequestId: "2",
		})

		aggregatedLogs := a.EndAggregationPeriod()
		require.Len(t, aggregatedLogs, 1)
		require.Equal(t, 2, aggregatedLogs[0].Count)
		require.Equal(t, now, aggregatedLogs[0].Timestamp)
		require.Equal(t, "/test", aggregatedLogs[0].Path)
		// No source info for the first log, so we use aggregated values
		require.Equal(t, "-", aggregatedLogs[0].Source.IP)
		require.Equal(t, int32(0), aggregatedLogs[0].Source.PortNum)
		// RequestId is set to "-" since one log doesn't have it
		require.Equal(t, "-", aggregatedLogs[0].RequestId)
	})
}
