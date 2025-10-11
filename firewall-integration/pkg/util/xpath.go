// Copyright 2019 Tigera Inc. All rights reserved.

package util

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"time"

	panw "github.com/PaloAltoNetworks/pango"
	log "github.com/sirupsen/logrus"
)

const (
	PanwTimestampFormat = "2006/01/02 15:04:05"
)

// Request/Response format to get audit config.
type AuditConfigRequest struct {
	XMLName xml.Name `xml:"show"`
	Val     string   `xml:"config>audit>info"`
}

type AuditConfigResponse struct {
	Entries []AuditConfigResponseEntry `xml:"result>entry"`
}

type AuditConfigResponseEntry struct {
	Order       string `xml:"name,attr"`
	Timestamp   string `xml:"timestamp"`
	Admin       string `xml:"admin"`
	Description string `xml:"description"`
}

// Response format to get pre-defined security rules.
type PredefinedSecurityRulesResponse struct {
	Rules []PredefinedSecurityRules `xml:"result>default-security-rules>rules>entry"`
}
type PredefinedSecurityRules struct {
	Name   string `xml:"name,attr"`
	Action string `xml:"action"`
}

func GetPredefinedDefaultSecurityRules(p *panw.Panorama, testDg string) (map[string]string, error) {
	var response PredefinedSecurityRulesResponse
	preDefRuleMap := make(map[string]string)

	if _, err := p.Get("/config/predefined/default-security-rules", nil, &response); err != nil {
		log.WithError(err).Error("error reading pre-defined default rules.")
		return preDefRuleMap, err
	}
	log.Infof("pre-defined default rules(response): %v", response)
	for _, r := range response.Rules {
		preDefRuleMap[r.Name] = r.Action
	}

	xp := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/post-rulebase/default-security-rules", testDg)
	if _, err := p.Get(xp, nil, &response); err != nil {
		log.Infof("No device-group pre-defined security rules.")
		// No error needed, move to the next step.
	} else {
		log.Infof("device-group predefined rules(response): %v", response)
	}
	for _, r := range response.Rules {
		preDefRuleMap[r.Name] = r.Action
	}

	if _, err := p.Get("/config/shared/post-rulebase/default-security-rules", nil, &response); err != nil {
		log.Infof("No shared pre-defined security rules.")
	} else {
		log.Infof("shared overridden default rules(response): %v", response)
	}
	for _, r := range response.Rules {
		preDefRuleMap[r.Name] = r.Action
	}

	log.Infof("pre-defined rule map: %v", preDefRuleMap)
	return preDefRuleMap, nil
}

// Get the config audit detailing when was the last config committed.
// pango doesn't support all *op* type commands. This helper function helps

func GetLatestConfigTimestamp(p *panw.Panorama) (int64, error) {
	var (
		timestamp int64
		request   AuditConfigRequest
		response  AuditConfigResponse
	)

	if _, err := p.Op(request, "", nil, &response); err != nil {
		return timestamp, err
	}

	if len(response.Entries) == 0 {
		log.Infof("No committed configuration found.")
		// while this is odd and shouldn't happen for a Panorama with valid
		// configuration to import, do not raise an error and let the fetching
		// check if there are any rules to import.
		return timestamp, nil
	}

	// Panorama response may not be guaranteed sorted.
	entry := response.Entries[0]
	ts := entry.Timestamp
	origOrder, _ := strconv.ParseInt(entry.Order, 10, 32)
	for _, e := range response.Entries {
		newOrder, _ := strconv.ParseInt(e.Order, 10, 32)

		if newOrder > origOrder {
			ts = e.Timestamp
			log.Infof("ts: %s", ts)
		}
	}

	return getUnixTimestampFromCustomTimestamp(ts), nil
}

func getUnixTimestampFromCustomTimestamp(timestamp string) int64 {
	if timestamp == "" {
		log.Infof("timestamp: %s", timestamp)
		return 0
	}
	t, err := time.Parse(PanwTimestampFormat, timestamp)
	if err != nil {
		log.Infof("timestamp: %s, t: %v", timestamp, t)
		return int64(0)
	}

	return t.Unix()
}
