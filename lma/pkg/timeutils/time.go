// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
package timeutils

import (
	"errors"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// ParseTime parses a time that follows a loose elasticsearch format. Time may be specific in RFC 3339 format, or as
// "now - X" where X is a unit of time in either seconds (s), minutes (m), hours (h) or days (d).  The days is
// strictly speaking 24h and does not take into consideration daylight savings etc.
//
// Returns:
// - Calculated time
// - The query parameter:
//   - For relative time format "now-X" this returns the original string value
//   - Otherwise, it is parsed in RFC 3339 format and is returned as a Unix time, seconds since the epoch.
//
// If the query parameter is a string, then the time can be assumed to be a time relative to, and prior to "now".
func ParseTime(now time.Time, tstr *string) (*time.Time, any, error) {
	if tstr == nil || *tstr == "" {
		return nil, nil, nil
	}
	// Expecting times in RFC3999 format, or now-<duration> format. Try the latter first.
	parts := strings.SplitN(*tstr, "-", 2)
	if strings.TrimSpace(parts[0]) == "now" {
		log.Debug("Time is relative to now")

		// Make sure time is in UTC format.
		now = now.UTC()

		// Handle time string just being "now"
		if len(parts) == 1 {
			log.Debug("Time is now")
			return &now, *tstr, nil
		}

		// Time string has section after the subtraction sign. We currently support minutes (m), hours (h), days (d) and seconds (s).
		log.Debugf("Time string in now-x format; x=%s", parts[1])
		dur := strings.TrimSpace(parts[1])
		if dur == "0" {
			// 0 does not need units, so this also means now.
			log.Debug("Zero delta - time is now")
			return &now, *tstr, nil
		} else if len(dur) < 2 {
			// We need at least two values for the unit and the value
			log.Debug("Error parsing duration string, unrecognized unit of time")
			return nil, nil, errors.New("error parsing time in query - not a supported format")
		}

		// Last letter indicates the units.
		var mul time.Duration
		switch dur[len(dur)-1] {
		case 's':
			mul = time.Second
		case 'm':
			mul = time.Minute
		case 'h':
			mul = time.Hour
		case 'd':
			// A day isn't necessarily 24hr, but this should be a good enough approximation for now.
			//TODO(rlb): If we really want to support the ES date math format then this'll need more work.
			mul = 24 * time.Hour
		default:
			log.Debugf("Error parsing duration string, unrecognized unit of time: %s", dur)
			return nil, nil, errors.New("error parsing time in query - not a supported format")
		}

		// First digits indicates the multiplier.
		if val, err := strconv.ParseUint(strings.TrimSpace(dur[:len(dur)-1]), 10, 64); err != nil {
			log.WithError(err).Debugf("Error parsing duration string: %s", dur)
			return nil, nil, err
		} else {
			t := now.Add(-(time.Duration(val) * mul))
			return &t, *tstr, nil
		}
	}

	// Not now-X format, parse as RFC3339.
	if t, err := time.Parse(time.RFC3339, *tstr); err == nil {
		log.Debugf("Time is in a valid RFC3339 format: %s", *tstr)
		tutc := t.UTC()
		return &tutc, tutc.Unix(), nil
	} else {
		log.Debugf("Time format is not recognized: %s", *tstr)
		return nil, nil, err
	}
}
