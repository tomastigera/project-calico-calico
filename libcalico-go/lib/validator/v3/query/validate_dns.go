// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package query

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/gopacket/layers"
)

var (
	dnsKeys = map[string]Validator{
		"start_time":        DateValidator,
		"end_time":          DateValidator,
		"count":             PositiveIntValidator,
		"client_name":       DomainValidator,
		"client_name_aggr":  DomainValidator,
		"client_namespace":  DomainValidator,
		"client_ip":         IPValidator,
		"host":              NullValidator,
		"latency_count":     PositiveIntValidator,
		"latency_max":       PositiveIntValidator,
		"latency_mean":      PositiveIntValidator,
		"servers.name":      DomainValidator,
		"servers.name_aggr": DomainValidator,
		"servers.namespace": DomainValidator,
		"servers.ip":        IPValidator,
		"qname":             DomainValidator,
		"qtype":             DNSTypeValidator,
		"qclass":            NullValidator,
		"rcode":             NullValidator,
		"rrsets.name":       DomainValidator,
		"rrsets.type":       DNSTypeValidator,
		"rrsets.class":      NullValidator,
		"rrsets.rdata":      NullValidator,
	}

	dnsWildcardKeys = map[string]Validator{
		"client_labels.":  NullValidator,
		"servers.labels.": NullValidator,
	}
)

var dnsTypeStringValidator = SetValidator(
	layers.DNSTypeA.String(),
	layers.DNSTypeNS.String(),
	layers.DNSTypeMD.String(),
	layers.DNSTypeMF.String(),
	layers.DNSTypeCNAME.String(),
	layers.DNSTypeSOA.String(),
	layers.DNSTypeMB.String(),
	layers.DNSTypeMG.String(),
	layers.DNSTypeMR.String(),
	layers.DNSTypeNULL.String(),
	layers.DNSTypeWKS.String(),
	layers.DNSTypePTR.String(),
	layers.DNSTypeHINFO.String(),
	layers.DNSTypeMINFO.String(),
	layers.DNSTypeMX.String(),
	layers.DNSTypeTXT.String(),
	layers.DNSTypeAAAA.String(),
	layers.DNSTypeSRV.String(),
)

func DNSTypeValidator(a *Atom) error {
	if regexp.MustCompile(`^#\d+$`).MatchString(a.Value) {
		return nil
	}

	return dnsTypeStringValidator(a)
}

func IsValidDNSAtom(a *Atom) error {
	if validator, ok := dnsKeys[a.Key]; ok {
		return validator(a)
	}

	for prefix, validator := range dnsWildcardKeys {
		if strings.HasPrefix(a.Key, prefix) {
			return validator(a)
		}
	}

	return fmt.Errorf("invalid key: %s", a.Key)
}
