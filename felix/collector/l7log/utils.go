// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

package l7log

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/utils"
)

func newMetaSpecFromUpdate(update Update, ak AggregationKind) (L7Meta, L7Spec, error) {
	meta := L7Meta{
		ResponseCode:     update.ResponseCode,
		RouteName:        update.RouteName,
		GatewayName:      update.GatewayName,
		Protocol:         update.Protocol,
		Method:           update.Method,
		Domain:           update.Domain,
		Path:             update.Path,
		UserAgent:        update.UserAgent,
		Type:             update.Type,
		ServiceName:      update.ServiceName,
		ServiceNamespace: update.ServiceNamespace,
		ServicePortName:  update.ServicePortName,
		ServicePortNum:   update.ServicePortNum,

		// Gateway API enrichment fields
		GatewayNamespace:     update.GatewayNamespace,
		GatewayClass:         update.GatewayClass,
		GatewayStatus:        update.GatewayStatus,
		GatewayStatusMessage: update.GatewayStatusMessage,

		// Gateway listener context fields
		GatewayListenerName:     update.GatewayListenerName,
		GatewayListenerPort:     update.GatewayListenerPort,
		GatewayListenerProtocol: update.GatewayListenerProtocol,
		GatewayListenerFullName: update.GatewayListenerFullName,
		GatewayListenerHostname: update.GatewayListenerHostname,

		// Route resource identification
		RouteNamespace:    update.RouteNamespace,
		RouteResourceName: update.RouteResourceName,
		RouteType:         update.RouteType,

		// Gateway route context fields
		GatewayRouteType:          update.GatewayRouteType,
		GatewayRouteName:          update.GatewayRouteName,
		GatewayRouteNamespace:     update.GatewayRouteNamespace,
		GatewayRouteHostname:      update.GatewayRouteHostname,
		GatewayRouteStatus:        update.GatewayRouteStatus,
		GatewayRouteStatusMessage: update.GatewayRouteStatusMessage,
	}

	// Get source endpoint metadata
	srcMeta, err := endpoint.GetMetadata(update.SrcEp, update.Tuple.Src)
	if err != nil {
		log.WithError(err).Errorf("Failed to extract metadata for source %v", update.SrcEp)
	}

	// Get destination endpoint metadata
	dstMeta, err := endpoint.GetMetadata(update.DstEp, update.Tuple.Dst)
	if err != nil {
		log.WithError(err).Errorf("Failed to extract metadata for destination %v", update.DstEp)
	}

	meta.SrcNameAggr = srcMeta.AggregatedName
	meta.SrcNamespace = srcMeta.Namespace
	meta.SourcePortNum = update.Tuple.L4Src

	meta.DestNameAggr = dstMeta.AggregatedName
	meta.DestNamespace = dstMeta.Namespace
	meta.DestPortNum = update.Tuple.L4Dst

	meta.SrcType = srcMeta.Type
	meta.DestType = dstMeta.Type

	// If we have a service and the service namespace has not been set, default it to the destination namespace.
	if meta.ServiceName != "" && meta.ServiceNamespace == "" {
		meta.ServiceNamespace = dstMeta.Namespace
	}

	// Handle aggregation and remove any unneeded values.
	if ak.HTTPHeader == HTTPHeaderInfoNone {
		meta.UserAgent = utils.FieldNotIncluded
		meta.Type = utils.FieldNotIncluded
	}

	if ak.HTTPMethod == HTTPMethodNone {
		meta.Method = utils.FieldNotIncluded
	}

	if ak.Service == ServiceInfoNone {
		meta.ServiceName = utils.FieldNotIncluded
		meta.ServiceNamespace = utils.FieldNotIncluded
		meta.ServicePortName = utils.FieldNotIncluded
		meta.ServicePortNum = 0
	}

	if ak.Destination == DestinationInfoNone {
		meta.DestNameAggr = utils.FieldNotIncluded
		meta.DestNamespace = utils.FieldNotIncluded
		meta.DestType = utils.FieldNotIncluded
		meta.DestPortNum = 0
	}

	if ak.ResponseCode == ResponseCodeNone {
		meta.ResponseCode = utils.FieldNotIncluded
	}

	switch ak.Source {
	case SourceInfoNone:
		meta.SrcNameAggr = utils.FieldNotIncluded
		meta.SrcNamespace = utils.FieldNotIncluded
		meta.SrcType = utils.FieldNotIncluded
		meta.SourcePortNum = 0
	case SourceInfoNoPort:
		meta.SourcePortNum = 0
	}

	switch ak.TrimURL {
	case FullURL:
		// If the whole URL is specified, trim the path if required.
		if ak.NumURLPathParts >= 0 {
			// Remove the query portion of the URL
			path := strings.Split(update.Path, "?")[0]

			// Split the path into components and only grab the specified number of components.
			parts := strings.Split(path, "/")
			// Since the Path is expected to lead with "/", parts
			// will be 1 longer than the valid parts of the path.
			if len(parts) > ak.NumURLPathParts+1 {
				trimmed := []string{}
				i := 0
				for i < ak.NumURLPathParts+1 {
					trimmed = append(trimmed, parts[i])
					i++
				}
				parts = trimmed
			}
			meta.Path = strings.Join(parts, "/")
		}
	case URLWithoutQuery:
		// Trim path of query params
		meta.Path = strings.Split(meta.Path, "?")[0]
	case BaseURL:
		// Remove path
		meta.Path = utils.FieldNotIncluded
	case URLNone:
		// Remove the URL entirely
		meta.Domain = utils.FieldNotIncluded
		meta.Path = utils.FieldNotIncluded
	}
	// once the processing is done eventually make sure URL length is manageable
	limitURLLength(&meta, ak.URLCharLimit)
	spec := L7Spec{
		Duration:      update.Duration,
		DurationMax:   update.DurationMax,
		BytesReceived: update.BytesReceived,
		BytesSent:     update.BytesSent,
		Latency:       update.Latency,
		Count:         update.Count,
	}

	return meta, spec, nil
}

func limitURLLength(meta *L7Meta, limit int) {
	// when the URL exceeds a configured limit, trim it down to manageable length
	if len(meta.Domain)+len(meta.Path) > limit {
		// path length that is permissible
		maxPath := limit - len(meta.Domain)
		if maxPath < 0 {
			// in this case we don't send the path at all and we limit domain to limit
			meta.Domain = meta.Domain[0:limit]
			meta.Path = utils.FieldNotIncluded
		} else {
			meta.Path = meta.Path[0:maxPath]
		}
	}
}
