// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package transaction

import (
	"fmt"

	corazatypes "github.com/corazawaf/coraza/v3/types"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

func codeAndMessageFromInterruption(it *corazatypes.Interruption) (envoy_type_v3.StatusCode, string) {
	switch it.Action {
	// We only handle disruptive actions here.
	// However, not all disruptive actions mean a change in response code. See below:
	// - drop Initiates an immediate close of the TCP connection by sending a FIN packet.
	// - deny Stops rule processing and intercepts transaction.
	// - block Performs the disruptive action defined by the previous SecDefaultAction.
	// - pause Pauses transaction processing for the specified number of milliseconds. We don't support this, yet.
	// - proxy Intercepts the current transaction by forwarding the request to another web server using the proxy backend.
	// 		The forwarding is carried out transparently to the HTTP client (i.e., there’s no external redirection taking place)
	// - redirect Intercepts transaction by issuing an external (client-visible) redirection to the given location
	//
	// for more info about actions: https://coraza.io/docs/seclang/actions/ and note the Action Group for each.
	case "allow":
		// default response code is OK, do nothing but return OK
	case "drop", "deny", "block":
		return envoy_type_v3.StatusCode_Forbidden, messageFromInterruption(it)
	case "pause", "proxy", "redirect":
		// these are non-disruptive actions, so we return OK but the message is the action data for the next processing step
		return envoy_type_v3.StatusCode_PermanentRedirect, it.Data
	default:
		// all other actions should be non-disruptive. Do nothing but return OK
	}
	return envoy_type_v3.StatusCode_OK, ""
}

func messageFromInterruption(it *corazatypes.Interruption) string {
	return fmt.Sprintf("WAF rule %d interrupting request: %s (%d)", it.RuleID, it.Action, it.Status)
}
