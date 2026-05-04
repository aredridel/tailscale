// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package local

import "context"

// DebugRejects returns the raw JSON body of the node's aggregated
// connection-rejection diagnostics, as served by the debug-rejects
// LocalAPI endpoint. Callers that want a typed response can decode the
// returned bytes into [tailscale.com/net/connreject.DebugRejectsResponse].
//
// The response body is returned as opaque bytes so that the
// tailscale.com/net/connreject package is not pulled into builds (such
// as the tailscale CLI) that don't need the typed struct.
//
// The feature is gated at runtime by [tailcfg.NodeAttrConnReject]; when
// that attribute is not set on the node, the JSON object's Enabled
// field is false and its Outgoing/Incoming arrays are empty.
func (lc *Client) DebugRejects(ctx context.Context) ([]byte, error) {
	return lc.get200(ctx, "/localapi/v0/debug-rejects")
}
