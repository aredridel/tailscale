// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_connreject

package tstun

import "tailscale.com/net/packet"

// notifyConnRejectTSMPSent is a no-op when the connreject feature is
// omitted at build time.
func (t *Wrapper) notifyConnRejectTSMPSent(packet.TailscaleRejectedHeader) {}
