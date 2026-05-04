// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_connreject

package tstun

import (
	"tailscale.com/net/connreject"
	"tailscale.com/net/packet"
)

// SetConnRejectNote installs a callback that is invoked when the Wrapper
// emits an outbound TSMP reject for an inbound peer connection that was
// dropped by the packet filter. The callback receives a fully populated
// [connreject.Event] of [connreject.Incoming] direction.
//
// A nil fn unsets any previously installed callback. Typically called
// once at startup by the connreject feature extension.
func (t *Wrapper) SetConnRejectNote(fn func(connreject.Event)) {
	if fn == nil {
		t.connRejectNote.Store((func(connreject.Event))(nil))
		return
	}
	t.connRejectNote.Store(fn)
}

// notifyConnRejectTSMPSent delivers an Incoming-direction event to the
// installed callback, if any, derived from a TSMP reject we just
// injected outbound.
func (t *Wrapper) notifyConnRejectTSMPSent(rj packet.TailscaleRejectedHeader) {
	v := t.connRejectNote.Load()
	if v == nil {
		return
	}
	fn, _ := v.(func(connreject.Event))
	if fn == nil {
		return
	}
	reason := connreject.ReasonACL
	if rj.Reason == packet.RejectedDueToShieldsUp {
		reason = connreject.ReasonShields
	}
	fn(connreject.Event{
		Direction: connreject.Incoming,
		Proto:     rj.Proto,
		Src:       rj.Src,
		Dst:       rj.Dst,
		Reason:    reason,
		Source:    connreject.SourceTSMPSent,
	})
}
