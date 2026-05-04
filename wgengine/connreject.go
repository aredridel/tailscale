// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug && !ts_omit_connreject

package wgengine

import (
	"tailscale.com/net/connreject"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
)

// SetConnRejectNote installs a callback invoked when the engine observes
// an outbound-direction connection rejection (an inbound TSMP reject
// from a peer or a pendopen timeout). Passing nil uninstalls a
// previously installed callback.
//
// SetConnRejectNote is typically called once at startup by the
// [tailscale.com/feature/connreject] extension. It is not declared on
// the [Engine] interface; callers structurally type-assert for it (see
// feature/connreject) so that ts_omit_connreject builds do not pull in
// tailscale.com/net/connreject.
func (e *userspaceEngine) SetConnRejectNote(fn func(connreject.Event)) {
	if fn == nil {
		e.connRejectNote.Store((func(connreject.Event))(nil))
		return
	}
	e.connRejectNote.Store(fn)
}

// loadConnRejectNote returns the installed callback, or nil if none.
func (e *userspaceEngine) loadConnRejectNote() func(connreject.Event) {
	v := e.connRejectNote.Load()
	if v == nil {
		return nil
	}
	fn, _ := v.(func(connreject.Event))
	return fn
}

// notifyConnRejectTSMPRecv emits an Outgoing-direction event derived
// from an inbound TSMP rejected header, if a callback is installed.
func (e *userspaceEngine) notifyConnRejectTSMPRecv(rh packet.TailscaleRejectedHeader) {
	fn := e.loadConnRejectNote()
	if fn == nil {
		return
	}
	fn(connreject.Event{
		Direction:   connreject.Outgoing,
		Proto:       rh.Proto,
		Src:         rh.Src,
		Dst:         rh.Dst,
		Reason:      rejectReasonToReason(rh.Reason),
		Source:      connreject.SourceTSMPRecv,
		MaybeBroken: rh.MaybeBroken,
	})
}

// notifyConnRejectOpenTimeout classifies a pendopen-timeout diagnosis
// and emits an Outgoing-direction event, if a callback is installed and
// the classification is not deliberately suppressed (see
// [classifyOpenTimeout]).
func (e *userspaceEngine) notifyConnRejectOpenTimeout(flow flowtrack.Tuple, d openTimeoutDiag) {
	fn := e.loadConnRejectNote()
	if fn == nil {
		return
	}
	reason, source := classifyOpenTimeout(d)
	if reason == "" {
		return
	}
	fn(connreject.Event{
		Direction: connreject.Outgoing,
		Proto:     flow.Proto(),
		Src:       flow.Src(),
		Dst:       flow.Dst(),
		Reason:    reason,
		Source:    source,
	})
}

// classifyOpenTimeout maps an [openTimeoutDiag] to a [connreject.Reason]
// and [connreject.Source] for emission. A returned reason of "" means
// the caller should not emit any event (used for the deliberately-silent
// onlyZeroRoute case).
//
// If d.problem is set, the peer's TSMP-reported reason supersedes our
// own diagnosis and the event is tagged SourceTSMPRecv (the timeout
// confirms the previously non-terminal reject was actually terminal).
func classifyOpenTimeout(d openTimeoutDiag) (connreject.Reason, connreject.Source) {
	if d.onlyZeroRoute {
		return "", connreject.SourceUnknown
	}
	if !d.problem.IsZero() {
		return rejectReasonToReason(d.problem), connreject.SourceTSMPRecv
	}
	switch {
	case d.noPeer:
		return connreject.ReasonNoPeer, connreject.SourcePendOpenTimeout
	case d.peerUnreachable:
		return connreject.ReasonPeerUnreachable, connreject.SourcePendOpenTimeout
	}
	return connreject.ReasonTimeout, connreject.SourcePendOpenTimeout
}

// rejectReasonToReason maps a [packet.TailscaleRejectReason] to its
// corresponding [connreject.Reason] tag.
func rejectReasonToReason(r packet.TailscaleRejectReason) connreject.Reason {
	switch r {
	case packet.RejectedDueToACLs:
		return connreject.ReasonACL
	case packet.RejectedDueToShieldsUp:
		return connreject.ReasonShields
	case packet.RejectedDueToIPForwarding:
		return connreject.ReasonHostIPForwarding
	case packet.RejectedDueToHostFirewall:
		return connreject.ReasonHostFirewall
	}
	return connreject.ReasonUnknown
}
