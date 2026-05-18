// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
)

const AppConnectorsExperimentalAttrName = "tailscale.com/app-connectors-experimental"

func isPeerEligibleConnector(peer tailcfg.NodeView) bool {
	if !peer.Valid() || !peer.Hostinfo().Valid() {
		return false
	}
	isConn, _ := peer.Hostinfo().AppConnector().Get()
	return isConn
}

func sortByPreference(ns []tailcfg.NodeView) {
	// The ordering of the nodes is semantic (callers use the first node they can
	// get a peer api url for). We don't (currently 2026-02-27) have any
	// preference over which node is chosen as long as it's consistent.  In the
	// future we anticipate integrating with traffic steering.
	slices.SortFunc(ns, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
}

// PickConnector returns peers the backend knows about that match the app, in order of preference to use as
// a connector.
func PickConnector(nb ipnext.NodeBackend, app appctype.Conn25Attr) []tailcfg.NodeView {
	appTagsSet := set.SetOf(app.Connectors)
	matches := nb.AppendMatchingPeers(nil, func(n tailcfg.NodeView) bool {
		if !isPeerEligibleConnector(n) {
			return false
		}
		for _, t := range n.Tags().All() {
			if appTagsSet.Contains(t) {
				return true
			}
		}
		return false
	})
	sortByPreference(matches)
	return matches
}

// DNSAddrScheme is the custom URI scheme used for conn25-managed split DNS
// entries to determine the destination at query time rather than configuration
// time.
const DNSAddrScheme = "tailscale-app"

func AppDNSRoutes(hasCap func(c tailcfg.NodeCapability) bool, self tailcfg.NodeView, advertiseConnectorPref bool) map[string][]*dnstype.Resolver {
	if !hasCap(AppConnectorsExperimentalAttrName) {
		return nil
	}
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](self.CapMap(), AppConnectorsExperimentalAttrName)
	if err != nil {
		return nil
	}

	toDomain := func(s string) (dnsname.FQDN, error) {
		domain, _ := strings.CutPrefix(s, "*.")
		domain = strings.ToLower(domain)
		return dnsname.ToFQDN(domain)
	}

	// Routes we return will make tailscale attempt to get the OS to send tailscale
	// dns queries for the domains, and any subdomains.
	//
	// If we are a connector for a domain, we want the OS to handle the dns query,
	// so we want to avoid returning routes for any domain or ancestor domain of any of
	// the domains we are a connector for.
	//
	// ie if we are a connector for b.example.com, we want to avoid routes for
	// example.com and b.example.com but a.b.example.com is ok.
	var selfRoutedDomains []dnsname.FQDN
	isSelfRouted := func(d dnsname.FQDN) bool {
		for _, existing := range selfRoutedDomains {
			if d.Contains(existing) {
				return true
			}
		}
		return false
	}
	if advertiseConnectorPref {
		// Populate selfRoutedDomains.
		selfTags := set.SetOf(self.Tags().AsSlice())
		for _, app := range apps {
			for _, tag := range app.Connectors {
				if selfTags.Contains(tag) {
					// This node connects for this app.
					for _, domain := range app.Domains {
						if d, err := toDomain(domain); err == nil {
							selfRoutedDomains = append(selfRoutedDomains, d)
						}
					}
				}
			}
		}
	}

	appNamesByDomain := map[dnsname.FQDN]string{}
	for _, app := range apps {
		for _, domain := range app.Domains {
			if d, err := toDomain(domain); err == nil {
				if !isSelfRouted(d) {
					// in the case of multiple apps specifying the same domain (which is misconfiguration
					// that should be validated at point of input) last write wins.
					appNamesByDomain[d] = app.Name
				}
			}
		}
	}
	m := make(map[string][]*dnstype.Resolver, len(appNamesByDomain))
	for domain, appName := range appNamesByDomain {
		m[domain.WithoutTrailingDot()] = []*dnstype.Resolver{{Addr: fmt.Sprintf("%s:%s", DNSAddrScheme, appName)}}
	}
	return m
}
