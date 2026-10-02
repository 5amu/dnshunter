package dnschecks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/miekg/dns"
)

// Delegation verifies the health of the delegation: number of nameservers,
// consistency between parent and child, lame servers, dangling nameserver
// names and network diversity.
var Delegation = &core.Check{
	ID:       "ns",
	Aliases:  []string{"delegation", "lame"},
	Name:     "Nameserver delegation",
	Category: core.CategoryDNS,
	Description: "A healthy delegation has at least two nameservers on different networks, the same NS " +
		"set at the parent and in the zone, and every nameserver answering authoritatively. Lame or " +
		"dangling nameservers degrade availability and, when the nameserver domain can be registered by " +
		"anyone, allow an attacker to take over the zone.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc1034#section-4.1",
		"https://www.rfc-editor.org/rfc/rfc2182#section-3.1",
		"https://www.rfc-editor.org/rfc/rfc8499#section-7",
	},
	Run: runDelegation,
}

func runDelegation(ctx context.Context, env *core.Env, r *core.Result) error {
	t := env.Target
	zone := t.Zone

	if n := len(t.Nameservers); n < 2 {
		r.Add(core.Fail(core.SeverityMedium, zone, fmt.Sprintf("only %d nameserver: at least 2 are required (RFC 1034)", n),
			"a single nameserver is a single point of failure for the whole domain"))
	} else {
		r.Add(core.Pass(zone, fmt.Sprintf("%d nameservers: %s", n, strings.Join(t.NameserverNames(), ", "))))
	}

	// Nameservers whose name does not resolve.
	for _, ns := range t.Nameservers {
		if len(ns.IPs) > 0 {
			continue
		}
		r.Add(danglingNS(ctx, env, ns.Name, ns.Error))
	}

	// Parent / child consistency.
	if d := t.Delegation; d != nil {
		onlyParent, onlyChild := diffSets(d.NS, t.NameserverNames())
		if len(onlyParent)+len(onlyChild) > 0 {
			var details []string
			if len(onlyParent) > 0 {
				details = append(details, fmt.Sprintf("only at the parent (%s): %s", d.Parent, strings.Join(onlyParent, ", ")))
			}
			if len(onlyChild) > 0 {
				details = append(details, fmt.Sprintf("only in the zone: %s", strings.Join(onlyChild, ", ")))
			}
			r.Add(core.Fail(core.SeverityLow, zone, "NS records at the parent and in the zone differ", details...).
				WithPoC("dig NS %s +norecurse @%s; dig NS %s @%s", zone, d.Server, zone, t.NameserverNames()[0]))
			for _, ns := range onlyParent {
				if ips, err := env.DNS.LookupIPs(ctx, ns); err != nil || len(ips) == 0 {
					r.Add(danglingNS(ctx, env, ns, "delegated by the parent but does not resolve"))
				}
			}
		} else {
			r.Add(core.Pass(zone, fmt.Sprintf("NS set at the parent (%s) matches the zone", d.Parent)))
		}
	} else if t.DelegationErr != "" {
		r.Add(core.Errorf(zone, "could not obtain the delegation from the parent zone: %s", t.DelegationErr))
	}

	// Lame delegation: every server must answer authoritatively.
	for _, a := range queryAll(ctx, env, zone, dns.TypeSOA) {
		poc := digAt(a.ep, "SOA "+zone+" +norecurse")
		switch {
		case a.err != nil:
			r.Add(core.Fail(core.SeverityMedium, a.ep.String(), "nameserver does not answer", a.err.Error()).WithPoC("%s", poc))
		case a.msg.Rcode != dns.RcodeSuccess:
			r.Add(core.Fail(core.SeverityMedium, a.ep.String(), fmt.Sprintf("lame delegation: nameserver answers %s for the zone", rcode(a.msg))).WithPoC("%s", poc))
		case !a.msg.Authoritative:
			r.Add(core.Fail(core.SeverityMedium, a.ep.String(), "lame delegation: answer is not authoritative (AA flag not set)").WithPoC("%s", poc))
		default:
			r.Add(core.Pass(a.ep.String(), "answers authoritatively"))
		}
	}

	// Network diversity (RFC 2182 §3.1): IPv4 /24 and IPv6 /48 networks.
	nets := map[string]bool{}
	var v4, v6 int
	resolved := 0
	for _, ns := range t.Nameservers {
		if len(ns.IPs) > 0 {
			resolved++
		}
		for _, ip := range ns.IPs {
			if ip4 := ip.To4(); ip4 != nil {
				v4++
				nets[ip4.Mask(net.CIDRMask(24, 32)).String()+"/24"] = true
			} else {
				v6++
				nets[ip.Mask(net.CIDRMask(48, 128)).String()+"/48"] = true
			}
		}
	}
	switch {
	case len(t.Nameservers) < 2 || resolved < len(t.Nameservers):
		// Not enough data to judge the diversity.
	case len(nets) == 1:
		for subnet := range nets {
			r.Add(core.Fail(core.SeverityLow, zone, "all nameservers are in the same network",
				fmt.Sprintf("%s hosts every nameserver: a single network outage takes the domain offline (RFC 2182)", subnet)))
		}
	default:
		r.Add(core.Pass(zone, fmt.Sprintf("nameservers are spread over %d different networks (/24 for IPv4, /48 for IPv6)", len(nets))))
	}
	if v4 > 0 && v6 == 0 {
		r.Add(core.Info(zone, "no nameserver is reachable over IPv6"))
	}
	return nil
}

// danglingNS reports a nameserver whose name does not resolve, escalating when
// its domain is not even registered (anyone could register it and take over
// the zone).
func danglingNS(ctx context.Context, env *core.Env, ns, reason string) core.Finding {
	reg := dnsutil.OrgDomain(ns)
	m, err := env.DNS.Lookup(ctx, reg, dns.TypeNS)
	if err == nil && m.Rcode == dns.RcodeNameError {
		return core.Fail(core.SeverityHigh, ns, fmt.Sprintf("nameserver domain %s is not registered: the delegation can be hijacked", reg),
			"anyone registering "+reg+" can answer for the zone (nameserver takeover)").
			WithPoC("dig NS %s; whois %s", reg, reg)
	}
	return core.Fail(core.SeverityMedium, ns, "nameserver name does not resolve to any address", reason)
}

func diffSets(a, b []string) (onlyA, onlyB []string) {
	inB := map[string]bool{}
	for _, x := range b {
		inB[x] = true
	}
	inA := map[string]bool{}
	for _, x := range a {
		inA[x] = true
		if !inB[x] {
			onlyA = append(onlyA, x)
		}
	}
	for _, x := range b {
		if !inA[x] {
			onlyB = append(onlyB, x)
		}
	}
	return onlyA, onlyB
}
