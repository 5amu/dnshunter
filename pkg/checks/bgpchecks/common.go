// Package bgpchecks implements checks on the routing infrastructure of the
// domain: the networks hosting its nameservers and the addresses it points
// to, their RPKI/IRR registration and the autonomous systems announcing them.
package bgpchecks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/5amu/dnshunter/pkg/bgp"
	"github.com/5amu/dnshunter/pkg/core"
)

// ipTarget is an address to analyze and the roles it plays for the domain.
type ipTarget struct {
	IP    net.IP
	Roles []string
	p     *bgp.Profile
	err   error
}

func (t *ipTarget) subject() string {
	return fmt.Sprintf("%s (%s)", t.IP, strings.Join(t.Roles, ", "))
}

// collect returns the nameserver and/or domain addresses, deduplicated.
func collect(env *core.Env, nameservers, addresses bool) []*ipTarget {
	byIP := map[string]*ipTarget{}
	var out []*ipTarget
	add := func(ip net.IP, role string) {
		k := ip.String()
		if t, ok := byIP[k]; ok {
			t.Roles = append(t.Roles, role)
			return
		}
		t := &ipTarget{IP: ip, Roles: []string{role}}
		byIP[k] = t
		out = append(out, t)
	}
	if nameservers {
		for _, ns := range env.Target.Nameservers {
			for _, ip := range ns.IPs {
				add(ip, "nameserver "+ns.Name)
			}
		}
	}
	if addresses {
		for _, ip := range env.Target.Addresses {
			add(ip, "address of "+env.Target.AddressHost)
		}
	}
	return out
}

// profile resolves the routing profile of every target.
func profile(ctx context.Context, env *core.Env, ts []*ipTarget) {
	core.ParallelMap(ts, 8, func(t *ipTarget) struct{} {
		t.p, t.err = env.BGP.Profile(ctx, t.IP)
		return struct{}{}
	})
}

// route is a (prefix, origin AS) pair and the targets it carries.
type route struct {
	Prefix  string
	ASN     uint32
	ASName  string
	Members []*ipTarget
}

func (r *route) subject() string {
	return fmt.Sprintf("%s (AS%d)", r.Prefix, r.ASN)
}

func (r *route) members() string {
	var s []string
	for _, m := range r.Members {
		s = append(s, m.subject())
	}
	return "carries " + strings.Join(s, "; ")
}

// analyzable filters targets, reporting reserved, unrouted and provider
// addresses, and groups the remaining ones by route.
func analyzable(env *core.Env, r *core.Result, ts []*ipTarget) []*route {
	byKey := map[string]*route{}
	var out []*route
	var skipped []*ipTarget
	defer func() { r.Add(providerSkips(skipped)...) }()
	for _, t := range ts {
		switch {
		case t.p != nil && t.p.Reserved != "":
			r.Add(core.Skip(t.subject(), "not a public address: "+t.p.Reserved))
			continue
		case errors.Is(t.err, bgp.ErrNotRouted):
			r.Add(core.Fail(core.SeverityLow, t.subject(), "address is not announced in BGP: it is unreachable from the Internet"))
			continue
		case t.err != nil:
			r.Add(core.Errorf(t.subject(), "routing lookup failed: %v", t.err))
			continue
		case t.p.Provider != nil && !env.Opts.IncludeProviders:
			skipped = append(skipped, t)
			continue
		}
		for _, asn := range t.p.Origin.ASNs {
			key := fmt.Sprintf("%s|%d", t.p.Origin.Prefix, asn)
			rt, ok := byKey[key]
			if !ok {
				rt = &route{Prefix: t.p.Origin.Prefix, ASN: asn}
				if t.p.AS != nil && t.p.AS.ASN == asn {
					rt.ASName = t.p.AS.Name
				}
				byKey[key] = rt
				out = append(out, rt)
			}
			rt.Members = append(rt.Members, t)
		}
	}
	return out
}

// providerSkips reports addresses hosted by providers, one finding per
// provider AS.
func providerSkips(ts []*ipTarget) []core.Finding {
	var order []uint32
	byAS := map[uint32][]*ipTarget{}
	for _, t := range ts {
		asn := t.p.Origin.ASN()
		if _, ok := byAS[asn]; !ok {
			order = append(order, asn)
		}
		byAS[asn] = append(byAS[asn], t)
	}
	var out []core.Finding
	for _, asn := range order {
		group := byAS[asn]
		p := group[0].p
		subject := fmt.Sprintf("AS%d", asn)
		if p.AS != nil && p.AS.Name != "" {
			subject += " " + p.AS.Name
		}
		var details []string
		for _, t := range group {
			details = append(details, t.subject())
		}
		details = append(details, p.Provider.Reason, "use -include-providers to analyze provider networks anyway")
		noun := "address"
		if len(group) > 1 {
			noun = "addresses"
		}
		out = append(out, core.Skip(subject,
			fmt.Sprintf("%d %s hosted by %s (%s provider): shared infrastructure, not analyzed", len(group), noun, p.Provider.Name, p.Provider.Kind),
			details...))
	}
	return out
}

func asList(asns []uint32) string {
	sorted := append([]uint32(nil), asns...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var s []string
	for _, a := range sorted {
		s = append(s, fmt.Sprintf("AS%d", a))
	}
	return strings.Join(s, ", ")
}

func describeProfile(p *bgp.Profile) string {
	if p == nil || p.Origin == nil {
		return "unknown"
	}
	name := ""
	if p.AS != nil && p.AS.Name != "" {
		name = " " + p.AS.Name
	}
	s := fmt.Sprintf("AS%d%s, prefix %s", p.Origin.ASN(), name, p.Origin.Prefix)
	if p.Origin.Country != "" {
		s += ", registered in " + p.Origin.Country
	}
	return s
}

var errNoTargets = errors.New("no address to analyze")
