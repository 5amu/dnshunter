package bgpchecks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/5amu/dnshunter/pkg/bgp"
	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
)

// ASN profiles the autonomous systems announcing the addresses the domain
// points to, skipping cloud/CDN/hosting provider networks.
var ASN = &core.Check{
	ID:       "asn",
	Name:     "ASN of the domain addresses",
	Category: core.CategoryBGP,
	Description: "Identifies the autonomous system (AS) announcing every address the domain points to. " +
		"Addresses in cloud, CDN or hosting provider networks are reported and skipped, as their AS is " +
		"shared infrastructure outside the domain owner's control. For the other networks the AS is " +
		"profiled: holder and likely ownership, upstream redundancy, BGP visibility, multiple-origin " +
		"announcements, IRR and RPKI coverage of its prefixes and abuse contact.",
	References: []string{
		"https://www.manrs.org/netops/",
		"https://www.rfc-editor.org/rfc/rfc7454",
		"https://stat.ripe.net/docs/data-api/",
	},
	Run: runASN,
}

// asGroup gathers the domain addresses announced by the same AS.
type asGroup struct {
	asn      uint32
	info     *bgp.ASInfo
	targets  []*ipTarget
	prefixes []string
}

func runASN(ctx context.Context, env *core.Env, r *core.Result) error {
	t := env.Target
	ts := collect(env, false, true)
	if len(ts) == 0 {
		r.Add(core.Info(t.Domain, "the domain has no A/AAAA record: nothing to analyze"))
		return nil
	}
	profile(ctx, env, ts)

	groups := map[uint32]*asGroup{}
	var order []uint32
	var skipped []*ipTarget
	for _, it := range ts {
		switch {
		case it.p != nil && it.p.Reserved != "":
			r.Add(core.Fail(core.SeverityLow, it.subject(),
				"the domain resolves to a non-public address: "+it.p.Reserved,
				"internal addressing is disclosed and clients outside the network cannot reach the service").
				WithPoC("dig A %s +short; dig AAAA %s +short", t.AddressHost, t.AddressHost))
			continue
		case errors.Is(it.err, bgp.ErrNotRouted):
			r.Add(core.Fail(core.SeverityLow, it.subject(), "the address is not announced in BGP: it is unreachable from the Internet"))
			continue
		case it.err != nil:
			r.Add(core.Errorf(it.subject(), "routing lookup failed: %v", it.err))
			continue
		}
		r.Add(core.Info(it.subject(), describeProfile(it.p)))
		if it.p.Provider != nil && !env.Opts.IncludeProviders {
			skipped = append(skipped, it)
			continue
		}
		asn := it.p.Origin.ASN()
		g, ok := groups[asn]
		if !ok {
			g = &asGroup{asn: asn, info: it.p.AS}
			groups[asn] = g
			order = append(order, asn)
		}
		g.targets = append(g.targets, it)
		if !contains(g.prefixes, it.p.Origin.Prefix) {
			g.prefixes = append(g.prefixes, it.p.Origin.Prefix)
		}
		if len(it.p.Origin.ASNs) > 1 && env.BGP.Stat == nil {
			r.Add(core.Fail(core.SeverityMedium, it.subject(),
				fmt.Sprintf("prefix %s is announced by multiple origin ASes (%s)", it.p.Origin.Prefix, asList(it.p.Origin.ASNs)),
				"multiple-origin (MOAS) announcements can be legitimate (anycast, migrations) but are also the signature of a prefix hijack"))
		}
	}

	r.Add(providerSkips(skipped)...)

	findings := core.ParallelMap(order, 2, func(asn uint32) []core.Finding {
		return analyzeAS(ctx, env, groups[asn])
	})
	for _, f := range findings {
		r.Add(f...)
	}
	return nil
}

func analyzeAS(ctx context.Context, env *core.Env, g *asGroup) []core.Finding {
	subject := fmt.Sprintf("AS%d", g.asn)
	var out []core.Finding
	add := func(f ...core.Finding) { out = append(out, f...) }

	add(asProfile(ctx, env, g))
	add(upstreams(ctx, env, g))

	stat := env.BGP.Stat
	if stat == nil {
		add(core.Info(subject, "RIPEstat is disabled: BGP visibility, IRR and RPKI coverage of the AS were not analyzed"))
		return out
	}
	for _, prefix := range g.prefixes {
		add(visibility(ctx, env, g, prefix)...)
	}
	add(irrCoverage(ctx, env, g))
	add(rpkiCoverage(ctx, env, g))
	add(abuseContact(ctx, env, g))
	return out
}

func asProfile(ctx context.Context, env *core.Env, g *asGroup) core.Finding {
	subject := fmt.Sprintf("AS%d", g.asn)
	name := ""
	var details []string
	if g.info != nil {
		name = g.info.Name
		if g.info.Name != "" {
			details = append(details, "holder: "+g.info.Name)
		}
		var reg []string
		if g.info.Country != "" {
			reg = append(reg, "country "+g.info.Country)
		}
		if g.info.Registry != "" {
			reg = append(reg, "registry "+strings.ToUpper(g.info.Registry))
		}
		if g.info.Allocated != "" {
			reg = append(reg, "allocated "+g.info.Allocated)
		}
		if len(reg) > 0 {
			details = append(details, "registration: "+strings.Join(reg, ", "))
		}
	}
	for _, t := range g.targets {
		details = append(details, fmt.Sprintf("announces %s via %s", t.IP, t.p.Origin.Prefix))
	}
	if env.BGP.Stat != nil && len(g.targets) > 0 {
		if netname := networkName(ctx, env, g.targets[0].IP); netname != "" {
			details = append(details, "network registered to: "+netname)
		}
	}
	details = append(details, ownership(env.Target.Domain, name))
	title := subject
	if name != "" {
		title += " " + name
	}
	return core.Info(subject, title, details...).WithPoC("dig TXT AS%d.asn.cymru.com +short", g.asn)
}

// ownership guesses whether the AS is operated by the domain owner by
// comparing the AS name with the domain name.
func ownership(domain, asName string) string {
	label := strings.Split(dnsutil.OrgDomain(domain), ".")[0]
	if len(label) >= 4 && strings.Contains(strings.ToUpper(asName), strings.ToUpper(label)) {
		return "the AS name matches the domain: the network appears to be operated by the domain owner"
	}
	return "the AS name does not match the domain: the addresses are probably hosted by a third party (ISP or hosting company) that controls their routing"
}

// networkName returns the name of the registry object (inetnum/NetRange)
// covering ip.
func networkName(ctx context.Context, env *core.Env, ip net.IP) string {
	records, err := env.BGP.Stat.Whois(ctx, ip.String())
	if err != nil {
		return ""
	}
	for _, rec := range records {
		var netname, descr, org string
		for _, a := range rec {
			switch strings.ToLower(a.Key) {
			case "netname":
				netname = a.Value
			case "descr":
				if descr == "" {
					descr = a.Value
				}
			case "org-name", "orgname", "organization", "owner":
				if org == "" {
					org = a.Value
				}
			}
		}
		if netname == "" {
			continue
		}
		var extra []string
		for _, s := range []string{org, descr} {
			if s != "" && !contains(extra, s) {
				extra = append(extra, s)
			}
		}
		if len(extra) > 0 {
			return fmt.Sprintf("%s (%s)", netname, strings.Join(extra, ", "))
		}
		return netname
	}
	return ""
}

func upstreams(ctx context.Context, env *core.Env, g *asGroup) core.Finding {
	subject := fmt.Sprintf("AS%d", g.asn)
	var ip net.IP
	for _, t := range g.targets {
		if t.IP.To4() != nil {
			ip = t.IP
			break
		}
	}
	ups, source, err := env.BGP.Upstreams(ctx, g.asn, ip)
	if err != nil {
		return core.Errorf(subject, "could not determine the upstream providers: %v", err)
	}
	names := core.ParallelMap(limit(ups, 10), 4, func(a uint32) string {
		if info, err := env.BGP.AS(ctx, a); err == nil && info.Name != "" {
			return fmt.Sprintf("AS%d %s", a, info.Name)
		}
		return fmt.Sprintf("AS%d", a)
	})
	if len(ups) > len(names) {
		names = append(names, fmt.Sprintf("... and %d more", len(ups)-len(names)))
	}
	poc := fmt.Sprintf("curl -s 'https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS%d'", g.asn)
	switch len(ups) {
	case 0:
		return core.Info(subject, "no upstream provider observed ("+source+")")
	case 1:
		return core.Fail(core.SeverityLow, subject, "single-homed: the AS has only one upstream provider",
			append(names, "an outage or routing incident at the upstream makes the domain unreachable", "source: "+source)...).WithPoC("%s", poc)
	default:
		return core.Pass(subject, fmt.Sprintf("multi-homed: %d upstream/peer ASes observed", len(ups)),
			append(names, "source: "+source)...).WithPoC("%s", poc)
	}
}

func visibility(ctx context.Context, env *core.Env, g *asGroup, prefix string) []core.Finding {
	subject := fmt.Sprintf("%s (AS%d)", prefix, g.asn)
	rs, err := env.BGP.Stat.RoutingStatus(ctx, prefix)
	if err != nil {
		return []core.Finding{core.Errorf(subject, "routing status lookup failed: %v", err)}
	}
	var out []core.Finding
	var origins []uint32
	for _, o := range rs.Origins {
		origins = append(origins, o.Origin)
	}
	if len(origins) > 1 {
		out = append(out, core.Fail(core.SeverityMedium, subject,
			fmt.Sprintf("prefix announced by multiple origin ASes (%s) according to RIPE RIS", asList(origins)),
			"multiple-origin (MOAS) announcements can be legitimate (anycast, migrations) but are also the signature of a prefix hijack"))
	}
	vis := rs.VisibilityV4
	if p, err := netip.ParsePrefix(prefix); err == nil && p.Addr().Is6() {
		vis = rs.VisibilityV6
	}
	var details []string
	if rs.FirstSeen != "" {
		details = append(details, "first seen in BGP: "+rs.FirstSeen)
	}
	poc := fmt.Sprintf("curl -s 'https://stat.ripe.net/data/routing-status/data.json?resource=%s'", prefix)
	switch {
	case vis.Total == 0:
		out = append(out, core.Info(subject, "BGP visibility unknown", details...))
	case vis.Seeing*2 < vis.Total:
		out = append(out, core.Fail(core.SeverityLow, subject,
			fmt.Sprintf("limited BGP visibility: seen by %d of %d RIS full-table peers (%.0f%%)", vis.Seeing, vis.Total, pct(vis)),
			append(details, "part of the Internet may not reach the address")...).WithPoC("%s", poc))
	default:
		out = append(out, core.Pass(subject,
			fmt.Sprintf("globally visible: seen by %d of %d RIS full-table peers (%.0f%%)", vis.Seeing, vis.Total, pct(vis)), details...))
	}
	return out
}

func pct(v bgp.Visibility) float64 { return 100 * float64(v.Seeing) / float64(v.Total) }

func irrCoverage(ctx context.Context, env *core.Env, g *asGroup) core.Finding {
	subject := fmt.Sprintf("AS%d", g.asn)
	prefixes, err := env.BGP.Stat.ASRoutingConsistency(ctx, g.asn)
	if err != nil {
		return core.Errorf(subject, "IRR consistency lookup failed: %v", err)
	}
	var announced, missing []string
	for _, p := range prefixes {
		if !p.InBGP {
			continue
		}
		announced = append(announced, p.Prefix)
		if !p.InWhois {
			missing = append(missing, p.Prefix)
		}
	}
	poc := fmt.Sprintf("curl -s 'https://stat.ripe.net/data/as-routing-consistency/data.json?resource=AS%d'", g.asn)
	if len(announced) == 0 {
		return core.Info(subject, "no announced prefix found in the IRR consistency data")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		details := limitStrings(missing, 15)
		return core.Fail(core.SeverityLow, subject,
			fmt.Sprintf("%d of %d announced prefixes have no IRR route object", len(missing), len(announced)),
			details...).WithPoC("%s", poc)
	}
	return core.Pass(subject, fmt.Sprintf("all %d announced prefixes have an IRR route object", len(announced)))
}

func rpkiCoverage(ctx context.Context, env *core.Env, g *asGroup) core.Finding {
	subject := fmt.Sprintf("AS%d", g.asn)
	prefixes, err := env.BGP.Stat.AnnouncedPrefixes(ctx, g.asn)
	if err != nil {
		return core.Errorf(subject, "announced prefixes lookup failed: %v", err)
	}
	if len(prefixes) == 0 {
		return core.Info(subject, "no announced prefix found")
	}
	max := env.Opts.MaxPrefixes
	if max <= 0 {
		max = 20
	}
	// Always include the prefixes carrying the domain, then sample the rest.
	sample := append([]string(nil), g.prefixes...)
	for _, p := range prefixes {
		if len(sample) >= max {
			break
		}
		if !contains(sample, p) {
			sample = append(sample, p)
		}
	}
	type res struct {
		prefix, status string
		err            error
	}
	results := core.ParallelMap(sample, 4, func(p string) res {
		v, err := env.BGP.Stat.RPKIValidation(ctx, g.asn, p)
		if err != nil {
			return res{prefix: p, err: err}
		}
		return res{prefix: p, status: v.Status}
	})
	var notFound, invalid, errs []string
	for _, x := range results {
		switch {
		case x.err != nil:
			errs = append(errs, x.prefix)
		case x.status == "valid":
		case strings.HasPrefix(x.status, "invalid"):
			invalid = append(invalid, fmt.Sprintf("%s (%s)", x.prefix, x.status))
		default:
			notFound = append(notFound, x.prefix)
		}
	}
	checked := len(sample) - len(errs)
	scope := fmt.Sprintf("checked %d of %d announced prefixes", checked, len(prefixes))
	poc := fmt.Sprintf("curl -s 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d'", g.asn)
	switch {
	case checked == 0:
		return core.Errorf(subject, "RPKI validation failed for every prefix")
	case len(invalid) > 0:
		return core.Fail(core.SeverityMedium, subject,
			fmt.Sprintf("%d prefixes of the AS are RPKI invalid", len(invalid)),
			append([]string{scope}, limitStrings(invalid, 15)...)...).WithPoC("%s", poc)
	case len(notFound) > 0:
		return core.Fail(core.SeverityLow, subject,
			fmt.Sprintf("%d of %d checked prefixes have no ROA: the AS does not fully deploy RPKI", len(notFound), checked),
			append([]string{scope}, limitStrings(notFound, 15)...)...).WithPoC("%s", poc)
	default:
		return core.Pass(subject, fmt.Sprintf("RPKI deployed: all %d checked prefixes are covered by valid ROAs", checked), scope)
	}
}

func abuseContact(ctx context.Context, env *core.Env, g *asGroup) core.Finding {
	subject := fmt.Sprintf("AS%d", g.asn)
	resource := g.prefixes[0]
	contacts, err := env.BGP.Stat.AbuseContacts(ctx, resource)
	if err != nil {
		return core.Errorf(subject, "abuse contact lookup failed: %v", err)
	}
	if len(contacts) == 0 {
		return core.Info(subject, "no abuse contact registered for "+resource)
	}
	return core.Info(subject, "abuse contact for "+resource+": "+strings.Join(contacts, ", "))
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func limit(a []uint32, n int) []uint32 {
	if len(a) > n {
		return a[:n]
	}
	return a
}

func limitStrings(a []string, n int) []string {
	if len(a) > n {
		return append(append([]string(nil), a[:n]...), fmt.Sprintf("... and %d more", len(a)-n))
	}
	return a
}
