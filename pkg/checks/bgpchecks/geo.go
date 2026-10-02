package bgpchecks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
)

// GEO checks the topological and geographic diversity of the nameservers.
var GEO = &core.Check{
	ID:       "geo",
	Aliases:  []string{"georedundancy"},
	Name:     "Nameserver AS and geographic redundancy",
	Category: core.CategoryBGP,
	Description: "Nameservers should be spread over different autonomous systems and locations so that " +
		"a single network outage, routing incident or regional event cannot make the whole domain " +
		"unresolvable (RFC 2182). Large DNS providers mitigate geographic concentration with anycast, but " +
		"remain a single provider dependency.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc2182#section-3.1",
	},
	Run: runGEO,
}

func runGEO(ctx context.Context, env *core.Env, r *core.Result) error {
	ts := collect(env, true, false)
	if len(ts) == 0 {
		return errNoTargets
	}
	profile(ctx, env, ts)

	// Prefer geolocation data, fall back to the registration country.
	type loc struct {
		country, city string
		geo           bool
	}
	locs := core.ParallelMap(ts, 4, func(t *ipTarget) loc {
		if t.p == nil || t.p.Origin == nil {
			return loc{}
		}
		if env.BGP.Stat != nil {
			if l, err := env.BGP.Stat.Geolocation(ctx, t.IP.String()); err == nil {
				return loc{l.Country, l.City, true}
			}
		}
		return loc{country: t.p.Origin.Country}
	})

	asns := map[uint32][]string{}
	countries := map[string][]string{}
	allAnycast, providers, independent := true, map[string]bool{}, 0
	for i, t := range ts {
		switch {
		case t.p != nil && t.p.Reserved != "":
			r.Add(core.Fail(core.SeverityMedium, t.subject(), "nameserver address is not public: "+t.p.Reserved))
			continue
		case t.err != nil || t.p == nil || t.p.Origin == nil:
			r.Add(core.Errorf(t.subject(), "routing lookup failed: %v", t.err))
			continue
		}
		desc := describeProfile(t.p)
		if l := locs[i]; l.geo {
			where := l.country
			if l.city != "" {
				where = l.city + ", " + where
			}
			desc += ", geolocated in " + where
		}
		if t.p.Provider != nil {
			desc += ", provider " + t.p.Provider.Name
			providers[t.p.Provider.Name] = true
			if !t.p.Provider.Anycast {
				allAnycast = false
			}
		} else {
			allAnycast = false
			independent++
		}
		r.Add(core.Info(t.subject(), desc))
		asns[t.p.Origin.ASN()] = append(asns[t.p.Origin.ASN()], t.IP.String())
		if c := locs[i].country; c != "" {
			countries[c] = append(countries[c], t.IP.String())
		}
	}
	if len(asns) == 0 {
		return fmt.Errorf("no nameserver address could be mapped to an AS")
	}

	var asNames []string
	for a := range asns {
		asNames = append(asNames, fmt.Sprintf("AS%d", a))
	}
	sort.Strings(asNames)
	var ccs []string
	for c := range countries {
		ccs = append(ccs, c)
	}
	sort.Strings(ccs)
	summary := fmt.Sprintf("nameservers spread over %d AS (%s) and %d countries (%s, by geolocation or registration)",
		len(asns), strings.Join(asNames, ", "), len(countries), strings.Join(ccs, ", "))
	anycastNote := "the provider serves DNS over anycast, which mitigates geographic concentration"

	if len(asns) == 1 {
		details := []string{"an outage or routing incident affecting this AS makes the domain unresolvable"}
		if allAnycast {
			details = append(details, anycastNote+", but the domain still depends on a single provider")
		}
		r.Add(core.Fail(core.SeverityLow, env.Target.Zone, "all nameservers are in a single autonomous system", details...))
	}
	if len(countries) == 1 {
		if allAnycast {
			r.Add(core.Info(env.Target.Zone, "all nameserver addresses are registered in a single country", anycastNote))
		} else {
			r.Add(core.Fail(core.SeverityLow, env.Target.Zone, "all nameservers are located in a single country",
				"a regional outage or event can make the domain unresolvable"))
		}
	}
	if len(asns) > 1 && len(countries) != 1 {
		r.Add(core.Pass(env.Target.Zone, summary))
	} else {
		r.Add(core.Info(env.Target.Zone, summary))
	}
	if len(providers) == 1 && independent == 0 && len(asns) > 1 {
		for p := range providers {
			r.Add(core.Info(env.Target.Zone, "every nameserver is operated by "+p+": the domain depends on a single DNS provider"))
		}
	}
	return nil
}
