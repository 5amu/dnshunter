package dnschecks

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
)

// GLUE verifies the glue records published by the parent zone: nameservers
// inside the delegated zone (in-bailiwick) can only be reached through glue,
// and stale glue silently redirects resolvers to old addresses.
var GLUE = &core.Check{
	ID:       "glue",
	Name:     "Glue records",
	Category: core.CategoryDNS,
	Description: "When a nameserver name lies inside the zone it serves (e.g. ns1.example.com for " +
		"example.com) the parent zone must publish its address as a glue record, otherwise resolution " +
		"loops and fails. Glue that differs from the authoritative A/AAAA records points resolvers to " +
		"stale, possibly reassigned, addresses.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc9471",
		"https://www.rfc-editor.org/rfc/rfc1034#section-4.2.1",
	},
	Run: runGLUE,
}

func runGLUE(ctx context.Context, env *core.Env, r *core.Result) error {
	t := env.Target
	d := t.Delegation
	if d == nil {
		return fmt.Errorf("could not obtain the delegation from the parent zone: %s", t.DelegationErr)
	}
	poc := fmt.Sprintf("dig NS %s +norecurse @%s", t.Zone, d.Server)
	authoritative := map[string][]string{}
	for _, ns := range t.Nameservers {
		authoritative[ns.Name] = ipStrings(ns.IPs)
	}

	for _, ns := range d.NS {
		glue := d.Glue[ns]
		inBailiwick := dnsutil.IsSubdomain(t.Zone, ns)
		if !inBailiwick {
			if len(glue) > 0 {
				r.Add(core.Info(ns, "out-of-bailiwick nameserver with glue at the parent", "glue: "+strings.Join(ipStrings(glue), ", ")))
			} else {
				r.Add(core.Pass(ns, "out-of-bailiwick nameserver: glue not required"))
			}
			continue
		}
		if len(glue) == 0 {
			r.Add(core.Fail(core.SeverityHigh, ns, fmt.Sprintf("in-bailiwick nameserver has no glue record in the %s zone", d.Parent),
				"resolvers cannot reach this nameserver without glue: resolution of the zone may fail").WithPoC("%s", poc))
			continue
		}
		authIPs, ok := authoritative[ns]
		if !ok {
			r.Add(core.Info(ns, "glue present for a nameserver that is not in the authoritative NS set", "glue: "+strings.Join(ipStrings(glue), ", ")))
			continue
		}
		glueIPs := ipStrings(glue)
		details := []string{
			fmt.Sprintf("glue at %s: %s", d.Parent, strings.Join(glueIPs, ", ")),
			fmt.Sprintf("authoritative: %s", strings.Join(authIPs, ", ")),
		}
		stale, missing := diffIPs(glueIPs, authIPs)
		switch {
		case len(authIPs) == 0:
			r.Add(core.Info(ns, "glue present but the nameserver name does not resolve", details...))
		case len(stale) > 0:
			r.Add(core.Fail(core.SeverityMedium, ns, "stale glue: the parent publishes addresses not served by the zone",
				append(details, "stale: "+strings.Join(stale, ", "))...).WithPoC("%s", poc))
		case len(missing) > 0:
			r.Add(core.Fail(core.SeverityLow, ns, "incomplete glue: some addresses of the nameserver are missing at the parent",
				append(details, "missing: "+strings.Join(missing, ", "))...).WithPoC("%s", poc))
		default:
			r.Add(core.Pass(ns, "glue records present and consistent", details[0]))
		}
	}
	if len(d.NS) == 0 {
		return errors.New("empty delegation")
	}
	return nil
}
