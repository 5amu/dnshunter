package bgpchecks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
)

// IRR verifies that the routes carrying the domain infrastructure are
// registered in an Internet Routing Registry with the right origin.
var IRR = &core.Check{
	ID:       "irr",
	Name:     "IRR route objects",
	Category: core.CategoryBGP,
	Description: "Many transit providers and IXPs build their BGP filters from Internet Routing " +
		"Registry (IRR) route objects. A prefix without a route object for its origin AS may be filtered " +
		"(reduced reachability), while route objects registered for other origins can be used to get a " +
		"hijack accepted. Nameserver and domain addresses are checked; provider networks are skipped.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc7682",
		"https://www.manrs.org/netops/guide/global-coordination/",
		"https://stat.ripe.net/docs/data-api/api-endpoints/prefix-routing-consistency",
	},
	Run: runIRR,
}

func runIRR(ctx context.Context, env *core.Env, r *core.Result) error {
	ts := collect(env, true, true)
	if len(ts) == 0 {
		return errNoTargets
	}
	profile(ctx, env, ts)
	routes := analyzable(env, r, ts)
	findings := core.ParallelMap(routes, 4, func(rt *route) core.Finding {
		return validateIRR(ctx, env, rt)
	})
	r.Add(findings...)
	return nil
}

func validateIRR(ctx context.Context, env *core.Env, rt *route) core.Finding {
	st, err := env.BGP.IRR(ctx, rt.Prefix)
	if err != nil {
		return core.Errorf(rt.subject(), "IRR lookup failed: %v", err)
	}
	poc := fmt.Sprintf("whois -h whois.radb.net -- '-x %s'", rt.Prefix)
	details := []string{rt.members(), "source: " + st.Source}

	if sources, ok := st.Origins[rt.ASN]; ok {
		if len(sources) > 0 {
			details = append(details, "registered in: "+strings.Join(uniq(sources), ", "))
		}
		if others := otherOrigins(st.Origins, rt.ASN); len(others) > 0 {
			details = append(details, "route objects also exist for "+asList(others)+": stale objects can be abused to get a hijack accepted")
		}
		return core.Pass(rt.subject(), "IRR route object registered for the origin AS", details...).WithPoC("%s", poc)
	}

	if others := otherOrigins(st.Origins, rt.ASN); len(others) > 0 {
		return core.Fail(core.SeverityMedium, rt.subject(),
			fmt.Sprintf("IRR route objects for %s only exist for other origins (%s): the announcement may be filtered", rt.Prefix, asList(others)),
			details...).WithPoC("%s", poc)
	}

	var covering []string
	for p, origins := range st.Covering {
		for _, o := range origins {
			if o == rt.ASN {
				covering = append(covering, p)
			}
		}
	}
	sort.Strings(covering)
	if len(covering) > 0 {
		return core.Fail(core.SeverityLow, rt.subject(),
			"no exact IRR route object: the prefix is only covered by less-specific route objects of the origin AS (strict filters may drop it)",
			append(details, "covering: "+strings.Join(covering, ", "))...).WithPoC("%s", poc)
	}
	return core.Fail(core.SeverityMedium, rt.subject(),
		"no IRR route object for the prefix: networks filtering on IRR data may drop the announcement",
		details...).WithPoC("%s", poc)
}

func otherOrigins(origins map[uint32][]string, asn uint32) []uint32 {
	var out []uint32
	for o := range origins {
		if o != asn {
			out = append(out, o)
		}
	}
	return out
}

func uniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
