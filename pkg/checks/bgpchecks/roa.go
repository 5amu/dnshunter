package bgpchecks

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/5amu/dnshunter/pkg/bgp"
	"github.com/5amu/dnshunter/pkg/core"
)

// ROA validates the routes carrying the domain infrastructure against RPKI.
var ROA = &core.Check{
	ID:       "roa",
	Aliases:  []string{"rpki"},
	Name:     "RPKI route origin validation (ROA)",
	Category: core.CategoryBGP,
	Description: "Route Origin Authorizations (ROAs) cryptographically state which AS may originate a " +
		"prefix. Networks enforcing RPKI origin validation drop invalid routes, so prefixes without a ROA " +
		"can be hijacked by anyone announcing them, and RPKI-invalid prefixes are unreachable from part of " +
		"the Internet. Nameserver and domain addresses are checked; provider networks are skipped.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc6811",
		"https://www.rfc-editor.org/rfc/rfc9319",
		"https://stat.ripe.net/docs/data-api/api-endpoints/rpki-validation",
	},
	Run: runROA,
}

func runROA(ctx context.Context, env *core.Env, r *core.Result) error {
	if env.BGP.Stat == nil {
		return fmt.Errorf("RPKI validation requires RIPEstat, which is disabled")
	}
	ts := collect(env, true, true)
	if len(ts) == 0 {
		return errNoTargets
	}
	profile(ctx, env, ts)
	routes := analyzable(env, r, ts)
	findings := core.ParallelMap(routes, 4, func(rt *route) []core.Finding {
		return validateROA(ctx, env, rt)
	})
	for _, f := range findings {
		r.Add(f...)
	}
	return nil
}

func validateROA(ctx context.Context, env *core.Env, rt *route) []core.Finding {
	res, err := env.BGP.Stat.RPKIValidation(ctx, rt.ASN, rt.Prefix)
	if err != nil {
		return []core.Finding{core.Errorf(rt.subject(), "RPKI validation failed: %v", err)}
	}
	poc := fmt.Sprintf("curl -s 'https://stat.ripe.net/data/rpki-validation/data.json?resource=AS%d&prefix=%s'", rt.ASN, rt.Prefix)
	var roas []string
	for _, roa := range res.ROAs {
		roas = append(roas, fmt.Sprintf("ROA %s max-length %d origin AS%d (%s)", roa.Prefix, roa.MaxLength, roa.Origin, roa.Validity))
	}
	details := append([]string{rt.members()}, roas...)

	var out []core.Finding
	switch {
	case res.Status == "valid":
		out = append(out, core.Pass(rt.subject(), "RPKI valid: the route is covered by a matching ROA", details...))
		if loose := looseROAs(rt.Prefix, rt.ASN, res.ROAs); len(loose) > 0 {
			out = append(out, core.Fail(core.SeverityLow, rt.subject(),
				"loose ROA: max-length allows more-specific prefixes that are not announced (forged-origin sub-prefix hijack, RFC 9319)",
				loose...).WithPoC("%s", poc))
		}
	case res.Status == "invalid_asn":
		out = append(out, core.Fail(core.SeverityHigh, rt.subject(),
			"RPKI invalid: ROAs authorize a different origin AS (possible hijack or stale ROA); the route is dropped by validating networks",
			details...).WithPoC("%s", poc))
	case res.Status == "invalid_length":
		out = append(out, core.Fail(core.SeverityHigh, rt.subject(),
			"RPKI invalid: the announced prefix is longer than the ROA max-length; the route is dropped by validating networks",
			details...).WithPoC("%s", poc))
	case strings.HasPrefix(res.Status, "invalid"):
		out = append(out, core.Fail(core.SeverityHigh, rt.subject(), "RPKI invalid ("+res.Status+")", details...).WithPoC("%s", poc))
	case res.Status == "unknown" || res.Status == "not-found" || res.Status == "notfound":
		out = append(out, core.Fail(core.SeverityMedium, rt.subject(),
			"no ROA covers the prefix (RPKI not-found): the route is not protected against origin hijacks",
			details...).WithPoC("%s", poc))
	default:
		out = append(out, core.Errorf(rt.subject(), "unexpected RPKI status %q", res.Status))
	}
	return out
}

// looseROAs returns the matching ROAs whose max-length exceeds the prefix
// length, allowing unannounced more-specifics.
func looseROAs(prefix string, asn uint32, roas []bgp.ROA) []string {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil
	}
	var out []string
	for _, roa := range roas {
		rp, err := netip.ParsePrefix(roa.Prefix)
		if err != nil || roa.Origin != asn || !rp.Contains(p.Addr()) {
			continue
		}
		if roa.MaxLength > p.Bits() && rp.Bits() == p.Bits() {
			out = append(out, fmt.Sprintf("ROA %s max-length %d (announced /%d)", roa.Prefix, roa.MaxLength, p.Bits()))
		}
	}
	return out
}
