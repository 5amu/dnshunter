package dnschecks

import (
	"context"
	"fmt"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/5amu/dnshunter/pkg/target"
	"github.com/miekg/dns"
)

// Recursion checks whether authoritative nameservers also act as open
// recursive resolvers.
var Recursion = &core.Check{
	ID:       "recursion",
	Aliases:  []string{"openresolver"},
	Name:     "Open recursive resolver",
	Category: core.CategoryDNS,
	Description: "Authoritative nameservers should not resolve names on behalf of arbitrary clients. " +
		"Open resolvers are abused for DNS amplification attacks and are exposed to cache poisoning, " +
		"which would affect every user relying on them.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc5358",
		"https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks",
	},
	Run: runRecursion,
}

// probeNames are well-known names outside of the tested zone.
var probeNames = []string{"www.iana.org", "www.example.com"}

func runRecursion(ctx context.Context, env *core.Env, r *core.Result) error {
	probe := probeNames[0]
	for _, p := range probeNames {
		if !dnsutil.IsSubdomain(env.Target.Zone, p) {
			probe = p
			break
		}
	}
	eps := env.Target.Endpoints(env.Opts.IPv6)
	if len(eps) == 0 {
		return errNoEndpoint
	}
	findings := core.ParallelMap(eps, parallelism, func(ep target.Endpoint) core.Finding {
		resp, err := env.DNS.Query(ctx, env.DNS.Addr(ep.IP), probe, dns.TypeA)
		if err != nil {
			return core.Errorf(ep.String(), "no answer to recursive query: %v", err)
		}
		switch {
		case resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 && !resp.Authoritative:
			return core.Fail(core.SeverityHigh, ep.String(), fmt.Sprintf("open resolver: the nameserver resolved %s on our behalf", probe),
				"open resolvers can be abused for amplification attacks and are exposed to cache poisoning").
				WithPoC("%s", digAt(ep, "A "+probe+" +recurse"))
		case resp.RecursionAvailable && resp.Rcode == dns.RcodeSuccess:
			return core.Fail(core.SeverityLow, ep.String(), "nameserver advertises recursion (RA flag) to external clients")
		default:
			return core.Pass(ep.String(), fmt.Sprintf("recursion refused (%s)", rcode(resp)))
		}
	})
	r.Add(findings...)
	return nil
}
