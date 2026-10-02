package dnschecks

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/5amu/dnshunter/pkg/target"
	"github.com/miekg/dns"
)

// Version checks whether nameservers disclose their software version or
// identity through CHAOS class queries.
var Version = &core.Check{
	ID:       "version",
	Aliases:  []string{"chaos"},
	Name:     "Nameserver version disclosure",
	Category: core.CategoryDNS,
	Description: "Many DNS servers answer CHAOS TXT queries such as version.bind with their software " +
		"name and version, letting attackers quickly match them against known vulnerabilities. The " +
		"version string should be hidden or replaced.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc4892",
	},
	Run: runVersion,
}

func runVersion(ctx context.Context, env *core.Env, r *core.Result) error {
	eps := env.Target.Endpoints(env.Opts.IPv6)
	if len(eps) == 0 {
		return errNoEndpoint
	}
	results := core.ParallelMap(eps, parallelism, func(ep target.Endpoint) []core.Finding {
		var out []core.Finding
		version, verr := chaosTXT(ctx, env, ep, "version.bind")
		if version == "" && verr == nil {
			version, _ = chaosTXT(ctx, env, ep, "version.server")
		}
		switch {
		case verr != nil:
			out = append(out, core.Errorf(ep.String(), "no answer to version.bind query: %v", verr))
		case version == "":
			out = append(out, core.Pass(ep.String(), "software version is not disclosed"))
		case looksLikeVersion(version):
			out = append(out, core.Fail(core.SeverityLow, ep.String(), fmt.Sprintf("software version disclosed: %q", version)).
				WithPoC("%s", digAt(ep, "CH TXT version.bind +short")))
		default:
			out = append(out, core.Pass(ep.String(), fmt.Sprintf("custom version string %q", version)))
		}
		if id, _ := chaosTXT(ctx, env, ep, "hostname.bind"); id != "" {
			out = append(out, core.Info(ep.String(), fmt.Sprintf("server identity disclosed (hostname.bind): %q", id)))
		} else if id, _ := chaosTXT(ctx, env, ep, "id.server"); id != "" {
			out = append(out, core.Info(ep.String(), fmt.Sprintf("server identity disclosed (id.server): %q", id)))
		}
		return out
	})
	for _, f := range results {
		r.Add(f...)
	}
	return nil
}

func chaosTXT(ctx context.Context, env *core.Env, ep target.Endpoint, name string) (string, error) {
	resp, err := env.DNS.Query(ctx, env.DNS.Addr(ep.IP), name, dns.TypeTXT, dnsutil.Class(dns.ClassCHAOS), dnsutil.NoRecurse())
	if err != nil {
		return "", err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", nil
	}
	txt := dnsutil.TXTStrings(resp.Answer)
	return strings.TrimSpace(strings.Join(txt, " ")), nil
}

// looksLikeVersion reports whether s contains a version number.
func looksLikeVersion(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}
