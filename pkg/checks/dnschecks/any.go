package dnschecks

import (
	"context"
	"fmt"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/target"
	"github.com/miekg/dns"
)

const (
	// amplificationFactor is the response/request size ratio above which an
	// ANY answer is considered abusable for reflection attacks.
	amplificationFactor = 10.0
	// amplificationRecords is the number of answer records above which an
	// ANY answer is considered abusable.
	amplificationRecords = 5
)

// ANY checks whether nameservers answer ANY queries with the full content of
// the apex, which makes them good DNS amplification reflectors.
var ANY = &core.Check{
	ID:       "any",
	Name:     "DNS amplification (ANY query)",
	Category: core.CategoryDNS,
	Description: "Nameservers that answer ANY queries over UDP with every record of a name return " +
		"responses much larger than the request and can be abused as reflectors in DNS amplification " +
		"DDoS attacks. RFC 8482 allows servers to return a minimal answer instead.",
	References: []string{
		"https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks",
		"https://www.rfc-editor.org/rfc/rfc8482",
	},
	Run: runANY,
}

func runANY(ctx context.Context, env *core.Env, r *core.Result) error {
	zone := env.Target.Zone
	eps := env.Target.Endpoints(env.Opts.IPv6)
	if len(eps) == 0 {
		return errNoEndpoint
	}
	findings := core.ParallelMap(eps, parallelism, func(ep target.Endpoint) core.Finding {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(zone), dns.TypeANY)
		m.RecursionDesired = false
		m.SetEdns0(4096, true)
		req := m.Len()
		resp, err := env.DNS.ExchangeUDP(ctx, m, env.DNS.Addr(ep.IP))
		if err != nil {
			return core.Errorf(ep.String(), "no answer to ANY query: %v", err)
		}
		return evaluateANY(ep, zone, req, resp)
	})
	r.Add(findings...)
	return nil
}

func evaluateANY(ep target.Endpoint, zone string, reqLen int, resp *dns.Msg) core.Finding {
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeFormatError:
		return core.Pass(ep.String(), fmt.Sprintf("ANY queries are refused (%s)", rcode(resp)))
	default:
		return core.Errorf(ep.String(), "unexpected answer to ANY query: %s", rcode(resp))
	}
	if isRFC8482(resp) {
		return core.Pass(ep.String(), "ANY queries get a minimal RFC 8482 answer")
	}
	size := resp.Len()
	factor := float64(size) / float64(reqLen)
	types := map[string]bool{}
	for _, rr := range resp.Answer {
		types[dns.TypeToString[rr.Header().Rrtype]] = true
	}
	var list []string
	for t := range types {
		list = append(list, t)
	}
	detail := fmt.Sprintf("%d records (%s), %d bytes answer to a %d bytes query: amplification factor %.1fx",
		len(resp.Answer), strings.Join(sortStrings(list), ", "), size, reqLen, factor)
	if resp.Truncated {
		detail += " (truncated over UDP)"
	}
	if factor >= amplificationFactor || len(resp.Answer) > amplificationRecords {
		return core.Fail(core.SeverityMedium, ep.String(), "full answer to ANY queries: usable for DNS amplification", detail).
			WithPoC("%s", digAt(ep, fmt.Sprintf("ANY %s +notcp +bufsize=4096 +dnssec", zone)))
	}
	return core.Pass(ep.String(), "ANY answer is small", detail)
}

// isRFC8482 detects the synthesized HINFO "RFC8482" minimal answer.
func isRFC8482(resp *dns.Msg) bool {
	if len(resp.Answer) == 0 {
		return true
	}
	for _, rr := range resp.Answer {
		if h, ok := rr.(*dns.HINFO); ok && strings.EqualFold(h.Cpu, "RFC8482") {
			return true
		}
	}
	return false
}
