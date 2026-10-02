package mailchecks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
)

// DMARC evaluates the DMARC policy of the domain.
var DMARC = &core.Check{
	ID:       "dmarc",
	Name:     "DMARC record",
	Category: core.CategoryMail,
	Description: "DMARC tells receivers what to do with messages failing SPF and DKIM alignment " +
		"(none, quarantine or reject) and where to send reports. Without an enforcing policy (p=reject " +
		"or p=quarantine applied to 100% of messages) spoofed e-mail reaches the recipients.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc7489",
	},
	Run: runDMARC,
}

func dmarcRecords(ctx context.Context, env *core.Env, domain string) ([]string, error) {
	txt, _, err := env.DNS.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range txt {
		l := strings.ToLower(strings.TrimSpace(t))
		if strings.HasPrefix(l, "v=dmarc1") {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out, nil
}

// parseTags parses a "k=v; k=v" tag list (DMARC, DKIM).
func parseTags(s string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, dup := tags[k]; !dup {
			tags[k] = strings.TrimSpace(v)
		}
	}
	return tags
}

func runDMARC(ctx context.Context, env *core.Env, r *core.Result) error {
	domain := env.Target.Domain
	owner := domain
	records, err := dmarcRecords(ctx, env, domain)
	if err != nil {
		return err
	}
	org := dnsutil.OrgDomain(domain)
	inherited := false
	if len(records) == 0 && org != domain {
		if records, err = dmarcRecords(ctx, env, org); err != nil {
			return err
		}
		owner, inherited = org, len(records) > 0
	}
	poc := fmt.Sprintf("dig TXT _dmarc.%s +short", owner)

	switch {
	case len(records) == 0:
		r.Add(core.Fail(core.SeverityMedium, domain, "no DMARC record: receivers have no policy for spoofed messages",
			"publish at least \"v=DMARC1; p=none; rua=mailto:...\" and move to p=reject").WithPoC("dig TXT _dmarc.%s +short", domain))
		return nil
	case len(records) > 1:
		r.Add(core.Fail(core.SeverityMedium, domain, fmt.Sprintf("%d DMARC records published at _dmarc.%s: receivers ignore all of them", len(records), owner), records...).WithPoC("%s", poc))
		return nil
	}

	record := records[0]
	tags := parseTags(record)
	details := []string{record}
	if inherited {
		details = append(details, "inherited from the organizational domain "+org)
	}
	r.Add(core.Info(domain, "DMARC record", details...).WithPoC("%s", poc))

	policy := strings.ToLower(tags["p"])
	if inherited {
		// RFC 7489 §6.6.3: subdomains use sp= when present.
		if sp := strings.ToLower(tags["sp"]); sp != "" {
			policy = sp
		}
	}
	switch policy {
	case "reject":
		r.Add(core.Pass(domain, "DMARC policy is reject"))
	case "quarantine":
		r.Add(core.Fail(core.SeverityLow, domain, "DMARC policy is quarantine: spoofed messages are delivered to the spam folder instead of being rejected"))
	case "none":
		r.Add(core.Fail(core.SeverityMedium, domain, "DMARC policy is none (monitoring only): spoofed messages are delivered"))
	case "":
		r.Add(core.Fail(core.SeverityMedium, domain, "DMARC record has no p= tag: the record is invalid"))
	default:
		r.Add(core.Fail(core.SeverityMedium, domain, fmt.Sprintf("invalid DMARC policy p=%s", tags["p"])))
	}

	if sp := strings.ToLower(tags["sp"]); sp != "" && !inherited && weaker(sp, policy) {
		r.Add(core.Fail(core.SeverityLow, domain, fmt.Sprintf("subdomain policy sp=%s is weaker than p=%s: subdomains can be spoofed", sp, policy)))
	}
	if pct, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(pct); err == nil && n < 100 {
			r.Add(core.Fail(core.SeverityLow, domain, fmt.Sprintf("pct=%d: the policy is applied only to %d%% of failing messages", n, n)))
		}
	}
	if rua := tags["rua"]; rua == "" {
		r.Add(core.Info(domain, "no aggregate report destination (rua): spoofing attempts go unnoticed"))
	} else {
		checkReportAuthorization(ctx, env, r, owner, rua)
	}
	if strings.EqualFold(tags["adkim"], "s") && strings.EqualFold(tags["aspf"], "s") {
		r.Add(core.Info(domain, "strict SPF and DKIM alignment"))
	}
	return nil
}

var strength = map[string]int{"none": 0, "quarantine": 1, "reject": 2}

func weaker(a, b string) bool {
	sa, ok1 := strength[a]
	sb, ok2 := strength[b]
	return ok1 && ok2 && sa < sb
}

// checkReportAuthorization verifies that third-party report destinations
// accept reports for the domain (RFC 7489 §7.1).
func checkReportAuthorization(ctx context.Context, env *core.Env, r *core.Result, domain, rua string) {
	for _, uri := range strings.Split(rua, ",") {
		uri = strings.TrimSpace(uri)
		if !strings.HasPrefix(strings.ToLower(uri), "mailto:") {
			continue
		}
		addr := uri[len("mailto:"):]
		if i := strings.IndexByte(addr, '!'); i >= 0 {
			addr = addr[:i]
		}
		at := strings.LastIndexByte(addr, '@')
		if at < 0 {
			r.Add(core.Fail(core.SeverityLow, domain, fmt.Sprintf("invalid rua destination %q", uri)))
			continue
		}
		dest := strings.ToLower(addr[at+1:])
		if dnsutil.OrgDomain(dest) == dnsutil.OrgDomain(domain) {
			continue
		}
		name := fmt.Sprintf("%s._report._dmarc.%s", domain, dest)
		txt, _, err := env.DNS.LookupTXT(ctx, name)
		if err != nil {
			continue
		}
		authorized := false
		for _, t := range txt {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
				authorized = true
			}
		}
		if !authorized {
			r.Add(core.Info(domain, fmt.Sprintf("external report destination %s has not authorized reports for %s: aggregate reports will not be sent", dest, domain)).
				WithPoC("dig TXT %s +short", name))
		}
	}
}
