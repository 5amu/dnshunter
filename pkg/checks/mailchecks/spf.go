// Package mailchecks implements checks on the e-mail authentication records
// of the domain (SPF, DMARC, DKIM).
package mailchecks

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/miekg/dns"
)

// SPF evaluates the Sender Policy Framework record of the domain.
var SPF = &core.Check{
	ID:       "spf",
	Name:     "SPF record",
	Category: core.CategoryMail,
	Description: "SPF lists the servers allowed to send e-mail for the domain. A missing or permissive " +
		"policy (+all, ?all, no 'all'), a record exceeding the 10 DNS lookups limit or multiple records " +
		"(permerror) let attackers spoof the domain in phishing campaigns.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc7208",
		"https://dmarcian.com/spf-syntax-table/",
	},
	Run: runSPF,
}

const (
	maxLookups     = 10 // RFC 7208 §4.6.4
	maxVoidLookups = 2  // RFC 7208 §4.6.4
	maxDepth       = 10
)

type spfIssue struct {
	sev core.Severity
	msg string
}

type spfEval struct {
	ctx     context.Context
	env     *core.Env
	lookups int
	voids   int
	tree    []string
	issues  []spfIssue
	stack   map[string]bool
}

func (e *spfEval) issue(sev core.Severity, format string, args ...any) {
	e.issues = append(e.issues, spfIssue{sev, fmt.Sprintf(format, args...)})
}

// fetch returns the SPF records published at name.
func (e *spfEval) fetch(name string) ([]string, int, error) {
	txt, rc, err := e.env.DNS.LookupTXT(e.ctx, name)
	if err != nil {
		return nil, 0, err
	}
	var out []string
	for _, t := range txt {
		if isSPF(t) {
			out = append(out, t)
		}
	}
	return out, rc, nil
}

func isSPF(txt string) bool {
	l := strings.ToLower(strings.TrimSpace(txt))
	return l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ")
}

type spfTerm struct {
	qualifier byte
	name      string
	arg       string
	modifier  bool
}

func parseSPF(record string) ([]spfTerm, []string) {
	var terms []spfTerm
	var bad []string
	fields := strings.Fields(record)
	for _, f := range fields[1:] {
		if i := strings.IndexByte(f, '='); i > 0 && !strings.ContainsAny(f[:i], ":/") {
			terms = append(terms, spfTerm{name: strings.ToLower(f[:i]), arg: f[i+1:], modifier: true})
			continue
		}
		t := spfTerm{qualifier: '+'}
		if strings.ContainsRune("+-~?", rune(f[0])) {
			t.qualifier, f = f[0], f[1:]
		}
		name, arg := f, ""
		if i := strings.IndexAny(f, ":/"); i >= 0 {
			name, arg = f[:i], strings.TrimPrefix(f[i:], ":")
		}
		t.name, t.arg = strings.ToLower(name), arg
		switch t.name {
		case "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists":
			terms = append(terms, t)
		default:
			bad = append(bad, f)
		}
	}
	return terms, bad
}

// walk evaluates the SPF record of domain and returns the qualifier of its
// effective "all" mechanism ("" when absent). top is true for the domain's own
// policy and redirect chain, false inside include: mechanisms.
func (e *spfEval) walk(domain string, depth int, top bool) (string, bool) {
	indent := strings.Repeat("  ", depth)
	if depth > maxDepth || e.stack[domain] {
		e.issue(core.SeverityMedium, "SPF include/redirect loop detected at %s (permerror)", domain)
		return "", false
	}
	e.stack[domain] = true
	defer delete(e.stack, domain)

	records, rc, err := e.fetch(domain)
	if err != nil {
		e.tree = append(e.tree, fmt.Sprintf("%s%s: lookup failed (%v)", indent, domain, err))
		e.issue(core.SeverityLow, "SPF lookup for %s failed (temperror): %v", domain, err)
		return "", false
	}
	switch {
	case len(records) == 0:
		if depth > 0 {
			e.voids++
			e.tree = append(e.tree, fmt.Sprintf("%s%s: no SPF record (%s)", indent, domain, dns.RcodeToString[rc]))
			e.issue(core.SeverityMedium, "%s is referenced but has no SPF record (permerror): it may be an expired or dangling domain", domain)
		}
		return "", false
	case len(records) > 1:
		e.issue(core.SeverityMedium, "%s publishes %d SPF records: receivers return permerror", domain, len(records))
	}
	record := records[0]
	e.tree = append(e.tree, fmt.Sprintf("%s%s: %s", indent, domain, record))

	terms, bad := parseSPF(record)
	for _, b := range bad {
		e.issue(core.SeverityMedium, "unknown mechanism %q in the SPF record of %s (permerror)", b, domain)
	}
	all := ""
	hasAll := false
	redirect := ""
	for _, t := range terms {
		if hasAll {
			// RFC 7208 §5.1: mechanisms after "all" are never evaluated,
			// and redirect= is ignored when "all" is present.
			break
		}
		if t.modifier {
			if t.name == "redirect" {
				redirect = t.arg
			}
			continue
		}
		switch t.name {
		case "all":
			all, hasAll = string(t.qualifier), true
		case "include":
			e.lookups++
			if strings.Contains(t.arg, "%") {
				e.tree = append(e.tree, fmt.Sprintf("%s  %s: uses macros, not evaluated", indent, t.arg))
				continue
			}
			if q, ok := e.walk(strings.ToLower(t.arg), depth+1, false); ok && q == "+" && t.qualifier == '+' {
				e.issue(core.SeverityHigh, "include:%s ends with +all: every host on the Internet is authorized", t.arg)
			}
		case "a", "mx", "exists":
			e.lookups++
		case "ptr":
			e.lookups++
			e.issue(core.SeverityLow, "%s uses the deprecated ptr mechanism (RFC 7208 §5.5): slow and unreliable", domain)
		case "ip4", "ip6":
			if top {
				e.checkRange(domain, t)
			}
		}
	}
	if redirect != "" && !hasAll {
		e.lookups++
		if strings.Contains(redirect, "%") {
			return "", false
		}
		return e.walk(strings.ToLower(redirect), depth+1, top)
	}
	return all, hasAll
}

// checkRange flags overly broad ip4/ip6 mechanisms in the domain's own policy.
func (e *spfEval) checkRange(domain string, t spfTerm) {
	if t.qualifier != '+' {
		return
	}
	p, err := netip.ParsePrefix(t.arg)
	if err != nil {
		if _, aerr := netip.ParseAddr(t.arg); aerr != nil {
			e.issue(core.SeverityMedium, "invalid %s mechanism %q in the SPF record of %s (permerror)", t.name, t.arg, domain)
		}
		return
	}
	limit := 16
	if t.name == "ip6" {
		limit = 32
	}
	if p.Bits() < limit {
		sev := core.SeverityMedium
		if p.Bits() <= 8 {
			sev = core.SeverityHigh
		}
		e.issue(sev, "%s:%s authorizes a very large address range (%s) to send mail for %s", t.name, t.arg, rangeSize(p), domain)
	}
}

func rangeSize(p netip.Prefix) string {
	host := p.Addr().BitLen() - p.Bits()
	if host >= 63 {
		return fmt.Sprintf("2^%d addresses", host)
	}
	return fmt.Sprintf("%d addresses", uint64(1)<<host)
}

func runSPF(ctx context.Context, env *core.Env, r *core.Result) error {
	domain := env.Target.Domain
	e := &spfEval{ctx: ctx, env: env, stack: map[string]bool{}}
	poc := fmt.Sprintf("dig TXT %s +short", domain)

	records, _, err := e.fetch(domain)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		r.Add(core.Fail(core.SeverityMedium, domain, "no SPF record: anyone can send e-mail pretending to be the domain",
			"publish \"v=spf1 -all\" if the domain does not send e-mail").WithPoC("%s", poc))
		return nil
	}

	all, _ := e.walk(domain, 0, true)
	switch all {
	case "+":
		r.Add(core.Fail(core.SeverityHigh, domain, "SPF policy ends with +all: every host on the Internet may send e-mail for the domain").WithPoC("%s", poc))
	case "?":
		r.Add(core.Fail(core.SeverityMedium, domain, "SPF policy ends with ?all (neutral): unauthorized senders are not rejected").WithPoC("%s", poc))
	case "~":
		r.Add(core.Fail(core.SeverityLow, domain, "SPF policy ends with ~all (softfail): spoofed mail is usually accepted unless DMARC enforces a policy").WithPoC("%s", poc))
	case "-":
		r.Add(core.Pass(domain, "SPF policy ends with -all (hard fail)"))
	default:
		r.Add(core.Fail(core.SeverityMedium, domain, "SPF policy has no 'all' mechanism: unauthorized senders get a neutral result").WithPoC("%s", poc))
	}

	if e.lookups > maxLookups {
		r.Add(core.Fail(core.SeverityMedium, domain, fmt.Sprintf("SPF evaluation requires %d DNS lookups (limit %d): receivers return permerror and ignore the policy", e.lookups, maxLookups)))
	} else {
		r.Add(core.Pass(domain, fmt.Sprintf("SPF evaluation requires %d DNS lookups (limit %d)", e.lookups, maxLookups)))
	}
	if e.voids > maxVoidLookups {
		r.Add(core.Fail(core.SeverityMedium, domain, fmt.Sprintf("SPF evaluation hits %d void lookups (limit %d): permerror", e.voids, maxVoidLookups)))
	}
	seen := map[string]bool{}
	for _, is := range e.issues {
		if seen[is.msg] {
			continue
		}
		seen[is.msg] = true
		r.Add(core.Fail(is.sev, domain, is.msg))
	}
	r.Add(core.Info(domain, "SPF record tree", e.tree...).WithPoC("%s", poc))
	return nil
}
