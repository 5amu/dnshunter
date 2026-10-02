package dnschecks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/miekg/dns"
)

// SOA checks the SOA record against RIPE-203 / RFC 1912 recommendations and
// verifies that every nameserver serves the same serial.
var SOA = &core.Check{
	ID:       "soa",
	Name:     "SOA record",
	Category: core.CategoryDNS,
	Description: "The SOA record controls how secondary nameservers refresh the zone and how long " +
		"negative answers are cached. Badly tuned timers cause stale data or outages when the primary " +
		"is unreachable, and diverging serials show nameservers that are out of sync.",
	References: []string{
		"https://www.ripe.net/publications/docs/ripe-203",
		"https://www.rfc-editor.org/rfc/rfc1912#section-2.2",
		"https://www.rfc-editor.org/rfc/rfc2308#section-5",
	},
	Run: runSOA,
}

func runSOA(ctx context.Context, env *core.Env, r *core.Result) error {
	zone := env.Target.Zone
	answers := queryAll(ctx, env, zone, dns.TypeSOA)
	if len(answers) == 0 {
		return errNoEndpoint
	}

	serials := map[uint32][]string{}
	// Distinct SOA contents (ignoring the TTL) and the servers serving them.
	var distinct []*dns.SOA
	servedBy := map[string][]string{}
	for _, a := range answers {
		if a.err != nil {
			r.Add(core.Errorf(a.ep.String(), "no answer: %v", a.err))
			continue
		}
		var soa *dns.SOA
		for _, rr := range a.msg.Answer {
			if s, ok := rr.(*dns.SOA); ok {
				soa = s
			}
		}
		if soa == nil {
			r.Add(core.Errorf(a.ep.String(), "no SOA record in the answer (rcode %s)", rcode(a.msg)))
			continue
		}
		serials[soa.Serial] = append(serials[soa.Serial], a.ep.String())
		k := soaKey(soa)
		if _, ok := servedBy[k]; !ok {
			distinct = append(distinct, soa)
		}
		servedBy[k] = append(servedBy[k], a.ep.String())
	}
	if len(distinct) == 0 {
		return fmt.Errorf("no nameserver returned the SOA record of %s", zone)
	}
	ref := distinct[0]

	r.Add(core.Info(zone, "SOA record",
		fmt.Sprintf("primary nameserver (MNAME): %s", strings.TrimSuffix(ref.Ns, ".")),
		fmt.Sprintf("responsible mailbox (RNAME): %s", mbox(ref.Mbox)),
		fmt.Sprintf("serial: %d, refresh: %s, retry: %s, expire: %s, negative TTL: %s",
			ref.Serial, dur(ref.Refresh), dur(ref.Retry), dur(ref.Expire), dur(ref.Minttl)),
	).WithPoC("dig SOA %s +short", zone))

	if len(serials) > 1 {
		var details []string
		keys := make([]uint32, 0, len(serials))
		for s := range serials {
			keys = append(keys, s)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, s := range keys {
			details = append(details, fmt.Sprintf("serial %d served by %s", s, strings.Join(serials[s], ", ")))
		}
		r.Add(core.Fail(core.SeverityLow, zone, "nameservers serve different SOA serials (zone not synchronized)", details...))
	} else {
		r.Add(core.Pass(zone, fmt.Sprintf("all nameservers serve serial %d", ref.Serial)))
	}

	timersOK := true
	for _, soa := range distinct {
		issues := soaTimerIssues(soa)
		if len(issues) == 0 {
			continue
		}
		timersOK = false
		if len(distinct) > 1 {
			issues = append(issues, "served by "+strings.Join(servedBy[soaKey(soa)], ", "))
		}
		r.Add(core.Fail(core.SeverityLow, zone, "SOA timers deviate from recommended values", issues...))
	}
	if timersOK {
		r.Add(core.Pass(zone, "SOA timers follow recommended values"))
	}

	switch msg, future := serialFormat(ref.Serial, time.Now()); {
	case future:
		r.Add(core.Fail(core.SeverityLow, zone, msg))
	default:
		r.Add(core.Info(zone, msg))
	}
	return nil
}

// soaKey identifies the content of a SOA record regardless of its TTL.
func soaKey(s *dns.SOA) string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", s.Ns, s.Mbox, s.Serial, s.Refresh, s.Retry, s.Expire, s.Minttl)
}

// soaTimerIssues returns the deviations of the SOA timers from RIPE-203,
// RFC 1912 and RFC 2308.
func soaTimerIssues(s *dns.SOA) []string {
	var out []string
	if s.Refresh < 1200 || s.Refresh > 86400 {
		out = append(out, fmt.Sprintf("refresh %s is outside the 20m-24h range (RIPE-203 recommends 24h)", dur(s.Refresh)))
	}
	if s.Retry >= s.Refresh {
		out = append(out, fmt.Sprintf("retry %s should be lower than refresh %s", dur(s.Retry), dur(s.Refresh)))
	} else if s.Retry < 120 || s.Retry > 7200 {
		out = append(out, fmt.Sprintf("retry %s is outside the 2m-2h range (RIPE-203 recommends 2h)", dur(s.Retry)))
	}
	if s.Expire < 604800 {
		out = append(out, fmt.Sprintf("expire %s is shorter than 1 week: secondaries stop answering quickly if the primary is down (RIPE-203 recommends 1000h)", dur(s.Expire)))
	}
	if s.Expire <= s.Refresh+s.Retry {
		out = append(out, fmt.Sprintf("expire %s should be greater than refresh + retry", dur(s.Expire)))
	}
	if s.Minttl > 86400 {
		out = append(out, fmt.Sprintf("negative caching TTL %s is longer than 1 day (RFC 2308 recommends 1-3h)", dur(s.Minttl)))
	} else if s.Minttl < 60 {
		out = append(out, fmt.Sprintf("negative caching TTL %s is very short and increases the load on the nameservers", dur(s.Minttl)))
	}
	return out
}

// serialFormat checks whether serial follows the YYYYMMDDnn convention
// recommended by RIPE-203. It returns a message and whether the encoded date
// is in the future (which breaks future serial increments).
func serialFormat(serial uint32, now time.Time) (string, bool) {
	s := fmt.Sprint(serial)
	if len(s) == 10 {
		if d, err := time.Parse("20060102", s[:8]); err == nil && d.Year() >= 1990 {
			if d.After(now.Add(48 * time.Hour)) {
				return fmt.Sprintf("serial %s encodes a date in the future (%s)", s, d.Format("2006-01-02")), true
			}
			return fmt.Sprintf("serial %s follows the YYYYMMDDnn convention (last change %s)", s, d.Format("2006-01-02")), false
		}
	}
	return fmt.Sprintf("serial %s does not follow the YYYYMMDDnn convention recommended by RIPE-203 (not a security issue)", s), false
}

// mbox converts an RNAME ("hostmaster.example.com.") into an e-mail address.
func mbox(rname string) string {
	rname = strings.TrimSuffix(rname, ".")
	for i := 0; i < len(rname); i++ {
		if rname[i] == '\\' {
			i++
			continue
		}
		if rname[i] == '.' {
			return strings.ReplaceAll(rname[:i], `\.`, ".") + "@" + rname[i+1:]
		}
	}
	return rname
}

func dur(sec uint32) string {
	d := time.Duration(sec) * time.Second
	switch {
	case sec == 0:
		return "0s"
	case sec%86400 == 0:
		return fmt.Sprintf("%dd", sec/86400)
	case sec%3600 == 0:
		return fmt.Sprintf("%dh", sec/3600)
	default:
		return d.String()
	}
}
