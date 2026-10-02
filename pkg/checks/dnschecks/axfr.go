package dnschecks

import (
	"context"
	"fmt"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/target"
	"github.com/miekg/dns"
)

// maxZoneDetails caps the number of transferred records listed in a finding.
const maxZoneDetails = 500

// AXFR checks whether nameservers allow unauthenticated zone transfers.
var AXFR = &core.Check{
	ID:       "zone",
	Aliases:  []string{"axfr"},
	Name:     "Unprotected zone transfer (AXFR)",
	Category: core.CategoryDNS,
	Description: "Nameservers that allow zone transfers (AXFR) to anyone disclose the full content " +
		"of the zone: internal hostnames, addresses and services, greatly helping reconnaissance. " +
		"Transfers should be restricted to secondary servers and authenticated with TSIG.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc5936#section-6",
		"https://www.cisa.gov/news-events/alerts/2015/04/13/dns-zone-transfer-axfr-requests-may-leak-domain-information",
	},
	Run: runAXFR,
}

func runAXFR(ctx context.Context, env *core.Env, r *core.Result) error {
	zone := env.Target.Zone
	eps := env.Target.Endpoints(env.Opts.IPv6)
	if len(eps) == 0 {
		return errNoEndpoint
	}
	findings := core.ParallelMap(eps, parallelism, func(ep target.Endpoint) core.Finding {
		return tryAXFR(ctx, env, ep, zone)
	})
	r.Add(findings...)
	return nil
}

func tryAXFR(ctx context.Context, env *core.Env, ep target.Endpoint, zone string) core.Finding {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))
	tr := &dns.Transfer{
		DialTimeout:  env.DNS.Timeout,
		ReadTimeout:  3 * env.DNS.Timeout,
		WriteTimeout: env.DNS.Timeout,
	}
	ch, err := tr.In(m, env.DNS.Addr(ep.IP))
	if err != nil {
		return core.Errorf(ep.String(), "could not connect over TCP: %v", err)
	}
	var records []dns.RR
	var transferErr error
	for env := range ch {
		if env.Error != nil {
			transferErr = env.Error
			break
		}
		records = append(records, env.RR...)
	}
	// Drain the channel so the transfer goroutine can exit.
	go func() {
		for range ch {
		}
	}()
	if ctx.Err() != nil {
		return core.Errorf(ep.String(), "interrupted: %v", ctx.Err())
	}
	if len(records) == 0 {
		reason := "zone transfer refused"
		if transferErr != nil {
			reason = fmt.Sprintf("zone transfer refused (%v)", transferErr)
		}
		return core.Pass(ep.String(), reason)
	}

	names := map[string]bool{}
	var details []string
	for _, rr := range records {
		names[strings.ToLower(rr.Header().Name)] = true
		if len(details) < maxZoneDetails {
			details = append(details, strings.ReplaceAll(rr.String(), "\t", " "))
		}
	}
	if len(records) > maxZoneDetails {
		details = append(details, fmt.Sprintf("... %d more records", len(records)-maxZoneDetails))
	}
	title := fmt.Sprintf("zone transfer allowed: %d records, %d names disclosed", len(records), len(names))
	if transferErr != nil {
		title += fmt.Sprintf(" (transfer interrupted: %v)", transferErr)
	}
	return core.Fail(core.SeverityHigh, ep.String(), title, details...).
		WithPoC("%s", digAt(ep, fmt.Sprintf("AXFR %s", zone)))
}
