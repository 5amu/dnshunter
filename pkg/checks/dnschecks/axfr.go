package dnschecks

import (
	"context"
	"fmt"
	"net"
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
	addr := env.DNS.Addr(ep.IP)
	d := net.Dialer{Timeout: env.DNS.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return core.Errorf(ep.String(), "could not connect over TCP: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// Closing the connection when the check is cancelled unblocks the
	// transfer goroutine, even on a server that trickles data slowly.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	tr := &dns.Transfer{
		Conn:         &dns.Conn{Conn: conn},
		ReadTimeout:  3 * env.DNS.Timeout,
		WriteTimeout: env.DNS.Timeout,
	}
	ch, err := tr.In(m, addr)
	if err != nil {
		return core.Errorf(ep.String(), "could not send the AXFR query: %v", err)
	}
	// Drain the channel on return so the transfer goroutine can exit.
	defer func() {
		go func() {
			for range ch {
			}
		}()
	}()

	var records []dns.RR
	var transferErr error
loop:
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				break loop
			}
			if e.Error != nil {
				transferErr = e.Error
				break loop
			}
			records = append(records, e.RR...)
		case <-ctx.Done():
			transferErr = ctx.Err()
			break loop
		}
	}
	// A transfer starts and ends with the SOA record: a lone SOA is not a
	// disclosure of the zone content.
	if len(records) < 2 {
		if ctx.Err() != nil {
			return core.Errorf(ep.String(), "zone transfer interrupted: %v", ctx.Err())
		}
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
