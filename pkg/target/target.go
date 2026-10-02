// Package target discovers the DNS infrastructure of the domain under test:
// its zone, authoritative nameservers (and their addresses), the delegation
// at the parent zone and the addresses the domain points to.
package target

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/5amu/dnshunter/pkg/dnsutil"
)

// Nameserver is an authoritative nameserver of the zone.
type Nameserver struct {
	Name string   `json:"name"`
	IPs  []net.IP `json:"ips"`
	// Error is set when the nameserver name could not be resolved.
	Error string `json:"error,omitempty"`
}

// Endpoint is a single address of a nameserver.
type Endpoint struct {
	NS string
	IP net.IP
}

func (e Endpoint) String() string { return fmt.Sprintf("%s (%s)", e.NS, e.IP) }

// Target holds everything known about the domain under test.
type Target struct {
	// Domain is the (normalized) domain provided by the user.
	Domain string `json:"domain"`
	// Zone is the apex of the zone containing Domain.
	Zone string `json:"zone"`
	// Nameservers are the authoritative servers of Zone.
	Nameservers []Nameserver `json:"nameservers"`
	// Delegation is the referral returned by the parent zone (may be nil).
	Delegation    *dnsutil.Delegation `json:"delegation,omitempty"`
	DelegationErr string              `json:"delegation_error,omitempty"`
	// Addresses are the A/AAAA records of AddressHost.
	Addresses   []net.IP `json:"addresses"`
	AddressHost string   `json:"address_host"`
}

// Discover resolves the zone, nameservers, delegation and addresses of domain.
func Discover(ctx context.Context, c *dnsutil.Client, domain string) (*Target, error) {
	domain, err := dnsutil.NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	t := &Target{Domain: domain}

	if t.Zone, err = c.FindZone(ctx, domain); err != nil {
		return nil, err
	}
	if dnsutil.IsPublicSuffix(t.Zone) {
		return nil, fmt.Errorf("%s is not delegated: the closest zone is the public suffix %s", domain, t.Zone)
	}

	names, err := c.LookupNS(ctx, t.Zone)
	if err != nil {
		return nil, fmt.Errorf("looking up nameservers of %s: %w", t.Zone, err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no nameserver found for %s", t.Zone)
	}

	var wg sync.WaitGroup
	t.Nameservers = make([]Nameserver, len(names))
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			ns := Nameserver{Name: n}
			ips, err := c.LookupIPs(ctx, n)
			switch {
			case err != nil:
				ns.Error = err.Error()
			case len(ips) == 0:
				ns.Error = "no A/AAAA record"
			}
			ns.IPs = sortIPs(ips)
			t.Nameservers[i] = ns
		}(i, n)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		d, err := c.Delegation(ctx, t.Zone)
		if err != nil {
			t.DelegationErr = err.Error()
			return
		}
		t.Delegation = d
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		t.AddressHost = domain
		ips, _ := c.LookupIPs(ctx, domain)
		if len(ips) == 0 && domain == t.Zone {
			if www, _ := c.LookupIPs(ctx, "www."+domain); len(www) > 0 {
				t.AddressHost, ips = "www."+domain, www
			}
		}
		t.Addresses = sortIPs(ips)
	}()
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return t, nil
}

// Endpoints returns one entry per nameserver address. IPv6 addresses are only
// included when ipv6 is true or when a nameserver has no IPv4 address.
func (t *Target) Endpoints(ipv6 bool) []Endpoint {
	var out []Endpoint
	for _, ns := range t.Nameservers {
		hasV4 := false
		for _, ip := range ns.IPs {
			if ip.To4() != nil {
				hasV4 = true
			}
		}
		for _, ip := range ns.IPs {
			if ip.To4() == nil && hasV4 && !ipv6 {
				continue
			}
			out = append(out, Endpoint{NS: ns.Name, IP: ip})
		}
	}
	return out
}

// NameserverNames returns the names of the authoritative nameservers.
func (t *Target) NameserverNames() []string {
	out := make([]string, 0, len(t.Nameservers))
	for _, ns := range t.Nameservers {
		out = append(out, ns.Name)
	}
	return out
}

// sortIPs orders IPv4 addresses before IPv6 ones, numerically.
func sortIPs(ips []net.IP) []net.IP {
	sort.SliceStable(ips, func(i, j int) bool {
		a4, b4 := ips[i].To4() != nil, ips[j].To4() != nil
		if a4 != b4 {
			return a4
		}
		return string(ips[i].To16()) < string(ips[j].To16())
	})
	return ips
}
