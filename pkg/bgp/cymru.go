package bgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/miekg/dns"
)

// ErrNotRouted is returned when no BGP origin is known for an address.
var ErrNotRouted = errors.New("no BGP route found")

// cymruZone is Team Cymru's IP to ASN mapping service, queried over DNS.
// See https://www.team-cymru.com/ip-asn-mapping
const cymruZone = "asn.cymru.com"

// Cymru queries Team Cymru's IP to ASN mapping service over DNS.
type Cymru struct {
	DNS *dnsutil.Client
	// Zone overrides cymruZone (used by tests).
	Zone string
}

func (c *Cymru) zone() string {
	if c.Zone != "" {
		return c.Zone
	}
	return cymruZone
}

func (c *Cymru) originName(ip net.IP, kind string) string {
	if ip.To4() != nil {
		return fmt.Sprintf("%s.%s.%s", dnsutil.ReverseLabels(ip), kind, c.zone())
	}
	return fmt.Sprintf("%s.%s6.%s", dnsutil.ReverseLabels(ip), kind, c.zone())
}

func (c *Cymru) txt(ctx context.Context, name string) ([]string, error) {
	recs, rcode, err := c.DNS.LookupTXT(ctx, name)
	if err != nil {
		return nil, err
	}
	if rcode == dns.RcodeNameError || len(recs) == 0 {
		return nil, ErrNotRouted
	}
	return recs, nil
}

// Origin returns the origin AS(es) and the most specific announced prefix
// covering ip.
func (c *Cymru) Origin(ctx context.Context, ip net.IP) (*Origin, error) {
	recs, err := c.txt(ctx, c.originName(ip, "origin"))
	if err != nil {
		return nil, err
	}
	var best *Origin
	for _, rec := range recs {
		o, err := parseCymruOrigin(rec)
		if err != nil {
			continue
		}
		if best == nil || o.prefixLen() > best.prefixLen() {
			best = o
		}
	}
	if best == nil {
		return nil, fmt.Errorf("unparsable Team Cymru answer: %q", recs)
	}
	best.IP = ip
	best.Source = "team-cymru"
	return best, nil
}

// Peers returns the ASes Team Cymru sees as BGP neighbours of the origin AS of
// ip (IPv4 only); in practice these are the upstream providers.
func (c *Cymru) Peers(ctx context.Context, ip net.IP) ([]uint32, error) {
	if ip.To4() == nil {
		return nil, errors.New("peer lookup only supports IPv4")
	}
	recs, err := c.txt(ctx, c.originName(ip, "peer"))
	if err != nil {
		return nil, err
	}
	seen := map[uint32]bool{}
	var out []uint32
	for _, rec := range recs {
		fields := splitPipe(rec)
		if len(fields) == 0 {
			continue
		}
		for _, a := range strings.Fields(fields[0]) {
			if n, err := ParseASN(a); err == nil && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out, nil
}

// AS returns registration details of an autonomous system.
func (c *Cymru) AS(ctx context.Context, asn uint32) (*ASInfo, error) {
	recs, err := c.txt(ctx, fmt.Sprintf("AS%d.%s", asn, c.zone()))
	if err != nil {
		return nil, err
	}
	return parseCymruAS(recs[0])
}

// parseCymruOrigin parses "15169 | 8.8.8.0/24 | US | arin | 2023-12-28".
// Multi-origin prefixes list several ASNs separated by spaces.
func parseCymruOrigin(rec string) (*Origin, error) {
	f := splitPipe(rec)
	if len(f) < 2 {
		return nil, fmt.Errorf("unexpected record %q", rec)
	}
	o := &Origin{}
	for _, a := range strings.Fields(f[0]) {
		n, err := ParseASN(a)
		if err != nil {
			return nil, err
		}
		o.ASNs = append(o.ASNs, n)
	}
	if len(o.ASNs) == 0 {
		return nil, fmt.Errorf("no ASN in %q", rec)
	}
	p, err := netip.ParsePrefix(f[1])
	if err != nil {
		return nil, err
	}
	o.Prefix = p.Masked().String()
	if len(f) > 2 {
		o.Country = f[2]
	}
	if len(f) > 3 {
		o.Registry = f[3]
	}
	if len(f) > 4 {
		o.Allocated = f[4]
	}
	return o, nil
}

// parseCymruAS parses "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US".
func parseCymruAS(rec string) (*ASInfo, error) {
	f := splitPipe(rec)
	if len(f) < 5 {
		return nil, fmt.Errorf("unexpected record %q", rec)
	}
	n, err := ParseASN(f[0])
	if err != nil {
		return nil, err
	}
	return &ASInfo{ASN: n, Country: f[1], Registry: f[2], Allocated: f[3], Name: strings.Join(f[4:], "|")}, nil
}

func splitPipe(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// ParseASN parses "AS15169", "as15169" or "15169".
func ParseASN(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if len(s) > 2 && strings.EqualFold(s[:2], "as") {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid ASN %q", s)
	}
	return uint32(n), nil
}
