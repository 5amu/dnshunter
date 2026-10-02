// Package dnsutil wraps github.com/miekg/dns with the primitives dnshunter
// needs: queries with retries and TCP fallback, recursive lookups through a
// configurable set of resolvers, zone discovery and delegation inspection.
package dnsutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DefaultResolvers are used when the user does not provide any.
var DefaultResolvers = []string{"8.8.8.8", "1.1.1.1"}

// Client performs DNS queries. It is safe for concurrent use.
type Client struct {
	// Resolvers are the recursive resolvers (host:port) used by Lookup*.
	Resolvers []string
	// Timeout is the per-attempt timeout.
	Timeout time.Duration
	// Retries is the number of additional attempts after a network error.
	Retries int
	// Port is the port used to contact authoritative nameservers (default 53).
	Port string
	// Overrides maps nameserver IPs to the host:port actually contacted
	// (used by tests and to reach servers behind port forwarding).
	Overrides map[string]string

	udp *dns.Client
	tcp *dns.Client
}

// New returns a client using the given resolvers (IP or host:port).
func New(resolvers []string, timeout time.Duration, retries int) *Client {
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if retries < 0 {
		retries = 0
	}
	c := &Client{
		Timeout: timeout,
		Retries: retries,
		Port:    "53",
		udp:     &dns.Client{Net: "udp", Timeout: timeout, UDPSize: dns.DefaultMsgSize},
		tcp:     &dns.Client{Net: "tcp", Timeout: timeout},
	}
	for _, r := range resolvers {
		c.Resolvers = append(c.Resolvers, WithPort(r, "53"))
	}
	return c
}

// WithPort appends port to host when it does not carry one already.
func WithPort(host, port string) string {
	host = strings.TrimSpace(host)
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}

// Addr returns the address used to contact an authoritative server on ip.
func (c *Client) Addr(ip net.IP) string {
	if a, ok := c.Overrides[ip.String()]; ok {
		return a
	}
	return net.JoinHostPort(ip.String(), c.Port)
}

// QueryOption customizes an outgoing message.
type QueryOption func(*dns.Msg)

// NoRecurse clears the RD bit, as appropriate for authoritative queries.
func NoRecurse() QueryOption { return func(m *dns.Msg) { m.RecursionDesired = false } }

// DNSSEC sets the DO bit (and EDNS0 with a 1232 bytes buffer).
func DNSSEC() QueryOption {
	return func(m *dns.Msg) {
		if o := m.IsEdns0(); o != nil {
			o.SetDo()
			return
		}
		m.SetEdns0(1232, true)
	}
}

// BufSize sets the advertised EDNS0 UDP buffer size.
func BufSize(size uint16) QueryOption {
	return func(m *dns.Msg) {
		if o := m.IsEdns0(); o != nil {
			o.SetUDPSize(size)
			return
		}
		m.SetEdns0(size, false)
	}
}

// Class sets the class of the question (e.g. dns.ClassCHAOS).
func Class(class uint16) QueryOption {
	return func(m *dns.Msg) { m.Question[0].Qclass = class }
}

// NewMsg builds a question for name/qtype with sensible defaults (RD set,
// EDNS0 with a 1232 bytes buffer as recommended by DNS flag day 2020).
func NewMsg(name string, qtype uint16, opts ...QueryOption) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)
	for _, o := range opts {
		o(m)
	}
	return m
}

// Exchange sends m to server, retrying on network errors and falling back to
// TCP when the UDP answer is truncated.
func (c *Client) Exchange(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
	r, err := c.exchange(ctx, c.udp, m, server)
	if err != nil {
		return nil, err
	}
	if r.Truncated {
		tr, terr := c.exchange(ctx, c.tcp, m, server)
		if terr != nil {
			// A truncated answer is incomplete: using it would turn "too big
			// for UDP" into "no such record".
			return nil, fmt.Errorf("answer truncated over UDP and TCP fallback failed: %w", terr)
		}
		return tr, nil
	}
	return r, nil
}

// ExchangeUDP sends m over UDP only (no TCP fallback on truncation).
func (c *Client) ExchangeUDP(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
	return c.exchange(ctx, c.udp, m, server)
}

// ExchangeTCP sends m over TCP only.
func (c *Client) ExchangeTCP(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
	return c.exchange(ctx, c.tcp, m, server)
}

func (c *Client) exchange(ctx context.Context, dc *dns.Client, m *dns.Msg, server string) (*dns.Msg, error) {
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		actx, cancel := context.WithTimeout(ctx, c.Timeout)
		// Each attempt must use a fresh ID, otherwise late answers to a
		// previous attempt could be accepted.
		mm := m.Copy()
		mm.Id = dns.Id()
		r, _, err := dc.ExchangeContext(actx, mm, server)
		cancel()
		if err == nil {
			return r, nil
		}
		if cerr := contextDone(ctx); cerr != nil {
			// Report the caller's cancellation rather than the I/O error it
			// caused, so callers can tell the two apart.
			return nil, fmt.Errorf("query %s %s to %s: %w", m.Question[0].Name, dns.TypeToString[m.Question[0].Qtype], server, cerr)
		}
		lastErr = err
	}
	return nil, fmt.Errorf("query %s %s to %s: %w", m.Question[0].Name, dns.TypeToString[m.Question[0].Qtype], server, lastErr)
}

// contextDone returns the context error, also when the deadline has passed
// but the context timer has not fired yet (the socket deadline, set to the
// same instant, usually expires first).
func contextDone(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
		return context.DeadlineExceeded
	}
	return nil
}

// Query asks server (host:port) about name/qtype.
func (c *Client) Query(ctx context.Context, server, name string, qtype uint16, opts ...QueryOption) (*dns.Msg, error) {
	return c.Exchange(ctx, NewMsg(name, qtype, opts...), server)
}

// ErrNoResolver is returned when every configured resolver failed.
var ErrNoResolver = errors.New("no resolver returned a usable answer")

// Lookup performs a recursive query, with the CD bit set, through the
// configured resolvers. The first answer whose rcode is not SERVFAIL/REFUSED
// is returned; NXDOMAIN and NODATA answers are returned as-is so callers can
// tell them apart.
func (c *Client) Lookup(ctx context.Context, name string, qtype uint16, opts ...QueryOption) (*dns.Msg, error) {
	m := NewMsg(name, qtype, opts...)
	// Disable DNSSEC validation on the resolver: a zone with a broken chain
	// of trust must still be analyzable (dnshunter validates it itself).
	m.CheckingDisabled = true
	lastErr := ErrNoResolver
	for _, res := range c.Resolvers {
		r, err := c.Exchange(ctx, m, res)
		if err != nil {
			lastErr = err
			continue
		}
		if r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused {
			lastErr = fmt.Errorf("%s answered %s for %s %s", res, dns.RcodeToString[r.Rcode], name, dns.TypeToString[qtype])
			continue
		}
		return r, nil
	}
	return nil, lastErr
}

// LookupTXT returns the TXT records of name (each record's strings joined),
// along with the rcode of the answer.
func (c *Client) LookupTXT(ctx context.Context, name string) ([]string, int, error) {
	r, err := c.Lookup(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, 0, err
	}
	return TXTStrings(r.Answer), r.Rcode, nil
}

// TXTStrings extracts TXT records from rrs, joining the character-strings of
// every record as mandated by RFC 7208 §3.3 and RFC 6376 §3.6.2.2.
func TXTStrings(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}

// LookupIPs resolves the A and AAAA records of name.
func (c *Client) LookupIPs(ctx context.Context, name string) ([]net.IP, error) {
	var ips []net.IP
	var errs []error
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		r, err := c.Lookup(ctx, name, qt)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, rr := range r.Answer {
			switch t := rr.(type) {
			case *dns.A:
				ips = appendIP(ips, t.A)
			case *dns.AAAA:
				ips = appendIP(ips, t.AAAA)
			}
		}
	}
	if len(ips) == 0 && len(errs) == 2 {
		return nil, errors.Join(errs...)
	}
	return ips, nil
}

func appendIP(ips []net.IP, ip net.IP) []net.IP {
	for _, x := range ips {
		if x.Equal(ip) {
			return ips
		}
	}
	return append(ips, ip)
}

// LookupNS returns the sorted nameserver names (lowercase, no trailing dot)
// for zone.
func (c *Client) LookupNS(ctx context.Context, zone string) ([]string, error) {
	r, err := c.Lookup(ctx, zone, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("NS lookup for %s: %s", zone, dns.RcodeToString[r.Rcode])
	}
	return NSNames(r.Answer, zone), nil
}

// NSNames extracts the NS targets owned by zone from rrs.
func NSNames(rrs []dns.RR, zone string) []string {
	seen := map[string]bool{}
	var out []string
	for _, rr := range rrs {
		ns, ok := rr.(*dns.NS)
		if !ok || !strings.EqualFold(ns.Hdr.Name, dns.Fqdn(zone)) {
			continue
		}
		name := Canonical(ns.Ns)
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// FindZone returns the apex of the zone that contains name, walking up the
// tree until a SOA record owned by the candidate is found.
func (c *Client) FindZone(ctx context.Context, name string) (string, error) {
	name = Canonical(name)
	for candidate := name; ; candidate = Parent(candidate) {
		r, err := c.Lookup(ctx, candidate, dns.TypeSOA)
		if err != nil {
			return "", err
		}
		if candidate == name && r.Rcode == dns.RcodeNameError {
			return "", fmt.Errorf("%s does not exist (NXDOMAIN)", name)
		}
		for _, rr := range r.Answer {
			if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, dns.Fqdn(candidate)) {
				return candidate, nil
			}
		}
		if candidate == "." {
			return "", fmt.Errorf("could not find the zone containing %s", name)
		}
	}
}

// Delegation describes the referral returned by a parent zone server.
type Delegation struct {
	Parent     string              `json:"parent"`
	Server     string              `json:"server"`
	ServerAddr string              `json:"server_addr"`
	NS         []string            `json:"ns"`
	Glue       map[string][]net.IP `json:"glue,omitempty"`
}

// Delegation queries the servers of the parent zone (non recursively) for the
// NS records of zone, returning the delegation NS set and glue records.
func (c *Client) Delegation(ctx context.Context, zone string) (*Delegation, error) {
	zone = Canonical(zone)
	if zone == "." {
		return nil, errors.New("the root zone has no parent")
	}
	parent, err := c.FindZone(ctx, Parent(zone))
	if err != nil {
		return nil, fmt.Errorf("finding parent zone: %w", err)
	}
	servers, err := c.LookupNS(ctx, parent)
	if err != nil {
		return nil, fmt.Errorf("finding %s nameservers: %w", parent, err)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no nameserver found for parent zone %s", parent)
	}
	lastErr := fmt.Errorf("no %s server answered", parent)
	tried := 0
	for _, srv := range servers {
		if tried >= 3 {
			break
		}
		ips, err := c.LookupIPs(ctx, srv)
		if err != nil || len(ips) == 0 {
			continue
		}
		ip := firstIPv4(ips)
		tried++
		addr := c.Addr(ip)
		r, err := c.Query(ctx, addr, zone, dns.TypeNS, NoRecurse())
		if err != nil {
			lastErr = err
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("%s answered %s", srv, dns.RcodeToString[r.Rcode])
			continue
		}
		d := &Delegation{Parent: parent, Server: srv, ServerAddr: addr, Glue: map[string][]net.IP{}}
		d.NS = NSNames(r.Ns, zone)
		if len(d.NS) == 0 {
			// The parent server is also authoritative for the child (or the
			// answer was synthesized by an intercepting resolver).
			d.NS = NSNames(r.Answer, zone)
		}
		if len(d.NS) == 0 {
			lastErr = fmt.Errorf("%s returned no delegation for %s", srv, zone)
			continue
		}
		for _, rr := range r.Extra {
			switch t := rr.(type) {
			case *dns.A:
				n := Canonical(t.Hdr.Name)
				d.Glue[n] = appendIP(d.Glue[n], t.A)
			case *dns.AAAA:
				n := Canonical(t.Hdr.Name)
				d.Glue[n] = appendIP(d.Glue[n], t.AAAA)
			}
		}
		return d, nil
	}
	return nil, lastErr
}

func firstIPv4(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	return ips[0]
}

// rootServer is a.root-servers.net, used to detect DNS interception.
const rootServer = "198.41.0.4"

// DetectInterception checks whether outgoing DNS traffic is transparently
// redirected to a recursive resolver (common on corporate and sandboxed
// networks). It sends a non-recursive query for a TLD-delegated name to a root
// server: a genuine root server only returns a referral, never an answer.
// It returns true when interception is detected.
func (c *Client) DetectInterception(ctx context.Context) (bool, error) {
	r, err := c.ExchangeUDP(ctx, NewMsg("example.com", dns.TypeA, NoRecurse()), c.Addr(net.ParseIP(rootServer)))
	if err != nil {
		return false, err
	}
	return len(r.Answer) > 0 || r.RecursionAvailable, nil
}
