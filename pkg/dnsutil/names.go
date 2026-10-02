package dnsutil

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Canonical lowercases name and strips the trailing dot ("." stays ".").
func Canonical(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "." || name == "" {
		return "."
	}
	return strings.TrimSuffix(name, ".")
}

// Parent returns the parent of name ("example.com" -> "com", "com" -> ".").
func Parent(name string) string {
	name = Canonical(name)
	if name == "." {
		return "."
	}
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return "."
}

// IsSubdomain reports whether child is equal to or below parent.
func IsSubdomain(parent, child string) bool {
	return dns.IsSubDomain(dns.Fqdn(Canonical(parent)), dns.Fqdn(Canonical(child)))
}

// NormalizeDomain converts user input (possibly a URL, an IDN or a name with a
// trailing dot) into a canonical ASCII domain name.
func NormalizeDomain(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", fmt.Errorf("empty domain")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("invalid URL %q: %w", input, err)
		}
		s = u.Hostname()
	} else if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if net.ParseIP(s) != nil {
		return "", fmt.Errorf("%q is an IP address, not a domain", input)
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", input, err)
	}
	if _, ok := dns.IsDomainName(ascii); !ok || !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("invalid domain %q", input)
	}
	if ps, _ := publicsuffix.PublicSuffix(ascii); ps == ascii {
		return "", fmt.Errorf("%q is a public suffix, provide a registrable domain", input)
	}
	return ascii, nil
}

// OrgDomain returns the organizational domain (public suffix + 1 label) of
// name, as defined by RFC 7489 §3.2. It returns name itself on error.
func OrgDomain(name string) string {
	org, err := publicsuffix.EffectiveTLDPlusOne(Canonical(name))
	if err != nil {
		return Canonical(name)
	}
	return org
}

// IsPublicSuffix reports whether name is a public suffix (e.g. "co.uk").
func IsPublicSuffix(name string) bool {
	name = Canonical(name)
	if name == "." {
		return true
	}
	ps, _ := publicsuffix.PublicSuffix(name)
	return ps == name
}

// ReverseLabels returns the reverse-mapping labels of ip without the
// in-addr.arpa / ip6.arpa suffix (e.g. "4.3.2.1" for 1.2.3.4).
func ReverseLabels(ip net.IP) string {
	rev, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return ""
	}
	rev = strings.TrimSuffix(rev, ".")
	rev = strings.TrimSuffix(rev, ".in-addr.arpa")
	return strings.TrimSuffix(rev, ".ip6.arpa")
}
