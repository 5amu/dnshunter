package bgp

import (
	"net"
	"net/netip"
)

// specialPurpose lists IANA special-purpose ranges that are not globally
// routable (RFC 6890 and updates).
var specialPurpose = []struct {
	prefix netip.Prefix
	desc   string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "\"this network\" (RFC 791)"},
	{netip.MustParsePrefix("10.0.0.0/8"), "private network (RFC 1918)"},
	{netip.MustParsePrefix("100.64.0.0/10"), "shared address space / CGNAT (RFC 6598)"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback (RFC 1122)"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local (RFC 3927)"},
	{netip.MustParsePrefix("172.16.0.0/12"), "private network (RFC 1918)"},
	{netip.MustParsePrefix("192.0.0.0/24"), "IETF protocol assignments (RFC 6890)"},
	{netip.MustParsePrefix("192.0.2.0/24"), "documentation TEST-NET-1 (RFC 5737)"},
	{netip.MustParsePrefix("192.168.0.0/16"), "private network (RFC 1918)"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmarking (RFC 2544)"},
	{netip.MustParsePrefix("198.51.100.0/24"), "documentation TEST-NET-2 (RFC 5737)"},
	{netip.MustParsePrefix("203.0.113.0/24"), "documentation TEST-NET-3 (RFC 5737)"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast (RFC 5771)"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved (RFC 1112)"},
	{netip.MustParsePrefix("::/128"), "unspecified address (RFC 4291)"},
	{netip.MustParsePrefix("::1/128"), "loopback (RFC 4291)"},
	{netip.MustParsePrefix("::ffff:0:0/96"), "IPv4-mapped address (RFC 4291)"},
	{netip.MustParsePrefix("100::/64"), "discard-only (RFC 6666)"},
	{netip.MustParsePrefix("2001:db8::/32"), "documentation (RFC 3849)"},
	{netip.MustParsePrefix("fc00::/7"), "unique local address (RFC 4193)"},
	{netip.MustParsePrefix("fe80::/10"), "link-local (RFC 4291)"},
	{netip.MustParsePrefix("ff00::/8"), "multicast (RFC 4291)"},
}

// ReservedRange returns a description of the special-purpose range containing
// ip, or "" when ip is a global unicast address.
func ReservedRange(ip net.IP) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "invalid address"
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, sp := range specialPurpose {
		if sp.prefix.Contains(addr) {
			return sp.desc
		}
	}
	return ""
}
