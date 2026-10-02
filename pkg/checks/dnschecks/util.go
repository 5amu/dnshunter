package dnschecks

import (
	"net"
	"sort"
)

func sortStrings(s []string) []string {
	sort.Strings(s)
	return s
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return sortStrings(out)
}

// diffIPs returns the glue addresses not served by the zone (stale) and the
// served addresses of a family present in the glue that the glue lacks.
func diffIPs(glue, auth []string) (stale, missing []string) {
	in := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	family := map[bool]bool{}
	for _, g := range glue {
		family[net.ParseIP(g).To4() != nil] = true
		if !in(auth, g) {
			stale = append(stale, g)
		}
	}
	for _, a := range auth {
		if family[net.ParseIP(a).To4() != nil] && !in(glue, a) {
			missing = append(missing, a)
		}
	}
	return stale, missing
}
