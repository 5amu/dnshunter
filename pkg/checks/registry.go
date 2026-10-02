// Package checks is the registry of every available check.
package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/5amu/dnshunter/pkg/checks/bgpchecks"
	"github.com/5amu/dnshunter/pkg/checks/dnschecks"
	"github.com/5amu/dnshunter/pkg/checks/mailchecks"
	"github.com/5amu/dnshunter/pkg/core"
)

// All returns every check, in execution/report order.
func All() []*core.Check {
	return []*core.Check{
		dnschecks.Delegation,
		dnschecks.SOA,
		dnschecks.GLUE,
		dnschecks.AXFR,
		dnschecks.ANY,
		dnschecks.Recursion,
		dnschecks.Version,
		dnschecks.DNSSEC,
		dnschecks.CAA,
		mailchecks.SPF,
		mailchecks.DMARC,
		mailchecks.DKIM,
		bgpchecks.ASN,
		bgpchecks.GEO,
		bgpchecks.ROA,
		bgpchecks.IRR,
	}
}

// Groups maps group names to the categories they select.
var Groups = map[string]string{
	"dns":  core.CategoryDNS,
	"mail": core.CategoryMail,
	"bgp":  core.CategoryBGP,
}

// Select resolves a list of check IDs, aliases and groups ("all", "dns",
// "mail", "bgp"), removes the excluded ones and returns the checks in
// registry order.
func Select(include, exclude []string) ([]*core.Check, error) {
	all := All()
	resolve := func(names []string) (map[string]bool, error) {
		set := map[string]bool{}
		for _, n := range names {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" {
				continue
			}
			if n == "all" {
				for _, c := range all {
					set[c.ID] = true
				}
				continue
			}
			if cat, ok := Groups[n]; ok {
				for _, c := range all {
					if c.Category == cat {
						set[c.ID] = true
					}
				}
				continue
			}
			c := Lookup(n)
			if c == nil {
				return nil, fmt.Errorf("unknown check %q (use -list to see the available checks)", n)
			}
			set[c.ID] = true
		}
		return set, nil
	}
	if len(include) == 0 {
		include = []string{"all"}
	}
	in, err := resolve(include)
	if err != nil {
		return nil, err
	}
	out, err := resolve(exclude)
	if err != nil {
		return nil, err
	}
	var selected []*core.Check
	for _, c := range all {
		if in[c.ID] && !out[c.ID] {
			selected = append(selected, c)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no check selected")
	}
	return selected, nil
}

// Lookup returns the check with the given ID or alias.
func Lookup(name string) *core.Check {
	name = strings.ToLower(name)
	for _, c := range All() {
		if c.ID == name {
			return c
		}
		for _, a := range c.Aliases {
			if a == name {
				return c
			}
		}
	}
	return nil
}

// GroupNames returns the sorted group names.
func GroupNames() []string {
	var out []string
	for g := range Groups {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}
