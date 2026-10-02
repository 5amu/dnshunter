package checks

import (
	"testing"

	"github.com/5amu/dnshunter/pkg/core"
)

func TestSelect(t *testing.T) {
	all, err := Select(nil, nil)
	if err != nil || len(all) != len(All()) {
		t.Fatalf("Select(all) = %d, %v", len(all), err)
	}
	got, err := Select([]string{"SPF", "axfr", "rpki", "spf"}, nil)
	if err != nil || len(got) != 3 || got[0].ID != "zone" || got[1].ID != "spf" || got[2].ID != "roa" {
		t.Fatalf("Select = %v, %v", ids(got), err)
	}
	got, err = Select([]string{"bgp", "mail"}, []string{"geo", "dkim"})
	if err != nil || len(got) != 5 {
		t.Fatalf("Select(groups) = %v, %v", ids(got), err)
	}
	if _, err := Select([]string{"nope"}, nil); err == nil {
		t.Fatal("expected unknown check error")
	}
	if _, err := Select([]string{"spf"}, []string{"mail"}); err == nil {
		t.Fatal("expected empty selection error")
	}
}

func TestRegistryIntegrity(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		for _, n := range append([]string{c.ID}, c.Aliases...) {
			if seen[n] {
				t.Errorf("duplicate check name %q", n)
			}
			seen[n] = true
		}
		if c.Run == nil || c.Name == "" || c.Description == "" || c.Category == "" {
			t.Errorf("incomplete check %q", c.ID)
		}
	}
	// Every check advertised by the original tool must exist.
	for _, id := range []string{"soa", "any", "glue", "zone", "dnssec", "spf", "dmarc", "dkim", "geo", "irr", "roa"} {
		if Lookup(id) == nil {
			t.Errorf("missing check %q", id)
		}
	}
}

func ids(cs []*core.Check) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}
