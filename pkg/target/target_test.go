package target_test

import (
	"context"
	"testing"

	"github.com/5amu/dnshunter/internal/testenv"
	"github.com/5amu/dnshunter/pkg/target"
)

func TestDiscover(t *testing.T) {
	w := testenv.New(t)
	w.All("www.example.test. 300 IN A 45.33.30.4")
	tg, err := target.Discover(context.Background(), w.Client, "https://WWW.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Domain != "www.example.test" || tg.Zone != "example.test" {
		t.Fatalf("domain/zone = %s/%s", tg.Domain, tg.Zone)
	}
	if len(tg.Nameservers) != 2 || tg.Nameservers[0].Name != "ns1.example.test" || len(tg.Nameservers[0].IPs) != 1 {
		t.Fatalf("nameservers = %+v", tg.Nameservers)
	}
	if tg.Delegation == nil || len(tg.Delegation.NS) != 2 {
		t.Fatalf("delegation = %+v (%s)", tg.Delegation, tg.DelegationErr)
	}
	if len(tg.Addresses) != 1 || tg.Addresses[0].String() != "45.33.30.4" {
		t.Fatalf("addresses = %v", tg.Addresses)
	}
	if eps := tg.Endpoints(false); len(eps) != 2 {
		t.Fatalf("endpoints = %v", eps)
	}
}

func TestDiscoverFallsBackToWWW(t *testing.T) {
	w := testenv.New(t)
	w.Resolver.Remove("example.test", 1)
	w.All("www.example.test. 300 IN A 45.33.30.9")
	tg, err := target.Discover(context.Background(), w.Client, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if tg.AddressHost != "www.example.test" || len(tg.Addresses) != 1 {
		t.Fatalf("address host = %s %v", tg.AddressHost, tg.Addresses)
	}
}

func TestDiscoverErrors(t *testing.T) {
	w := testenv.New(t)
	if _, err := target.Discover(context.Background(), w.Client, "missing.example.test"); err == nil {
		t.Fatal("expected NXDOMAIN error")
	}
	if _, err := target.Discover(context.Background(), w.Client, "co.uk"); err == nil {
		t.Fatal("expected public suffix error")
	}
}
