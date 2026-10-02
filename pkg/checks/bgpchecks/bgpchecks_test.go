package bgpchecks_test

import (
	"strings"
	"testing"

	"github.com/5amu/dnshunter/internal/testenv"
	"github.com/5amu/dnshunter/pkg/checks/bgpchecks"
	"github.com/5amu/dnshunter/pkg/core"
)

const (
	pass = core.StatusPass
	fail = core.StatusFail
	info = core.StatusInfo
	skip = core.StatusSkip
	none = core.SeverityNone
	low  = core.SeverityLow
	med  = core.SeverityMedium
	high = core.SeverityHigh
)

// world maps the nameservers and the web server to three independent ASes.
func world(t *testing.T) *testenv.World {
	w := testenv.New(t)
	w.Origin(testenv.NS1IP, "64501", "45.33.10.0/24", "IT", "TRANSIT-ONE - Transit One S.p.A., IT")
	w.Origin(testenv.NS2IP, "64502", "45.33.20.0/24", "DE", "TRANSIT-TWO - Transit Two GmbH, DE")
	w.Origin(testenv.WebIP, "64500", "45.33.30.0/24", "IT", "EXAMPLE-NET - Example S.r.l., IT")
	return w
}

func TestASNAnalysis(t *testing.T) {
	w := world(t)
	w.ASName("3356", "US", "LEVEL3 - Level 3 Parent, LLC, US")
	w.Stat("asn-neighbours", "AS64500", `{"neighbours":[{"asn":3356,"type":"left","power":10},{"asn":64510,"type":"right","power":1}]}`)
	w.Stat("routing-status", "45.33.30.0/24", `{"first_seen":{"time":"2015-03-01T00:00:00"},"visibility":{"v4":{"ris_peers_seeing":100,"total_ris_peers":350},"v6":{"ris_peers_seeing":0,"total_ris_peers":0}},"origins":[{"origin":64500,"route_objects":["RIPE"]},{"origin":64666,"route_objects":[]}]}`)
	w.Stat("as-routing-consistency", "AS64500", `{"prefixes":[{"prefix":"45.33.30.0/24","in_bgp":true,"in_whois":true,"irr_sources":["RIPE"]},{"prefix":"45.33.31.0/24","in_bgp":true,"in_whois":false,"irr_sources":"-"}]}`)
	w.Stat("announced-prefixes", "AS64500", `{"prefixes":[{"prefix":"45.33.30.0/24"},{"prefix":"45.33.31.0/24"}]}`)
	w.Stat("rpki-validation", "AS64500|45.33.30.0/24", `{"status":"valid","validating_roas":[{"origin":"64500","prefix":"45.33.30.0/24","max_length":24,"validity":"valid"}]}`)
	w.Stat("rpki-validation", "AS64500|45.33.31.0/24", `{"status":"unknown","validating_roas":[]}`)
	w.Stat("abuse-contact-finder", "45.33.30.0/24", `{"abuse_contacts":["abuse@example.test"]}`)
	w.Stat("whois", "45.33.30.3", `{"records":[[{"key":"inetnum","value":"45.33.30.0 - 45.33.30.255"},{"key":"netname","value":"EXAMPLE-LAN"},{"key":"descr","value":"Example S.r.l. servers"}]]}`)

	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.ASN)
	testenv.Expect(t, r, info, none, "AS64500 EXAMPLE-NET - Example S.r.l., IT, prefix 45.33.30.0/24")
	var profile core.Finding
	for _, f := range testenv.Find(r, "AS64500 EXAMPLE-NET") {
		if f.Subject == "AS64500" && f.Status == info {
			profile = f
		}
	}
	details := strings.Join(profile.Details, "\n")
	for _, want := range []string{"registration: country IT, registry RIPENCC", "EXAMPLE-LAN (Example S.r.l. servers)", "operated by the domain owner"} {
		if !strings.Contains(details, want) {
			t.Errorf("profile details missing %q:\n%s", want, details)
		}
	}
	up := testenv.Expect(t, r, fail, low, "single-homed")
	if up.Details[0] != "AS3356 LEVEL3 - Level 3 Parent, LLC, US" {
		t.Errorf("upstream details = %q", up.Details)
	}
	testenv.Expect(t, r, fail, med, "multiple origin ASes (AS64500, AS64666)")
	testenv.Expect(t, r, fail, low, "limited BGP visibility: seen by 100 of 350")
	testenv.Expect(t, r, fail, low, "1 of 2 announced prefixes have no IRR route object")
	testenv.Expect(t, r, fail, low, "1 of 2 checked prefixes have no ROA")
	testenv.Expect(t, r, info, none, "abuse contact for 45.33.30.0/24: abuse@example.test")
}

func TestASNHealthyMultihomed(t *testing.T) {
	w := world(t)
	w.Stat("asn-neighbours", "AS64500", `{"neighbours":[{"asn":3356,"type":"left"},{"asn":1299,"type":"left"},{"asn":6939,"type":"uncertain"}]}`)
	w.Stat("routing-status", "45.33.30.0/24", `{"visibility":{"v4":{"ris_peers_seeing":349,"total_ris_peers":350}},"origins":[{"origin":64500}]}`)
	w.Stat("as-routing-consistency", "AS64500", `{"prefixes":[{"prefix":"45.33.30.0/24","in_bgp":true,"in_whois":true,"irr_sources":["RIPE"]}]}`)
	w.Stat("announced-prefixes", "AS64500", `{"prefixes":[{"prefix":"45.33.30.0/24"}]}`)
	w.Stat("rpki-validation", "AS64500|45.33.30.0/24", `{"status":"valid","validating_roas":[]}`)
	w.Stat("abuse-contact-finder", "45.33.30.0/24", `{"abuse_contacts":[]}`)
	w.Stat("whois", "45.33.30.3", `{"records":[]}`)
	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.ASN)
	testenv.Expect(t, r, pass, none, "multi-homed: 2 upstream/peer ASes")
	testenv.Expect(t, r, pass, none, "globally visible")
	testenv.Expect(t, r, pass, none, "all 1 announced prefixes have an IRR route object")
	testenv.Expect(t, r, pass, none, "RPKI deployed")
	if r.Status != pass {
		t.Errorf("status = %s\n%s", r.Status, testenv.Dump(r))
	}
}

func TestASNSkipsProviders(t *testing.T) {
	w := testenv.New(t)
	w.Origin(testenv.WebIP, "13335", "45.33.30.0/24", "US", "CLOUDFLARENET - Cloudflare, Inc., US")
	env := w.Env(testenv.Zone)
	r := testenv.Run(t, env, bgpchecks.ASN)
	f := testenv.Expect(t, r, skip, none, "hosted by Cloudflare (cdn provider)")
	if f.Subject != "AS13335 CLOUDFLARENET - Cloudflare, Inc., US" {
		t.Errorf("subject = %q", f.Subject)
	}
	if n := w.StatRequests["asn-neighbours"]; n != 0 {
		t.Errorf("provider AS was analyzed (%d asn-neighbours requests)", n)
	}

	env.Opts.IncludeProviders = true
	r = testenv.Run(t, env, bgpchecks.ASN)
	if len(testenv.Find(r, "hosted by Cloudflare")) != 0 || w.StatRequests["asn-neighbours"] == 0 {
		t.Errorf("-include-providers did not analyze the provider AS\n%s", testenv.Dump(r))
	}
}

func TestASNUserDefinedProvider(t *testing.T) {
	w := world(t)
	w.BGP.Providers.Add(64500, "")
	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.ASN)
	testenv.Expect(t, r, skip, none, "hosted by user-defined provider AS64500")
}

func TestASNPrivateAddress(t *testing.T) {
	w := testenv.New(t)
	w.Resolver.Remove(testenv.Zone, 1)
	w.Resolver.Add(t, "example.test. 300 IN A 10.0.0.5")
	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.ASN)
	testenv.Expect(t, r, fail, low, "non-public address: private network (RFC 1918)")
}

func TestASNNoAddress(t *testing.T) {
	w := testenv.New(t)
	w.Resolver.Remove(testenv.Zone, 1)
	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.ASN)
	testenv.Expect(t, r, info, none, "no A/AAAA record")
}

func TestASNWithoutRIPEstat(t *testing.T) {
	w := world(t)
	w.BGP.Stat = nil
	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.ASN)
	testenv.Expect(t, r, info, none, "RIPEstat is disabled")
	// Upstreams fall back to Team Cymru peer data, which is not registered.
	if len(testenv.Find(r, "could not determine the upstream providers")) != 1 {
		t.Errorf("expected upstream lookup error\n%s", testenv.Dump(r))
	}
}

func TestROA(t *testing.T) {
	w := world(t)
	w.Stat("rpki-validation", "AS64501|45.33.10.0/24", `{"status":"invalid_asn","validating_roas":[{"origin":"64999","prefix":"45.33.0.0/16","max_length":24,"validity":"invalid_asn"}]}`)
	w.Stat("rpki-validation", "AS64502|45.33.20.0/24", `{"status":"unknown","validating_roas":[]}`)
	w.Stat("rpki-validation", "AS64500|45.33.30.0/24", `{"status":"valid","validating_roas":[{"origin":"64500","prefix":"45.33.30.0/24","max_length":28,"validity":"valid"}]}`)
	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.ROA)
	f := testenv.Expect(t, r, fail, high, "RPKI invalid: ROAs authorize a different origin AS")
	if f.Subject != "45.33.10.0/24 (AS64501)" || !strings.Contains(f.Details[0], "nameserver ns1.example.test") {
		t.Errorf("finding = %+v", f)
	}
	testenv.Expect(t, r, fail, med, "no ROA covers the prefix")
	testenv.Expect(t, r, pass, none, "RPKI valid")
	testenv.Expect(t, r, fail, low, "loose ROA")
}

func TestIRR(t *testing.T) {
	w := world(t)
	w.Stat("prefix-routing-consistency", "45.33.10.0/24", `{"routes":[{"prefix":"45.33.10.0/24","origin":64501,"in_bgp":true,"in_whois":true,"irr_sources":["RADB","RIPE"]}]}`)
	w.Stat("prefix-routing-consistency", "45.33.20.0/24", `{"routes":[{"prefix":"45.33.20.0/24","origin":64999,"in_bgp":false,"in_whois":true,"irr_sources":["RADB"]},{"prefix":"45.33.20.0/24","origin":64502,"in_bgp":true,"in_whois":false,"irr_sources":[]}]}`)
	w.Stat("prefix-routing-consistency", "45.33.30.0/24", `{"routes":[{"prefix":"45.33.0.0/16","origin":64500,"in_bgp":false,"in_whois":true,"irr_sources":["RIPE"]}]}`)
	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.IRR)
	f := testenv.Expect(t, r, pass, none, "IRR route object registered for the origin AS")
	if !strings.Contains(strings.Join(f.Details, " "), "registered in: RADB, RIPE") {
		t.Errorf("details = %q", f.Details)
	}
	testenv.Expect(t, r, fail, med, "only exist for other origins (AS64999)")
	testenv.Expect(t, r, fail, low, "only covered by less-specific route objects")
}

func TestGEOSingleAS(t *testing.T) {
	w := testenv.New(t)
	w.Origin(testenv.NS1IP, "64501", "45.33.10.0/24", "IT", "SMALL-ISP")
	w.Origin(testenv.NS2IP, "64501", "45.33.20.0/24", "IT", "SMALL-ISP")
	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.GEO)
	testenv.Expect(t, r, fail, low, "single autonomous system")
	testenv.Expect(t, r, fail, low, "single country")
}

func TestGEODiverse(t *testing.T) {
	w := world(t)
	w.Stat("maxmind-geo-lite", testenv.NS1IP, `{"located_resources":[{"locations":[{"country":"IT","city":"Milan"}]}]}`)
	w.Stat("maxmind-geo-lite", testenv.NS2IP, `{"located_resources":[{"locations":[{"country":"DE","city":"Frankfurt"}]}]}`)
	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.GEO)
	testenv.Expect(t, r, pass, none, "nameservers spread over 2 AS (AS64501, AS64502) and 2 countries (DE, IT")
	testenv.Expect(t, r, info, none, "geolocated in Milan, IT")
}

func TestGEOAnycastProvider(t *testing.T) {
	w := testenv.New(t)
	w.Origin(testenv.NS1IP, "13335", "45.33.10.0/24", "US", "CLOUDFLARENET")
	w.Origin(testenv.NS2IP, "13335", "45.33.20.0/24", "US", "CLOUDFLARENET")
	r := testenv.Run(t, w.Env(testenv.Zone), bgpchecks.GEO)
	f := testenv.Expect(t, r, fail, low, "single autonomous system")
	if !strings.Contains(strings.Join(f.Details, " "), "anycast") {
		t.Errorf("details = %q", f.Details)
	}
	testenv.Expect(t, r, info, none, "registered in a single country")
}
