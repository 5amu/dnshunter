package bgp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseCymru(t *testing.T) {
	o, err := parseCymruOrigin("15169 | 8.8.8.0/24 | US | arin | 2023-12-28")
	if err != nil || o.ASN() != 15169 || o.Prefix != "8.8.8.0/24" || o.Country != "US" || o.Registry != "arin" {
		t.Fatalf("parseCymruOrigin = %+v, %v", o, err)
	}
	o, err = parseCymruOrigin("13335 209242 | 2606:4700::/44 | US | arin | 2011-11-01")
	if err != nil || len(o.ASNs) != 2 || o.Prefix != "2606:4700::/44" {
		t.Fatalf("multi-origin = %+v, %v", o, err)
	}
	if _, err := parseCymruOrigin("garbage"); err == nil {
		t.Fatal("expected error")
	}
	as, err := parseCymruAS("3269 | IT | ripencc | 1994-11-14 | ASN-IBSNAZ - Telecom Italia S.p.A., IT")
	if err != nil || as.ASN != 3269 || as.Name != "ASN-IBSNAZ - Telecom Italia S.p.A., IT" || as.Country != "IT" {
		t.Fatalf("parseCymruAS = %+v, %v", as, err)
	}
	for in, want := range map[string]uint32{"AS64500": 64500, "as13335": 13335, " 3333 ": 3333} {
		if got, err := ParseASN(in); err != nil || got != want {
			t.Errorf("ParseASN(%q) = %d, %v", in, got, err)
		}
	}
	if _, err := ParseASN("ASX"); err == nil {
		t.Error("ParseASN(ASX) should fail")
	}
}

func TestReservedRange(t *testing.T) {
	for ip, reserved := range map[string]bool{
		"10.1.2.3": true, "192.168.1.1": true, "100.64.0.1": true, "127.0.0.1": true,
		"169.254.1.1": true, "fd00::1": true, "fe80::1": true, "2001:db8::1": true,
		"8.8.8.8": false, "62.149.189.54": false, "2a00:1450::1": false,
	} {
		if got := ReservedRange(net.ParseIP(ip)) != ""; got != reserved {
			t.Errorf("ReservedRange(%s) reserved=%v, want %v", ip, got, reserved)
		}
	}
}

func TestProviders(t *testing.T) {
	db := NewProviderDB()
	cases := []struct {
		asn  uint32
		name string
		want string
	}{
		{13335, "CLOUDFLARENET", "Cloudflare"},
		{16509, "AMAZON-02", "Amazon Web Services"},
		{31034, "ARUBA-ASN - Aruba S.p.A., IT", "Aruba S.p.A."},
		{64999, "DIGITALOCEAN-ASN", "DigitalOcean"},
		{64998, "EXAMPLE-HOSTING-AS Example Hosting Ltd", "EXAMPLE-HOSTING-AS Example Hosting Ltd"},
		{64997, "OVH SAS", "OVHcloud"},
		{3269, "ASN-IBSNAZ - Telecom Italia S.p.A., IT", ""},
		{64496, "ACME-CORP - Acme Corporation", ""},
		{64495, "ICLOUDFLOWERS", ""}, // "CLOUD" must match whole words only
	}
	for _, c := range cases {
		p := db.Classify(c.asn, c.name)
		got := ""
		if p != nil {
			got = p.Name
		}
		if got != c.want {
			t.Errorf("Classify(%d, %q) = %q, want %q", c.asn, c.name, got, c.want)
		}
	}
	db.Add(64496, "")
	if p := db.Classify(64496, "ACME-CORP"); p == nil || !strings.Contains(p.Reason, "by the user") {
		t.Errorf("user provider not honored: %+v", p)
	}
	db.DisableHeuristics = true
	if p := db.Classify(64999, "DIGITALOCEAN-ASN"); p != nil {
		t.Errorf("heuristics should be disabled: %+v", p)
	}
}

// statFixtures are trimmed real RIPEstat responses.
var statFixtures = map[string]string{
	"/data/rpki-validation/data.json":            `{"status":"ok","status_code":200,"data":{"validating_roas":[{"origin":"3333","prefix":"193.0.0.0/21","validity":"valid","source":"RIPE NCC RPKI Root","max_length":21}],"status":"valid","validator":"routinator","resource":"3333","prefix":"193.0.0.0/21"}}`,
	"/data/prefix-routing-consistency/data.json": `{"status":"ok","data":{"routes":[{"in_bgp":true,"in_whois":true,"prefix":"193.0.0.0/21","origin":3333,"irr_sources":["RIPE"],"asn_name":"RIPE-NCC-AS"},{"in_bgp":false,"in_whois":true,"prefix":"193.0.0.0/21","origin":64500,"irr_sources":["RADB"],"asn_name":"OLD"},{"in_bgp":false,"in_whois":true,"prefix":"193.0.0.0/16","origin":3333,"irr_sources":["RIPE"],"asn_name":"RIPE-NCC-AS"}],"resource":"193.0.0.0/21"}}`,
	"/data/as-routing-consistency/data.json":     `{"status":"ok","data":{"prefixes":[{"prefix":"193.0.0.0/21","in_bgp":true,"in_whois":true,"irr_sources":["RIPE"]},{"prefix":"193.0.10.0/23","in_bgp":true,"in_whois":false,"irr_sources":"-"}],"imports":[],"exports":[],"authority":"RIPE","resource":"3333"}}`,
	"/data/asn-neighbours/data.json":             `{"status":"ok","data":{"resource":"3333","neighbour_counts":{"left":2,"right":1,"unique":3,"uncertain":1},"neighbours":[{"asn":1299,"type":"left","power":50,"v4_peers":10,"v6_peers":5},{"asn":3356,"type":"left","power":40,"v4_peers":9,"v6_peers":4},{"asn":64500,"type":"right","power":2,"v4_peers":1,"v6_peers":0},{"asn":6939,"type":"uncertain","power":1,"v4_peers":1,"v6_peers":1}]}}`,
	"/data/routing-status/data.json":             `{"status":"ok","data":{"first_seen":{"prefix":"193.0.0.0/21","origin":"3333","time":"2000-08-18T08:00:00"},"visibility":{"v4":{"ris_peers_seeing":340,"total_ris_peers":350},"v6":{"ris_peers_seeing":0,"total_ris_peers":0}},"origins":[{"origin":3333,"route_objects":["RIPE"]}],"less_specifics":[],"more_specifics":[{"prefix":"193.0.0.0/24","origin":3333}],"resource":"193.0.0.0/21"}}`,
	"/data/announced-prefixes/data.json":         `{"status":"ok","data":{"prefixes":[{"prefix":"193.0.0.0/21","timelines":[{"starttime":"2024-01-01T00:00:00","endtime":"2024-01-15T00:00:00"}]},{"prefix":"2001:67c:2e8::/48","timelines":[]}],"resource":"3333"}}`,
	"/data/network-info/data.json":               `{"status":"ok","data":{"asns":["3333"],"prefix":"193.0.0.0/21"}}`,
	"/data/as-overview/data.json":                `{"status":"ok","data":{"type":"as","resource":"3333","holder":"RIPE-NCC-AS - Reseaux IP Europeens Network Coordination Centre (RIPE NCC)","announced":true}}`,
	"/data/abuse-contact-finder/data.json":       `{"status":"ok","data":{"abuse_contacts":["abuse@ripe.net"],"authoritative_rir":"ripe"}}`,
	"/data/whois/data.json":                      `{"status":"ok","data":{"records":[[{"key":"inetnum","value":"193.0.0.0 - 193.0.7.255","details_link":null},{"key":"netname","value":"RIPE-NCC","details_link":null},{"key":"descr","value":"RIPE Network Coordination Centre","details_link":null}]],"irr_records":[]}}`,
	"/data/maxmind-geo-lite/data.json":           `{"status":"ok","data":{"located_resources":[{"resource":"193.0.0.0/21","locations":[{"country":"NL","city":"Amsterdam","resources":["193.0.0.0/21"],"latitude":52.37,"longitude":4.89,"covered_percentage":100}]}]}}`,
}

func statServer(t *testing.T) (*RIPEstat, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Query().Get("sourceapp") != "dnshunter" {
			t.Errorf("missing sourceapp in %s", r.URL)
		}
		body, ok := statFixtures[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"status":"error","status_code":404,"messages":[["error","unknown data call"]],"data":{}}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NewRIPEstat(srv.URL+"/data", 5*time.Second), &hits
}

func TestRIPEstat(t *testing.T) {
	s, hits := statServer(t)
	ctx := context.Background()

	rpki, err := s.RPKIValidation(ctx, 3333, "193.0.0.0/21")
	if err != nil || rpki.Status != "valid" || len(rpki.ROAs) != 1 || rpki.ROAs[0].Origin != 3333 || rpki.ROAs[0].MaxLength != 21 {
		t.Fatalf("RPKIValidation = %+v, %v", rpki, err)
	}
	if _, err := s.RPKIValidation(ctx, 3333, "193.0.0.0/21"); err != nil || atomic.LoadInt32(hits) != 1 {
		t.Fatalf("expected a cached response, hits=%d err=%v", atomic.LoadInt32(hits), err)
	}

	routes, err := s.PrefixRoutingConsistency(ctx, "193.0.0.0/21")
	if err != nil || len(routes) != 3 || routes[0].Origin != 3333 || routes[0].IRRSources[0] != "RIPE" {
		t.Fatalf("PrefixRoutingConsistency = %+v, %v", routes, err)
	}
	cons, err := s.ASRoutingConsistency(ctx, 3333)
	if err != nil || len(cons) != 2 || cons[1].InWhois || len(cons[1].IRRSources) != 0 {
		t.Fatalf("ASRoutingConsistency = %+v, %v", cons, err)
	}
	nbs, err := s.Neighbours(ctx, 3333)
	if err != nil || len(nbs) != 4 || nbs[0].ASN != 1299 || nbs[0].Type != "left" {
		t.Fatalf("Neighbours = %+v, %v", nbs, err)
	}
	rs, err := s.RoutingStatus(ctx, "193.0.0.0/21")
	if err != nil || rs.VisibilityV4.Seeing != 340 || rs.VisibilityV4.Total != 350 || len(rs.Origins) != 1 || rs.Origins[0].Origin != 3333 || rs.FirstSeen == "" {
		t.Fatalf("RoutingStatus = %+v, %v", rs, err)
	}
	pfx, err := s.AnnouncedPrefixes(ctx, 3333)
	if err != nil || len(pfx) != 2 {
		t.Fatalf("AnnouncedPrefixes = %v, %v", pfx, err)
	}
	o, err := s.NetworkInfo(ctx, net.ParseIP("193.0.6.139"))
	if err != nil || o.ASN() != 3333 || o.Prefix != "193.0.0.0/21" {
		t.Fatalf("NetworkInfo = %+v, %v", o, err)
	}
	as, err := s.ASOverview(ctx, 3333)
	if err != nil || !strings.HasPrefix(as.Name, "RIPE-NCC-AS") {
		t.Fatalf("ASOverview = %+v, %v", as, err)
	}
	ab, err := s.AbuseContacts(ctx, "193.0.0.0/21")
	if err != nil || len(ab) != 1 || ab[0] != "abuse@ripe.net" {
		t.Fatalf("AbuseContacts = %v, %v", ab, err)
	}
	wh, err := s.Whois(ctx, "193.0.6.139")
	if err != nil || len(wh) != 1 || wh[0][1].Value != "RIPE-NCC" {
		t.Fatalf("Whois = %v, %v", wh, err)
	}
	loc, err := s.Geolocation(ctx, "193.0.6.139")
	if err != nil || loc.Country != "NL" || loc.City != "Amsterdam" {
		t.Fatalf("Geolocation = %+v, %v", loc, err)
	}
}

func TestRIPEstatErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"status":"error","status_code":429,"messages":[["error","rate limited"]],"data":{}}`))
	}))
	defer srv.Close()
	s := NewRIPEstat(srv.URL, time.Second)
	if _, err := s.RPKIValidation(context.Background(), 1, "10.0.0.0/8"); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("expected rate limit error, got %v", err)
	}

	// An unreachable API trips the circuit breaker.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	s = NewRIPEstat("http://"+addr, time.Second)
	_, err1 := s.ASOverview(context.Background(), 1)
	_, err2 := s.ASOverview(context.Background(), 2)
	if err1 == nil || err2 == nil || !strings.Contains(err2.Error(), "unreachable") {
		t.Fatalf("errors = %v / %v", err1, err2)
	}
}

func TestIRRd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 256)
				n, _ := c.Read(buf)
				q := strings.TrimSpace(string(buf[:n]))
				switch q {
				case "!r193.0.0.0/21,o":
					payload := "AS3333 AS64500\n"
					_, _ = fmt.Fprintf(c, "A%d\n%sC\n", len(payload), payload)
				case "!r10.0.0.0/8,o":
					_, _ = fmt.Fprint(c, "D\n")
				default:
					_, _ = fmt.Fprint(c, "F invalid query\n")
				}
			}(c)
		}
	}()
	c := &IRRd{Addr: ln.Addr().String(), Timeout: 2 * time.Second}
	got, err := c.RouteOrigins(context.Background(), "193.0.0.0/21")
	if err != nil || len(got) != 2 || got[0] != 3333 || got[1] != 64500 {
		t.Fatalf("RouteOrigins = %v, %v", got, err)
	}
	if got, err := c.RouteOrigins(context.Background(), "10.0.0.0/8"); err != nil || len(got) != 0 {
		t.Fatalf("RouteOrigins(not found) = %v, %v", got, err)
	}
	if _, err := c.RouteOrigins(context.Background(), "bad"); err == nil {
		t.Fatal("expected error")
	}
}

func TestServiceIRRFallsBackToIRRd(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = fmt.Fprint(c, "A7\nAS3333\nC\n")
	}()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"status":"error","data":{}}`))
	}))
	defer srv.Close()
	s := &Service{Stat: NewRIPEstat(srv.URL, time.Second), IRRd: &IRRd{Addr: ln.Addr().String(), Timeout: time.Second}, Providers: NewProviderDB()}
	st, err := s.IRR(context.Background(), "193.0.0.0/21")
	if err != nil || st.Source != "RADb" {
		t.Fatalf("IRR = %+v, %v", st, err)
	}
	if _, ok := st.Origins[3333]; !ok {
		t.Fatalf("origins = %v", st.Origins)
	}
}

func TestServiceIRRFromRIPEstat(t *testing.T) {
	stat, _ := statServer(t)
	s := &Service{Stat: stat, Providers: NewProviderDB()}
	st, err := s.IRR(context.Background(), "193.0.0.0/21")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Origins) != 2 || st.Origins[3333][0] != "RIPE" {
		t.Fatalf("origins = %v", st.Origins)
	}
	if got := st.Covering["193.0.0.0/16"]; len(got) != 1 || got[0] != 3333 {
		t.Fatalf("covering = %v", st.Covering)
	}
}

func TestCancelledCallDoesNotPoisonCache(t *testing.T) {
	s, hits := statServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ASOverview(ctx, 3333); err == nil {
		t.Fatal("expected context error")
	}
	if _, err := s.ASOverview(context.Background(), 3333); err != nil {
		t.Fatalf("cancelled call poisoned the cache: %v", err)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("hits = %d", atomic.LoadInt32(hits))
	}
}
