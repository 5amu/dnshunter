package dnsutil_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/5amu/dnshunter/internal/dnstest"
	"github.com/5amu/dnshunter/internal/testenv"
	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/miekg/dns"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in, want string
		err      bool
	}{
		{in: "Example.COM.", want: "example.com"},
		{in: "https://www.example.co.uk/path?q=1", want: "www.example.co.uk"},
		{in: "example.com:8443", want: "example.com"},
		{in: "bücher.de", want: "xn--bcher-kva.de"},
		{in: "sub.example.it/", want: "sub.example.it"},
		{in: "co.uk", err: true},
		{in: "com", err: true},
		{in: "192.0.2.1", err: true},
		{in: "", err: true},
		{in: "exa mple.com", err: true},
	}
	for _, c := range cases {
		got, err := dnsutil.NormalizeDomain(c.in)
		if c.err {
			if err == nil {
				t.Errorf("NormalizeDomain(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestNames(t *testing.T) {
	if got := dnsutil.Parent("a.b.example.com."); got != "b.example.com" {
		t.Errorf("Parent = %q", got)
	}
	if got := dnsutil.Parent("com"); got != "." {
		t.Errorf("Parent(com) = %q", got)
	}
	if got := dnsutil.OrgDomain("mail.sub.example.co.uk"); got != "example.co.uk" {
		t.Errorf("OrgDomain = %q", got)
	}
	if !dnsutil.IsSubdomain("example.com", "NS1.Example.com.") || dnsutil.IsSubdomain("example.com", "example.net") {
		t.Error("IsSubdomain")
	}
	if got := dnsutil.ReverseLabels(net.ParseIP("192.0.2.10")); got != "10.2.0.192" {
		t.Errorf("ReverseLabels v4 = %q", got)
	}
	if got := dnsutil.ReverseLabels(net.ParseIP("2001:db8::1")); !strings.HasPrefix(got, "1.0.0.0.") || !strings.HasSuffix(got, "8.b.d.0.1.0.0.2") {
		t.Errorf("ReverseLabels v6 = %q", got)
	}
}

func TestLookupAndZone(t *testing.T) {
	srv := dnstest.Start(t)
	srv.Add(t,
		"example.com. 300 IN SOA ns1.example.com. h.example.com. 1 2 3 4 5",
		`example.com. 300 IN TXT "v=spf1 " "include:_spf.example.net -all"`,
		"www.example.com. 300 IN CNAME web.example.com.",
		"web.example.com. 300 IN A 192.0.2.1",
		"web.example.com. 300 IN AAAA 2001:db8::1",
	)
	c := dnsutil.New([]string{srv.Addr}, time.Second, 0)
	ctx := context.Background()

	txt, rc, err := c.LookupTXT(ctx, "example.com")
	if err != nil || rc != dns.RcodeSuccess || len(txt) != 1 || txt[0] != "v=spf1 include:_spf.example.net -all" {
		t.Fatalf("LookupTXT = %q, %d, %v", txt, rc, err)
	}
	ips, err := c.LookupIPs(ctx, "www.example.com")
	if err != nil || len(ips) != 2 {
		t.Fatalf("LookupIPs = %v, %v", ips, err)
	}
	zone, err := c.FindZone(ctx, "www.example.com")
	if err != nil || zone != "example.com" {
		t.Fatalf("FindZone = %q, %v", zone, err)
	}
	if _, err := c.FindZone(ctx, "missing.example.com"); err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Fatalf("FindZone(missing) err = %v", err)
	}
}

func TestLookupFallsBackToNextResolver(t *testing.T) {
	broken := dnstest.Start(t)
	broken.SetRcode(dns.RcodeServerFailure)
	good := dnstest.Start(t)
	good.Add(t, "example.com. 300 IN A 192.0.2.1")
	c := dnsutil.New([]string{broken.Addr, good.Addr}, time.Second, 0)
	m, err := c.Lookup(context.Background(), "example.com", dns.TypeA)
	if err != nil || len(m.Answer) != 1 {
		t.Fatalf("Lookup = %v, %v", m, err)
	}
}

func TestTruncatedAnswerFallsBackToTCP(t *testing.T) {
	srv := dnstest.Start(t)
	for i := 0; i < 60; i++ {
		srv.Add(t, "big.example.com. 300 IN TXT \""+strings.Repeat("x", 200)+"\"")
	}
	c := dnsutil.New([]string{srv.Addr}, 2*time.Second, 0)
	m, err := c.Lookup(context.Background(), "big.example.com", dns.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if m.Truncated || len(m.Answer) != 60 {
		t.Fatalf("expected full answer over TCP, got truncated=%v records=%d", m.Truncated, len(m.Answer))
	}
}

func TestDelegation(t *testing.T) {
	w := testenv.New(t)
	d, err := w.Client.Delegation(context.Background(), testenv.Zone)
	if err != nil {
		t.Fatal(err)
	}
	if d.Parent != "test" || len(d.NS) != 2 || len(d.Glue["ns1.example.test"]) != 1 {
		t.Fatalf("unexpected delegation %+v", d)
	}
}

func TestDetectInterception(t *testing.T) {
	interceptor := dnstest.Start(t)
	interceptor.SetAuthoritative(false)
	interceptor.SetRecursion(true)
	interceptor.Add(t, "example.com. 300 IN A 192.0.2.1")
	c := dnsutil.New(nil, time.Second, 0)
	c.Overrides = map[string]string{"198.41.0.4": interceptor.Addr}
	got, err := c.DetectInterception(context.Background())
	if err != nil || !got {
		t.Fatalf("DetectInterception = %v, %v; want true", got, err)
	}

	root := dnstest.Start(t)
	root.SetAuthoritative(false)
	root.SetHook(func(w dns.ResponseWriter, r *dns.Msg) bool {
		m := new(dns.Msg)
		m.SetReply(r)
		ns, _ := dns.NewRR("com. 172800 IN NS a.gtld-servers.net.")
		m.Ns = append(m.Ns, ns)
		_ = w.WriteMsg(m)
		return true
	})
	c.Overrides["198.41.0.4"] = root.Addr
	if got, err := c.DetectInterception(context.Background()); err != nil || got {
		t.Fatalf("DetectInterception(real root) = %v, %v; want false", got, err)
	}
}

func TestTruncatedAnswerWithoutTCPIsAnError(t *testing.T) {
	srv := dnstest.Start(t)
	for i := 0; i < 60; i++ {
		srv.Add(t, "big.example.com. 300 IN TXT \""+strings.Repeat("x", 200)+"\"")
	}
	// Serve UDP only: the TCP fallback hits a closed port.
	udpOnly := dnstest.Start(t)
	udpOnly.SetHook(func(w dns.ResponseWriter, r *dns.Msg) bool {
		if _, tcp := w.RemoteAddr().(*net.TCPAddr); tcp {
			_ = w.Close()
			return true
		}
		srv.ServeDNS(w, r)
		return true
	})
	c := dnsutil.New([]string{udpOnly.Addr}, time.Second, 0)
	if _, err := c.Lookup(context.Background(), "big.example.com", dns.TypeTXT); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected truncation error, got %v", err)
	}
}

func TestLookupSetsCheckingDisabled(t *testing.T) {
	// A validating resolver answers SERVFAIL for a bogus zone unless the CD
	// bit is set; the zone must stay analyzable.
	validating := dnstest.Start(t)
	validating.SetHook(func(w dns.ResponseWriter, r *dns.Msg) bool {
		m := new(dns.Msg)
		m.SetReply(r)
		if !r.CheckingDisabled {
			m.Rcode = dns.RcodeServerFailure
		} else {
			soa, _ := dns.NewRR("bogus.test. 300 IN SOA ns.bogus.test. h.bogus.test. 1 2 3 4 5")
			m.Answer = append(m.Answer, soa)
		}
		_ = w.WriteMsg(m)
		return true
	})
	c := dnsutil.New([]string{validating.Addr}, time.Second, 0)
	if zone, err := c.FindZone(context.Background(), "bogus.test"); err != nil || zone != "bogus.test" {
		t.Fatalf("FindZone = %q, %v", zone, err)
	}
}

func TestCancelledQueryReturnsContextError(t *testing.T) {
	srv := dnstest.Start(t)
	srv.SetHook(func(dns.ResponseWriter, *dns.Msg) bool { return true }) // never answers
	c := dnsutil.New([]string{srv.Addr}, 5*time.Second, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.Lookup(ctx, "example.com", dns.TypeA)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected a context error, got %v", err)
	}
}
