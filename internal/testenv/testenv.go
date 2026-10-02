// Package testenv builds a complete fake deployment (recursive resolver,
// parent zone, authoritative nameservers, IP-to-ASN mapping and RIPEstat API)
// to test checks end to end without network access.
package testenv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/5amu/dnshunter/internal/dnstest"
	"github.com/5amu/dnshunter/pkg/bgp"
	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/5amu/dnshunter/pkg/target"
	"github.com/miekg/dns"
)

// Addresses used by the fake deployment.
const (
	Zone     = "example.test"
	ParentIP = "45.33.0.1"
	NS1IP    = "45.33.10.1"
	NS2IP    = "45.33.20.2"
	WebIP    = "45.33.30.3"
	CymruZ   = "asn.cymru.test"
)

// World is a fake deployment of the zone example.test.
type World struct {
	T        testing.TB
	Resolver *dnstest.Server
	Parent   *dnstest.Server
	NS1, NS2 *dnstest.Server
	Client   *dnsutil.Client
	BGP      *bgp.Service

	mu sync.Mutex
	// referral is the delegation served by the parent (NS names and glue).
	referralRRs []string
	stat        map[string]string
	// StatRequests counts RIPEstat requests per data call.
	StatRequests map[string]int
}

// New builds a healthy deployment: two nameservers in different networks,
// matching delegation and glue, consistent SOA.
func New(t testing.TB) *World {
	t.Helper()
	w := &World{T: t, stat: map[string]string{}, StatRequests: map[string]int{}}
	w.Resolver = dnstest.Start(t)
	w.Resolver.SetAuthoritative(false)
	w.Resolver.SetRecursion(true)
	w.Parent = dnstest.Start(t)
	w.NS1 = dnstest.Start(t)
	w.NS2 = dnstest.Start(t)

	soa := "example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2024010101 86400 7200 3600000 3600"
	common := []string{
		soa,
		"example.test. 3600 IN NS ns1.example.test.",
		"example.test. 3600 IN NS ns2.example.test.",
		"ns1.example.test. 3600 IN A " + NS1IP,
		"ns2.example.test. 3600 IN A " + NS2IP,
		"example.test. 300 IN A " + WebIP,
	}
	w.Resolver.Add(t, common...)
	w.Resolver.Add(t,
		"test. 3600 IN SOA ns.nic.test. hostmaster.nic.test. 1 7200 3600 1209600 3600",
		"test. 3600 IN NS ns.nic.test.",
		"ns.nic.test. 3600 IN A "+ParentIP,
	)
	w.NS1.Add(t, common...)
	w.NS2.Add(t, common...)
	w.Parent.Add(t,
		"test. 3600 IN SOA ns.nic.test. hostmaster.nic.test. 1 7200 3600 1209600 3600",
		"test. 3600 IN NS ns.nic.test.",
	)
	w.SetReferral(
		"example.test. 3600 IN NS ns1.example.test.",
		"example.test. 3600 IN NS ns2.example.test.",
		"ns1.example.test. 3600 IN A "+NS1IP,
		"ns2.example.test. 3600 IN A "+NS2IP,
	)
	w.Parent.SetHook(w.referral)

	w.Client = dnsutil.New([]string{w.Resolver.Addr}, 2*time.Second, 0)
	w.Client.Overrides = map[string]string{
		ParentIP: w.Parent.Addr,
		NS1IP:    w.NS1.Addr,
		NS2IP:    w.NS2.Addr,
	}

	api := httptest.NewServer(http.HandlerFunc(w.serveStat))
	t.Cleanup(api.Close)
	w.BGP = bgp.NewService(bgp.Config{DNS: w.Client, RIPEstatURL: api.URL + "/data", DisableIRRd: true, Timeout: 5 * time.Second})
	w.BGP.Cymru.Zone = CymruZ
	return w
}

// SetReferral sets the delegation (NS and glue records) served by the parent.
func (w *World) SetReferral(rrs ...string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.referralRRs = rrs
}

// referral answers queries for names in example.test with a referral.
func (w *World) referral(rw dns.ResponseWriter, r *dns.Msg) bool {
	q := r.Question[0]
	if !dns.IsSubDomain(Zone+".", strings.ToLower(q.Name)) {
		return false
	}
	m := new(dns.Msg)
	m.SetReply(r)
	w.mu.Lock()
	rrs := w.referralRRs
	w.mu.Unlock()
	for _, txt := range rrs {
		rr, err := dns.NewRR(txt)
		if err != nil {
			w.T.Errorf("invalid referral record %q: %v", txt, err)
			continue
		}
		switch rr.Header().Rrtype {
		case dns.TypeNS:
			m.Ns = append(m.Ns, rr)
		default:
			m.Extra = append(m.Extra, rr)
		}
	}
	_ = rw.WriteMsg(m)
	return true
}

// All adds records to the resolver and to both nameservers.
func (w *World) All(rrs ...string) {
	w.T.Helper()
	w.Resolver.Add(w.T, rrs...)
	w.NS1.Add(w.T, rrs...)
	w.NS2.Add(w.T, rrs...)
}

// Origin registers Team Cymru data for an IPv4 address.
func (w *World) Origin(ip, asn, prefix, cc, asName string) {
	w.T.Helper()
	rev := dnsutil.ReverseLabels(parseIP(w.T, ip))
	w.Resolver.AddRR(txt(rev+".origin."+CymruZ, asn+" | "+prefix+" | "+cc+" | ripencc | 2010-01-01"))
	w.Resolver.AddRR(txt("AS"+strings.Fields(asn)[0]+"."+CymruZ, strings.Fields(asn)[0]+" | "+cc+" | ripencc | 2001-01-01 | "+asName))
}

// Stat registers the JSON "data" member returned by a RIPEstat data call for
// a resource ("rpki-validation", "AS64500|10.0.0.0/8" for rpki-validation).
func (w *World) Stat(call, resource, data string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stat[call+"|"+resource] = data
}

func (w *World) serveStat(rw http.ResponseWriter, r *http.Request) {
	call := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/data/"), "/data.json")
	res := r.URL.Query().Get("resource")
	if p := r.URL.Query().Get("prefix"); p != "" {
		res += "|" + p
	}
	w.mu.Lock()
	w.StatRequests[call]++
	data, ok := w.stat[call+"|"+res]
	w.mu.Unlock()
	rw.Header().Set("Content-Type", "application/json")
	if !ok {
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write([]byte(`{"status":"error","status_code":400,"messages":[["error","no fixture for ` + call + ` ` + res + `"]],"data":{}}`))
		return
	}
	_, _ = rw.Write([]byte(`{"status":"ok","status_code":200,"messages":[],"data":` + data + `}`))
}

// Env discovers the target and returns a check environment.
func (w *World) Env(domain string) *core.Env {
	w.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t, err := target.Discover(ctx, w.Client, domain)
	if err != nil {
		w.T.Fatalf("discover %s: %v", domain, err)
	}
	return &core.Env{Target: t, DNS: w.Client, BGP: w.BGP, Opts: core.Options{MaxPrefixes: 20}}
}

// Run executes a check and returns its finalized result.
func Run(t testing.TB, env *core.Env, c *core.Check) *core.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := core.NewResult(c)
	if err := c.Run(ctx, env, r); err != nil {
		r.Error = err.Error()
	}
	r.Finalize()
	return r
}

// Find returns the findings whose title contains substr.
func Find(r *core.Result, substr string) []core.Finding {
	var out []core.Finding
	for _, f := range r.Findings {
		if strings.Contains(f.Title, substr) {
			out = append(out, f)
		}
	}
	return out
}

// Expect fails the test unless a finding with the given status (and severity
// for failures) has a title containing substr.
func Expect(t testing.TB, r *core.Result, status core.Status, sev core.Severity, substr string) core.Finding {
	t.Helper()
	for _, f := range Find(r, substr) {
		if f.Status == status && (status != core.StatusFail || f.Severity == sev) {
			return f
		}
	}
	t.Fatalf("no %s/%s finding containing %q in %s:\n%s", status, sev, substr, r.ID, Dump(r))
	return core.Finding{}
}

// Dump formats the findings of r for test failure messages.
func Dump(r *core.Result) string {
	var b strings.Builder
	if r.Error != "" {
		b.WriteString("  error: " + r.Error + "\n")
	}
	for _, f := range r.Findings {
		b.WriteString("  " + string(f.Status) + "/" + f.Severity.String() + " " + f.Subject + ": " + f.Title + "\n")
		for _, d := range f.Details {
			b.WriteString("      " + d + "\n")
		}
	}
	return b.String()
}

func txt(name, value string) dns.RR {
	return &dns.TXT{Hdr: dns.RR_Header{Name: dns.Fqdn(strings.ToLower(name)), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{value}}
}

// ASName registers Team Cymru AS data.
func (w *World) ASName(asn, cc, name string) {
	w.Resolver.AddRR(txt("AS"+asn+"."+CymruZ, asn+" | "+cc+" | ripencc | 2001-01-01 | "+name))
}
