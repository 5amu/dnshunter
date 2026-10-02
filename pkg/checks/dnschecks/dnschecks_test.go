package dnschecks_test

import (
	"crypto"
	"testing"
	"time"

	"github.com/5amu/dnshunter/internal/testenv"
	"github.com/5amu/dnshunter/pkg/checks/dnschecks"
	"github.com/5amu/dnshunter/pkg/core"
	"github.com/miekg/dns"
)

const (
	pass = core.StatusPass
	fail = core.StatusFail
	info = core.StatusInfo
	none = core.SeverityNone
	low  = core.SeverityLow
	med  = core.SeverityMedium
	high = core.SeverityHigh
)

func TestHealthyZone(t *testing.T) {
	w := testenv.New(t)
	env := w.Env(testenv.Zone)

	r := testenv.Run(t, env, dnschecks.Delegation)
	testenv.Expect(t, r, pass, none, "2 nameservers")
	testenv.Expect(t, r, pass, none, "NS set at the parent (test) matches the zone")
	testenv.Expect(t, r, pass, none, "answers authoritatively")
	testenv.Expect(t, r, pass, none, "spread over 2 different networks")
	if r.Status != pass {
		t.Errorf("ns status = %s\n%s", r.Status, testenv.Dump(r))
	}

	r = testenv.Run(t, env, dnschecks.SOA)
	testenv.Expect(t, r, pass, none, "all nameservers serve serial 2024010101")
	testenv.Expect(t, r, pass, none, "SOA timers follow recommended values")
	testenv.Expect(t, r, info, none, "follows the YYYYMMDDnn convention")
	soa := testenv.Expect(t, r, info, none, "SOA record")
	if soa.Details[1] != "responsible mailbox (RNAME): hostmaster@example.test" {
		t.Errorf("RNAME detail = %q", soa.Details[1])
	}

	r = testenv.Run(t, env, dnschecks.GLUE)
	if got := testenv.Find(r, "glue records present and consistent"); len(got) != 2 {
		t.Errorf("glue findings:\n%s", testenv.Dump(r))
	}

	r = testenv.Run(t, env, dnschecks.AXFR)
	if got := testenv.Find(r, "zone transfer refused"); len(got) != 2 || r.Status != pass {
		t.Errorf("axfr:\n%s", testenv.Dump(r))
	}

	r = testenv.Run(t, env, dnschecks.ANY)
	if r.Status != pass {
		t.Errorf("any:\n%s", testenv.Dump(r))
	}

	r = testenv.Run(t, env, dnschecks.Recursion)
	if got := testenv.Find(r, "recursion refused"); len(got) != 2 {
		t.Errorf("recursion:\n%s", testenv.Dump(r))
	}

	r = testenv.Run(t, env, dnschecks.Version)
	if got := testenv.Find(r, "software version is not disclosed"); len(got) != 2 {
		t.Errorf("version:\n%s", testenv.Dump(r))
	}

	r = testenv.Run(t, env, dnschecks.DNSSEC)
	testenv.Expect(t, r, fail, med, "DNSSEC is not enabled")

	r = testenv.Run(t, env, dnschecks.CAA)
	testenv.Expect(t, r, fail, low, "no CAA record")
}

func TestMisconfiguredZone(t *testing.T) {
	w := testenv.New(t)
	// Different serial and bad timers on ns2.
	w.NS2.Remove(testenv.Zone, dns.TypeSOA)
	w.NS2.Add(t, "example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 7 300 600 1000 172800")
	// ns2 is lame and an open resolver.
	w.NS2.SetAuthoritative(false)
	w.NS2.SetRecursion(true)
	w.NS2.Add(t, "www.iana.org. 300 IN A 192.0.43.8")
	// ns1 allows zone transfers, discloses its version and answers ANY with
	// a lot of records.
	w.NS1.SetAXFR(testenv.Zone)
	w.NS1.SetChaos("version.bind", "9.11.4-P2-RedHat")
	w.NS1.SetChaos("hostname.bind", "dns-prod-01")
	for i := 0; i < 12; i++ {
		w.NS1.Add(t, "example.test. 300 IN TXT \"record-"+string(rune('a'+i))+"-padding-padding-padding-padding\"")
	}
	// The parent delegates to a third, unresolvable nameserver and publishes
	// stale glue for ns1.
	w.SetReferral(
		"example.test. 3600 IN NS ns1.example.test.",
		"example.test. 3600 IN NS ns2.example.test.",
		"example.test. 3600 IN NS ns3.example.test.",
		"ns1.example.test. 3600 IN A 45.33.99.9",
		"ns2.example.test. 3600 IN A "+testenv.NS2IP,
	)
	w.All(`example.test. 300 IN CAA 0 issuewild "letsencrypt.org"`)
	env := w.Env(testenv.Zone)

	r := testenv.Run(t, env, dnschecks.SOA)
	testenv.Expect(t, r, fail, low, "different SOA serials")
	timers := testenv.Expect(t, r, fail, low, "SOA timers deviate")
	if len(timers.Details) < 3 {
		t.Errorf("expected several timer issues, got %q", timers.Details)
	}

	r = testenv.Run(t, env, dnschecks.Delegation)
	testenv.Expect(t, r, fail, med, "lame delegation: answer is not authoritative")
	testenv.Expect(t, r, fail, low, "NS records at the parent and in the zone differ")
	testenv.Expect(t, r, fail, med, "nameserver name does not resolve")

	r = testenv.Run(t, env, dnschecks.GLUE)
	testenv.Expect(t, r, fail, med, "stale glue")
	testenv.Expect(t, r, fail, high, "in-bailiwick nameserver has no glue record")

	r = testenv.Run(t, env, dnschecks.AXFR)
	f := testenv.Expect(t, r, fail, high, "zone transfer allowed")
	if f.Subject != "ns1.example.test (45.33.10.1)" || len(f.Details) < 5 {
		t.Errorf("axfr finding = %+v", f)
	}

	r = testenv.Run(t, env, dnschecks.ANY)
	testenv.Expect(t, r, fail, med, "full answer to ANY queries")

	r = testenv.Run(t, env, dnschecks.Recursion)
	testenv.Expect(t, r, fail, high, "open resolver")

	r = testenv.Run(t, env, dnschecks.Version)
	testenv.Expect(t, r, fail, low, `software version disclosed: "9.11.4-P2-RedHat"`)
	testenv.Expect(t, r, info, none, "server identity disclosed")

	r = testenv.Run(t, env, dnschecks.CAA)
	testenv.Expect(t, r, fail, low, "CAA only restricts wildcard issuance")
}

func TestDanglingNameserverDomain(t *testing.T) {
	w := testenv.New(t)
	w.All("example.test. 3600 IN NS ns.expired-domain.test.")
	env := w.Env(testenv.Zone)
	r := testenv.Run(t, env, dnschecks.Delegation)
	f := testenv.Expect(t, r, fail, high, "nameserver domain expired-domain.test is not registered")
	if f.Subject != "ns.expired-domain.test" {
		t.Errorf("subject = %q", f.Subject)
	}
}

func TestCAAInherited(t *testing.T) {
	w := testenv.New(t)
	w.All("www.example.test. 300 IN A "+testenv.WebIP,
		`example.test. 300 IN CAA 0 issue "letsencrypt.org"`,
		`example.test. 300 IN CAA 0 iodef "mailto:security@example.test"`)
	env := w.Env("www.example.test")
	r := testenv.Run(t, env, dnschecks.CAA)
	f := testenv.Expect(t, r, pass, none, "CAA restricts certificate issuance")
	if f.Details[0] != "inherited from example.test" {
		t.Errorf("details = %q", f.Details)
	}
}

// signedZone signs the test zone and returns the KSK, ZSK and their private
// keys.
type keys struct {
	ksk, zsk         *dns.DNSKEY
	kskPriv, zskPriv crypto.Signer
}

func newKeys(t *testing.T) keys {
	t.Helper()
	mk := func(flags uint16) (*dns.DNSKEY, crypto.Signer) {
		k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags: flags, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
		priv, err := k.Generate(256)
		if err != nil {
			t.Fatal(err)
		}
		return k, priv.(crypto.Signer)
	}
	var k keys
	k.ksk, k.kskPriv = mk(257)
	k.zsk, k.zskPriv = mk(256)
	return k
}

func sign(t *testing.T, key *dns.DNSKEY, priv crypto.Signer, rrset []dns.RR, inception, expiration time.Time) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Ttl: rrset[0].Header().Ttl},
		Algorithm:  key.Algorithm,
		SignerName: key.Hdr.Name,
		KeyTag:     key.KeyTag(),
		Inception:  uint32(inception.Unix()),
		Expiration: uint32(expiration.Unix()),
	}
	if err := sig.Sign(priv, rrset); err != nil {
		t.Fatal(err)
	}
	return sig
}

func signedWorld(t *testing.T, k keys, expiration time.Time) *testenv.World {
	t.Helper()
	w := testenv.New(t)
	now := time.Now()
	soa, _ := dns.NewRR("example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2024010101 86400 7200 3600000 3600")
	dnskeys := []dns.RR{k.ksk, k.zsk}
	keySig := sign(t, k.ksk, k.kskPriv, dnskeys, now.Add(-time.Hour), expiration)
	soaSig := sign(t, k.zsk, k.zskPriv, []dns.RR{soa}, now.Add(-time.Hour), expiration)
	for _, s := range []interface{ AddRR(...dns.RR) }{w.NS1, w.NS2, w.Resolver} {
		s.AddRR(k.ksk, k.zsk, keySig, soaSig)
	}
	return w
}

func TestDNSSECValid(t *testing.T) {
	k := newKeys(t)
	w := signedWorld(t, k, time.Now().Add(30*24*time.Hour))
	w.Resolver.AddRR(k.ksk.ToDS(dns.SHA256))
	nsec3, _ := dns.NewRR("abcdef.example.test. 3600 IN NSEC3 1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG")
	w.NS1.SetDenial(nsec3)
	w.NS2.SetDenial(nsec3)
	env := w.Env(testenv.Zone)
	r := testenv.Run(t, env, dnschecks.DNSSEC)
	testenv.Expect(t, r, pass, none, "chain of trust is valid")
	testenv.Expect(t, r, pass, none, "zone data is validly signed")
	testenv.Expect(t, r, pass, none, "algorithms and key sizes follow current recommendations")
	testenv.Expect(t, r, pass, none, "NSEC3 with recommended parameters")
	if r.Status != pass {
		t.Errorf("status = %s\n%s", r.Status, testenv.Dump(r))
	}
}

func TestDNSSECBroken(t *testing.T) {
	k := newKeys(t)
	w := signedWorld(t, k, time.Now().Add(-time.Minute))
	ds := k.ksk.ToDS(dns.SHA1)
	ds.Digest = "0000000000000000000000000000000000000000"
	w.Resolver.AddRR(ds)
	nsec, _ := dns.NewRR("example.test. 3600 IN NSEC ns1.example.test. A NS SOA RRSIG NSEC DNSKEY")
	w.NS1.SetDenial(nsec)
	env := w.Env(testenv.Zone)
	r := testenv.Run(t, env, dnschecks.DNSSEC)
	testenv.Expect(t, r, fail, high, "no DNSKEY matches the DS records")
	testenv.Expect(t, r, fail, high, "zone signatures do not validate")
	testenv.Expect(t, r, fail, low, "SHA-1")
	testenv.Expect(t, r, fail, low, "zone walking")
}

func TestDNSSECIslandAndMissingKeys(t *testing.T) {
	k := newKeys(t)
	w := signedWorld(t, k, time.Now().Add(30*24*time.Hour))
	env := w.Env(testenv.Zone)
	r := testenv.Run(t, env, dnschecks.DNSSEC)
	testenv.Expect(t, r, fail, med, "zone is signed but the parent has no DS record")

	w2 := testenv.New(t)
	w2.Resolver.AddRR(k.ksk.ToDS(dns.SHA256))
	r = testenv.Run(t, w2.Env(testenv.Zone), dnschecks.DNSSEC)
	testenv.Expect(t, r, fail, high, "DS record published at the parent but the nameservers serve no DNSKEY")
}

func TestAXFRLoneSOAIsNotADisclosure(t *testing.T) {
	w := testenv.New(t)
	lone := func(rw dns.ResponseWriter, r *dns.Msg) bool {
		if r.Question[0].Qtype != dns.TypeAXFR {
			return false
		}
		m := new(dns.Msg)
		m.SetReply(r)
		soa, _ := dns.NewRR("example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 2 3 4 5")
		m.Answer = []dns.RR{soa}
		_ = rw.WriteMsg(m)
		_ = rw.Close()
		return true
	}
	w.NS1.SetHook(lone)
	w.NS2.SetHook(lone)
	r := testenv.Run(t, w.Env(testenv.Zone), dnschecks.AXFR)
	if len(r.Failed()) != 0 {
		t.Fatalf("lone SOA reported as zone transfer:\n%s", testenv.Dump(r))
	}
}

func TestPartialWhenSomeServersAreUnreachable(t *testing.T) {
	w := testenv.New(t)
	w.Client.Overrides[testenv.NS2IP] = "127.0.0.1:1" // closed port
	r := testenv.Run(t, w.Env(testenv.Zone), dnschecks.AXFR)
	if r.Status != core.StatusPartial {
		t.Fatalf("status = %s, want partial\n%s", r.Status, testenv.Dump(r))
	}
}

func TestDelegationDiversityWithIPv6OnlyNameserver(t *testing.T) {
	w := testenv.New(t)
	w.Resolver.Remove("ns2.example.test", dns.TypeA)
	w.Resolver.Add(t, "ns2.example.test. 3600 IN AAAA 2001:4860:4860::8888")
	w.Client.Overrides["2001:4860:4860::8888"] = w.NS2.Addr
	r := testenv.Run(t, w.Env(testenv.Zone), dnschecks.Delegation)
	if len(testenv.Find(r, "same network")) != 0 {
		t.Fatalf("IPv6-only nameserver ignored in the diversity verdict:\n%s", testenv.Dump(r))
	}
	testenv.Expect(t, r, pass, none, "spread over 2 different networks")
}
