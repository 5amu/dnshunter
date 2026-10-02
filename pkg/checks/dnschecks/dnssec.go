package dnschecks

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/5amu/dnshunter/pkg/target"
	"github.com/miekg/dns"
)

// DNSSEC verifies that the zone is signed and that the chain of trust from the
// parent is intact, and reviews algorithms, signatures and denial of existence.
var DNSSEC = &core.Check{
	ID:       "dnssec",
	Name:     "DNSSEC",
	Category: core.CategoryDNS,
	Description: "DNSSEC lets resolvers verify that answers really come from the zone owner, protecting " +
		"against cache poisoning and on-path tampering. It requires a signed zone (DNSKEY/RRSIG) and a DS " +
		"record at the parent matching the key-signing key. Broken chains make the domain unresolvable for " +
		"validating resolvers; weak algorithms and NSEC allow forgery or zone enumeration.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc4033",
		"https://www.rfc-editor.org/rfc/rfc8624",
		"https://www.rfc-editor.org/rfc/rfc9276",
	},
	Run: runDNSSEC,
}

func runDNSSEC(ctx context.Context, env *core.Env, r *core.Result) error {
	zone := env.Target.Zone
	fqdn := dns.Fqdn(zone)

	var dsSet []*dns.DS
	dsMsg, dsErr := env.DNS.Lookup(ctx, zone, dns.TypeDS, dnsutil.DNSSEC())
	if dsErr == nil {
		for _, rr := range dsMsg.Answer {
			if ds, ok := rr.(*dns.DS); ok && strings.EqualFold(ds.Hdr.Name, fqdn) {
				dsSet = append(dsSet, ds)
			}
		}
	}

	answers := queryAll(ctx, env, zone, dns.TypeDNSKEY, dnsutil.DNSSEC())
	if len(answers) == 0 {
		return errNoEndpoint
	}
	var keys []*dns.DNSKEY
	var keySigs []*dns.RRSIG
	var keyEP target.Endpoint
	var withKeys, withoutKeys []string
	for _, a := range answers {
		if a.err != nil {
			r.Add(core.Errorf(a.ep.String(), "no answer to DNSKEY query: %v", a.err))
			continue
		}
		var k []*dns.DNSKEY
		var s []*dns.RRSIG
		for _, rr := range a.msg.Answer {
			switch t := rr.(type) {
			case *dns.DNSKEY:
				k = append(k, t)
			case *dns.RRSIG:
				if t.TypeCovered == dns.TypeDNSKEY {
					s = append(s, t)
				}
			}
		}
		if len(k) == 0 {
			withoutKeys = append(withoutKeys, a.ep.String())
			continue
		}
		withKeys = append(withKeys, a.ep.String())
		if keys == nil {
			keys, keySigs, keyEP = k, s, a.ep
		}
	}

	dsPoC := fmt.Sprintf("dig DS %s +dnssec +short", zone)
	switch {
	case dsErr != nil && len(keys) == 0:
		return fmt.Errorf("could not look up DS records: %v", dsErr)
	case len(dsSet) == 0 && len(keys) == 0:
		if len(withoutKeys) == 0 {
			return fmt.Errorf("no nameserver answered the DNSKEY query")
		}
		r.Add(core.Fail(core.SeverityMedium, zone, "DNSSEC is not enabled: no DS record at the parent and no DNSKEY in the zone",
			"answers for the zone can be spoofed (cache poisoning, on-path attacks)").WithPoC("%s", dsPoC))
		return nil
	case len(keys) == 0:
		r.Add(core.Fail(core.SeverityHigh, zone, "DS record published at the parent but the nameservers serve no DNSKEY",
			"validating resolvers will treat the zone as bogus: the domain becomes unresolvable for them").WithPoC("%s", dsPoC))
		return nil
	}

	if len(withoutKeys) > 0 {
		r.Add(core.Fail(core.SeverityHigh, zone, "nameservers serve inconsistent DNSSEC data",
			"DNSKEY served by: "+strings.Join(withKeys, ", "),
			"no DNSKEY from: "+strings.Join(withoutKeys, ", ")))
	}

	r.Add(core.Info(zone, "DNSKEY records", describeKeys(keys)...).WithPoC("%s", digAt(keyEP, "DNSKEY "+zone+" +dnssec +multi")))

	if len(dsSet) == 0 {
		if dsErr != nil {
			r.Add(core.Errorf(zone, "could not look up DS records: %v", dsErr))
		} else {
			r.Add(core.Fail(core.SeverityMedium, zone, "zone is signed but the parent has no DS record (no chain of trust)",
				"resolvers cannot validate the zone: DNSSEC provides no protection").WithPoC("%s", dsPoC))
		}
	} else {
		evaluateDS(r, zone, dsSet, keys, keySigs)
	}

	evaluateAlgorithms(r, zone, keys, dsSet)
	if ep := keyEP; ep.IP != nil {
		evaluateSOASignature(ctx, env, r, ep, zone, keys)
		evaluateDenial(ctx, env, r, ep, zone)
	}
	return nil
}

func describeKeys(keys []*dns.DNSKEY) []string {
	var out []string
	for _, k := range keys {
		role := "ZSK"
		if k.Flags&dns.SEP != 0 {
			role = "KSK"
		}
		if k.Flags&dns.REVOKE != 0 {
			role += " (revoked)"
		}
		bits := ""
		if n := keyBits(k); n > 0 {
			bits = fmt.Sprintf(", %d bits", n)
		}
		out = append(out, fmt.Sprintf("%s tag %d, algorithm %s%s", role, k.KeyTag(), algName(k.Algorithm), bits))
	}
	return out
}

func evaluateDS(r *core.Result, zone string, dsSet []*dns.DS, keys []*dns.DNSKEY, sigs []*dns.RRSIG) {
	var matched []*dns.DNSKEY
	for _, ds := range dsSet {
		for _, k := range keys {
			if k.KeyTag() != ds.KeyTag || k.Algorithm != ds.Algorithm {
				continue
			}
			if c := k.ToDS(ds.DigestType); c != nil && strings.EqualFold(c.Digest, ds.Digest) {
				matched = append(matched, k)
			}
		}
	}
	var dsDesc []string
	for _, ds := range dsSet {
		dsDesc = append(dsDesc, fmt.Sprintf("DS tag %d, algorithm %s, digest %s", ds.KeyTag, algName(ds.Algorithm), digestName(ds.DigestType)))
	}
	if len(matched) == 0 {
		r.Add(core.Fail(core.SeverityHigh, zone, "no DNSKEY matches the DS records at the parent (broken chain of trust)",
			append(dsDesc, "validating resolvers will consider the zone bogus and refuse to resolve it")...))
		return
	}

	rrset := make([]dns.RR, len(keys))
	for i, k := range keys {
		rrset[i] = k
	}
	now := time.Now()
	var errs []string
	for _, sig := range sigs {
		for _, k := range matched {
			if sig.KeyTag != k.KeyTag() || sig.Algorithm != k.Algorithm {
				continue
			}
			if err := sig.Verify(k, rrset); err != nil {
				errs = append(errs, fmt.Sprintf("signature by key %d: %v", k.KeyTag(), err))
				continue
			}
			if !sig.ValidityPeriod(now) {
				errs = append(errs, fmt.Sprintf("signature by key %d is outside its validity period (%s - %s)",
					k.KeyTag(), dns.TimeToString(sig.Inception), dns.TimeToString(sig.Expiration)))
				continue
			}
			r.Add(core.Pass(zone, "chain of trust is valid: DS matches a key-signing key that signs the DNSKEY set", dsDesc...))
			return
		}
	}
	if len(errs) == 0 {
		errs = append(errs, "no RRSIG over the DNSKEY set was made by a key referenced by the DS records")
	}
	r.Add(core.Fail(core.SeverityHigh, zone, "DNSKEY set is not validly signed by the key referenced at the parent", errs...))
}

func evaluateAlgorithms(r *core.Result, zone string, keys []*dns.DNSKEY, dsSet []*dns.DS) {
	var weak, deprecated, short []string
	for _, k := range keys {
		switch k.Algorithm {
		case dns.RSAMD5, dns.DSA, dns.DSANSEC3SHA1, dns.ECCGOST:
			weak = append(weak, fmt.Sprintf("key %d uses %s (MUST NOT be used, RFC 8624)", k.KeyTag(), algName(k.Algorithm)))
		case dns.RSASHA1, dns.RSASHA1NSEC3SHA1:
			deprecated = append(deprecated, fmt.Sprintf("key %d uses %s (NOT RECOMMENDED, RFC 8624)", k.KeyTag(), algName(k.Algorithm)))
		}
		if isRSA(k.Algorithm) {
			if n := keyBits(k); n > 0 && n < 2048 {
				short = append(short, fmt.Sprintf("key %d is a %d bits RSA key", k.KeyTag(), n))
			}
		}
	}
	for _, ds := range dsSet {
		if ds.DigestType == dns.SHA1 {
			deprecated = append(deprecated, fmt.Sprintf("DS for key %d uses a SHA-1 digest (MUST NOT be used, RFC 8624)", ds.KeyTag))
		}
	}
	if len(weak) > 0 {
		r.Add(core.Fail(core.SeverityMedium, zone, "DNSSEC uses broken algorithms", weak...))
	}
	if len(deprecated) > 0 {
		r.Add(core.Fail(core.SeverityLow, zone, "DNSSEC uses deprecated SHA-1 based algorithms", deprecated...))
	}
	if len(short) > 0 {
		r.Add(core.Fail(core.SeverityLow, zone, "RSA keys shorter than 2048 bits", short...))
	}
	if len(weak)+len(deprecated)+len(short) == 0 {
		r.Add(core.Pass(zone, "DNSSEC algorithms and key sizes follow current recommendations"))
	}
}

func evaluateSOASignature(ctx context.Context, env *core.Env, r *core.Result, ep target.Endpoint, zone string, keys []*dns.DNSKEY) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.RecursionDesired = false
	m.SetEdns0(1232, true)
	resp, err := env.DNS.Exchange(ctx, m, env.DNS.Addr(ep.IP))
	if err != nil {
		r.Add(core.Errorf(ep.String(), "SOA query failed: %v", err))
		return
	}
	var rrset []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range resp.Answer {
		switch t := rr.(type) {
		case *dns.SOA:
			rrset = append(rrset, t)
		case *dns.RRSIG:
			if t.TypeCovered == dns.TypeSOA {
				sigs = append(sigs, t)
			}
		}
	}
	if len(rrset) == 0 {
		r.Add(core.Errorf(ep.String(), "no SOA record returned"))
		return
	}
	if len(sigs) == 0 {
		r.Add(core.Fail(core.SeverityHigh, ep.String(), "SOA record is not signed although the zone publishes DNSKEY records").
			WithPoC("%s", digAt(ep, "SOA "+zone+" +dnssec")))
		return
	}
	now := time.Now()
	var errs []string
	for _, sig := range sigs {
		for _, k := range keys {
			if k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm {
				continue
			}
			if err := sig.Verify(k, rrset); err != nil {
				errs = append(errs, fmt.Sprintf("signature by key %d: %v", k.KeyTag(), err))
				continue
			}
			if !sig.ValidityPeriod(now) {
				errs = append(errs, fmt.Sprintf("signature by key %d expired or not yet valid (%s - %s)",
					k.KeyTag(), dns.TimeToString(sig.Inception), dns.TimeToString(sig.Expiration)))
				continue
			}
			exp := time.Unix(int64(sig.Expiration), 0)
			// Signers refresh signatures well before they expire: less
			// than 20% of the validity window left means re-signing is
			// not happening. (Online signers such as Cloudflare or NS1
			// use short ~2 days windows, so an absolute threshold would
			// always trigger.)
			window := time.Duration(sig.Expiration-sig.Inception) * time.Second
			if left := time.Until(exp); left < window/5 {
				r.Add(core.Fail(core.SeverityLow, zone, "zone signatures are about to expire",
					fmt.Sprintf("SOA signature expires on %s (in %s): check that re-signing works", exp.UTC().Format(time.RFC3339), left.Round(time.Minute))))
			} else {
				r.Add(core.Pass(zone, "zone data is validly signed",
					fmt.Sprintf("SOA signature by key %d valid until %s", k.KeyTag(), exp.UTC().Format(time.RFC3339))))
			}
			return
		}
	}
	if len(errs) == 0 {
		errs = append(errs, "the signing key is not in the DNSKEY set")
	}
	r.Add(core.Fail(core.SeverityHigh, zone, "zone signatures do not validate", errs...))
}

func evaluateDenial(ctx context.Context, env *core.Env, r *core.Result, ep target.Endpoint, zone string) {
	label := make([]byte, 6)
	_, _ = rand.Read(label)
	qname := fmt.Sprintf("dnshunter-%s.%s", hex.EncodeToString(label), dns.Fqdn(zone))
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)
	m.RecursionDesired = false
	m.SetEdns0(1232, true)
	resp, err := env.DNS.Exchange(ctx, m, env.DNS.Addr(ep.IP))
	if err != nil {
		r.Add(core.Errorf(ep.String(), "denial of existence query failed: %v", err))
		return
	}
	var nsec []*dns.NSEC
	var nsec3 []*dns.NSEC3
	for _, rr := range resp.Ns {
		switch t := rr.(type) {
		case *dns.NSEC:
			nsec = append(nsec, t)
		case *dns.NSEC3:
			nsec3 = append(nsec3, t)
		}
	}
	poc := digAt(ep, fmt.Sprintf("A %s +dnssec", strings.TrimSuffix(qname, ".")))
	switch {
	case len(nsec) > 0:
		for _, n := range nsec {
			// "Black lies" / compact denial (RFC 9824) answer NODATA with an
			// NSEC owned by the queried name, which reveals nothing.
			if !strings.EqualFold(n.Hdr.Name, qname) {
				r.Add(core.Fail(core.SeverityLow, zone, "zone uses NSEC: its whole content can be enumerated by zone walking",
					fmt.Sprintf("NSEC %s -> %s", n.Hdr.Name, n.NextDomain),
					"consider NSEC3 (RFC 5155) or compact denial of existence").WithPoC("%s", poc))
				return
			}
		}
		r.Add(core.Pass(zone, "denial of existence uses compact (minimally covering) NSEC records: zone walking is not possible"))
	case len(nsec3) > 0:
		n := nsec3[0]
		var issues []string
		if n.Iterations > 0 {
			issues = append(issues, fmt.Sprintf("NSEC3 uses %d additional iterations (RFC 9276 requires 0): CPU cost for resolvers without security benefit", n.Iterations))
		}
		if n.Salt != "" && n.Salt != "-" {
			issues = append(issues, fmt.Sprintf("NSEC3 uses a salt (%s): RFC 9276 recommends an empty salt", n.Salt))
		}
		if len(issues) > 0 {
			r.Add(core.Fail(core.SeverityLow, zone, "NSEC3 parameters do not follow RFC 9276", issues...).WithPoC("%s", poc))
		} else {
			r.Add(core.Pass(zone, "denial of existence uses NSEC3 with recommended parameters"))
		}
		if n.Flags&1 == 1 {
			r.Add(core.Info(zone, "NSEC3 opt-out is enabled: unsigned delegations are not covered"))
		}
	default:
		if resp.Rcode == dns.RcodeNameError || (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0) {
			r.Add(core.Fail(core.SeverityMedium, ep.String(), "negative answers are not authenticated (no NSEC/NSEC3 records)").WithPoC("%s", poc))
		} else {
			r.Add(core.Info(ep.String(), fmt.Sprintf("could not test denial of existence (answer: %s with %d records, wildcard?)", rcode(resp), len(resp.Answer))))
		}
	}
}

func isRSA(alg uint8) bool {
	switch alg {
	case dns.RSAMD5, dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		return true
	}
	return false
}

// keyBits returns the modulus size of RSA keys (RFC 3110 encoding), 0 for
// other algorithms.
func keyBits(k *dns.DNSKEY) int {
	if !isRSA(k.Algorithm) {
		return 0
	}
	b, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(b) < 3 {
		return 0
	}
	explen, off := int(b[0]), 1
	if explen == 0 {
		explen, off = int(b[1])<<8|int(b[2]), 3
	}
	if off+explen >= len(b) {
		return 0
	}
	mod := b[off+explen:]
	for len(mod) > 0 && mod[0] == 0 {
		mod = mod[1:]
	}
	if len(mod) == 0 {
		return 0
	}
	bits := len(mod) * 8
	for top := mod[0]; top&0x80 == 0; top <<= 1 {
		bits--
	}
	return bits
}

func algName(a uint8) string {
	if n, ok := dns.AlgorithmToString[a]; ok {
		return fmt.Sprintf("%s (%d)", n, a)
	}
	return fmt.Sprint(a)
}

func digestName(d uint8) string {
	if n, ok := dns.HashToString[d]; ok {
		return n
	}
	return fmt.Sprint(d)
}
