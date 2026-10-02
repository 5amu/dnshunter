package mailchecks_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/5amu/dnshunter/internal/testenv"
	"github.com/5amu/dnshunter/pkg/checks/mailchecks"
	"github.com/5amu/dnshunter/pkg/core"
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

func spf(t *testing.T, records ...string) *core.Result {
	t.Helper()
	w := testenv.New(t)
	w.Resolver.Add(t, records...)
	return testenv.Run(t, w.Env(testenv.Zone), mailchecks.SPF)
}

func TestSPFMissing(t *testing.T) {
	r := spf(t)
	testenv.Expect(t, r, fail, med, "no SPF record")
}

func TestSPFHardFail(t *testing.T) {
	r := spf(t,
		`example.test. 300 IN TXT "v=spf1 ip4:45.33.30.0/24 include:_spf.mail.test -all"`,
		`_spf.mail.test. 300 IN TXT "v=spf1 ip4:198.51.100.0/24 ~all"`,
		`example.test. 300 IN TXT "google-site-verification=abc"`,
	)
	testenv.Expect(t, r, pass, none, "ends with -all")
	testenv.Expect(t, r, pass, none, "requires 1 DNS lookups")
	if r.Status != pass {
		t.Fatalf("status %s\n%s", r.Status, testenv.Dump(r))
	}
	tree := testenv.Expect(t, r, info, none, "SPF record tree")
	if len(tree.Details) != 2 || !strings.HasPrefix(tree.Details[1], "  _spf.mail.test: ") {
		t.Errorf("tree = %q", tree.Details)
	}
}

func TestSPFQualifiers(t *testing.T) {
	cases := map[string]struct {
		sev   core.Severity
		title string
	}{
		"v=spf1 mx +all": {high, "+all"},
		"v=spf1 mx ?all": {med, "?all"},
		"v=spf1 mx ~all": {low, "~all"},
		"v=spf1 mx":      {med, "no 'all' mechanism"},
	}
	for record, want := range cases {
		t.Run(record, func(t *testing.T) {
			r := spf(t, fmt.Sprintf(`example.test. 300 IN TXT "%s"`, record))
			testenv.Expect(t, r, fail, want.sev, want.title)
		})
	}
}

func TestSPFRedirect(t *testing.T) {
	// The original implementation crashed on redirect= modifiers.
	r := spf(t,
		`example.test. 300 IN TXT "v=spf1 redirect=_spf.example.test"`,
		`_spf.example.test. 300 IN TXT "v=spf1 a mx -all"`,
	)
	testenv.Expect(t, r, pass, none, "ends with -all")
	testenv.Expect(t, r, pass, none, "requires 3 DNS lookups")
}

func TestSPFErrors(t *testing.T) {
	records := []string{
		`example.test. 300 IN TXT "v=spf1 include:a.test include:b.test include:missing.test ip4:10.0.0.0/8 ptr -all"`,
		`example.test. 300 IN TXT "v=spf1 -all"`,
		`a.test. 300 IN TXT "v=spf1 include:c.test include:c2.test a mx exists:x.test ~all"`,
		`b.test. 300 IN TXT "v=spf1 +all"`,
		`c.test. 300 IN TXT "v=spf1 a mx a:x.test mx:y.test ~all"`,
		`c2.test. 300 IN TXT "v=spf1 include:c.test ~all"`,
	}
	r := spf(t, records...)
	testenv.Expect(t, r, fail, med, "publishes 2 SPF records")
	testenv.Expect(t, r, fail, med, "DNS lookups (limit 10)")
	testenv.Expect(t, r, fail, high, "include:b.test ends with +all")
	testenv.Expect(t, r, fail, med, "missing.test is referenced but has no SPF record")
	testenv.Expect(t, r, fail, high, "very large address range")
	testenv.Expect(t, r, fail, low, "deprecated ptr mechanism")
}

func TestSPFLoop(t *testing.T) {
	r := spf(t,
		`example.test. 300 IN TXT "v=spf1 include:loop.test -all"`,
		`loop.test. 300 IN TXT "v=spf1 include:example.test -all"`,
	)
	testenv.Expect(t, r, fail, med, "loop detected")
}

func dmarc(t *testing.T, domain string, records ...string) *core.Result {
	t.Helper()
	w := testenv.New(t)
	w.All("www.example.test. 300 IN A " + testenv.WebIP)
	w.Resolver.Add(t, records...)
	return testenv.Run(t, w.Env(domain), mailchecks.DMARC)
}

func TestDMARC(t *testing.T) {
	r := dmarc(t, testenv.Zone)
	testenv.Expect(t, r, fail, med, "no DMARC record")

	r = dmarc(t, testenv.Zone, `_dmarc.example.test. 300 IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.test; adkim=s; aspf=s"`)
	testenv.Expect(t, r, pass, none, "policy is reject")
	if r.Status != pass {
		t.Errorf("status %s\n%s", r.Status, testenv.Dump(r))
	}

	r = dmarc(t, testenv.Zone, `_dmarc.example.test. 300 IN TXT "v=DMARC1; p=none"`)
	testenv.Expect(t, r, fail, med, "policy is none")
	testenv.Expect(t, r, info, none, "no aggregate report destination")

	r = dmarc(t, testenv.Zone, `_dmarc.example.test. 300 IN TXT "v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:reports@dmarc.vendor.test"`)
	testenv.Expect(t, r, fail, low, "subdomain policy sp=none is weaker")
	testenv.Expect(t, r, fail, low, "pct=50")
	testenv.Expect(t, r, info, none, "has not authorized reports")

	r = dmarc(t, testenv.Zone,
		`_dmarc.example.test. 300 IN TXT "v=DMARC1; p=quarantine; rua=mailto:reports@dmarc.vendor.test"`,
		`example.test._report._dmarc.dmarc.vendor.test. 300 IN TXT "v=DMARC1"`)
	testenv.Expect(t, r, fail, low, "policy is quarantine")
	if len(testenv.Find(r, "has not authorized reports")) != 0 {
		t.Errorf("authorized destination reported as unauthorized\n%s", testenv.Dump(r))
	}

	r = dmarc(t, testenv.Zone, `_dmarc.example.test. 300 IN TXT "v=DMARC1; p=reject"`, `_dmarc.example.test. 300 IN TXT "v=DMARC1; p=none"`)
	testenv.Expect(t, r, fail, med, "2 DMARC records")
}

func TestDMARCInheritedFromOrganizationalDomain(t *testing.T) {
	r := dmarc(t, "www.example.test", `_dmarc.example.test. 300 IN TXT "v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.test"`)
	f := testenv.Expect(t, r, info, none, "DMARC record")
	if !strings.Contains(strings.Join(f.Details, " "), "inherited from the organizational domain example.test") {
		t.Errorf("details = %q", f.Details)
	}
	testenv.Expect(t, r, fail, low, "policy is quarantine")
}

func dkimKey(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Skipf("cannot generate %d bits RSA key: %v", bits, err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// txtRecord splits long values in 255 bytes character-strings.
func txtRecord(name, value string) string {
	var parts []string
	for len(value) > 200 {
		parts = append(parts, `"`+value[:200]+`"`)
		value = value[200:]
	}
	parts = append(parts, `"`+value+`"`)
	return name + " 300 IN TXT " + strings.Join(parts, " ")
}

func TestDKIM(t *testing.T) {
	w := testenv.New(t)
	w.Resolver.Add(t,
		txtRecord("selector1._domainkey.example.test.", "v=DKIM1; k=rsa; p="+dkimKey(t, 2048)),
		txtRecord("google._domainkey.example.test.", "v=DKIM1; k=rsa; t=y; p="+dkimKey(t, 1024)),
		txtRecord("custom._domainkey.example.test.", "v=DKIM1; p="),
	)
	env := w.Env(testenv.Zone)
	env.Opts.DKIMSelectors = []string{"custom"}
	r := testenv.Run(t, env, mailchecks.DKIM)
	testenv.Expect(t, r, pass, none, `selector "selector1", rsa 2048 bits`)
	testenv.Expect(t, r, fail, low, "1024 bits: 2048 bits are recommended")
	testenv.Expect(t, r, fail, low, "testing mode")
	testenv.Expect(t, r, info, none, "revoked DKIM key")
}

func TestDKIMMissing(t *testing.T) {
	w := testenv.New(t)
	r := testenv.Run(t, w.Env(testenv.Zone), mailchecks.DKIM)
	testenv.Expect(t, r, fail, low, "_domainkey does not exist")

	w = testenv.New(t)
	w.Resolver.Add(t, txtRecord("s2024._domainkey.example.test.", "v=DKIM1; p="+dkimKey(t, 2048)))
	r = testenv.Run(t, w.Env(testenv.Zone), mailchecks.DKIM)
	testenv.Expect(t, r, info, none, "no DKIM key found among")
}

// weakKey is a 512 bits RSA public key (Go refuses to generate such keys).
const weakKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlSUgKqxUQYl7riVK35vkXdGccIiFsJC3/PI3YF2/XVKqF/snXcjj1gfVJBGuxs3wSNwmDCgaMa9ZJkIySUfzECAwEAAQ=="

func TestDKIMWeakKey(t *testing.T) {
	w := testenv.New(t)
	w.Resolver.Add(t, txtRecord("default._domainkey.example.test.", "v=DKIM1; h=sha1; p="+weakKey))
	r := testenv.Run(t, w.Env(testenv.Zone), mailchecks.DKIM)
	testenv.Expect(t, r, fail, high, "only 512 bits")
	testenv.Expect(t, r, fail, med, "SHA-1 is forbidden")
}

func TestSPFIgnoresTermsAfterAll(t *testing.T) {
	r := spf(t, `example.test. 300 IN TXT "v=spf1 -all include:a.test include:b.test include:c.test a mx a mx a mx a mx"`)
	if r.Status != pass {
		t.Fatalf("terms after all were evaluated:\n%s", testenv.Dump(r))
	}
	testenv.Expect(t, r, pass, none, "requires 0 DNS lookups")
}
