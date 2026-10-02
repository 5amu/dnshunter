package mailchecks

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/miekg/dns"
)

// DKIM looks for DKIM public keys published under common selectors and
// reviews their strength.
var DKIM = &core.Check{
	ID:       "dkim",
	Name:     "DKIM records",
	Category: core.CategoryMail,
	Description: "DKIM signs outgoing e-mail with a key published in DNS under <selector>._domainkey. " +
		"Selectors cannot be enumerated, so common ones are probed (add yours with -dkim-selectors). " +
		"Missing keys prevent DMARC alignment through DKIM; RSA keys shorter than 1024 bits can be " +
		"factored and used to forge signed mail.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc6376",
		"https://www.rfc-editor.org/rfc/rfc8301",
	},
	Run: runDKIM,
}

// DefaultSelectors are probed on every domain.
var DefaultSelectors = []string{
	"default", "dkim", "dkim1", "dkim2", "mail", "email", "smtp", "mx", "key1", "key2",
	"selector", "selector1", "selector2", "selector3", "s1", "s2", "s1024", "s2048",
	"k1", "k2", "k3", "google", "mandrill", "mailjet", "sendgrid", "smtpapi", "pm", "mxvault",
	"zoho", "zmail", "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3",
	"sig1", "everlytickey1", "everlytickey2", "cm", "hs1", "hs2", "sm", "mailo", "mesmtp",
	"dkimpal", "dkim-shared", "mdaemon", "gamma", "beta", "amazonses", "turbo-smtp", "krs",
}

type dkimKey struct {
	selector string
	record   string
}

func runDKIM(ctx context.Context, env *core.Env, r *core.Result) error {
	domain := env.Target.Domain
	selectors := selectorList(domain, env.Opts.DKIMSelectors)

	results := core.ParallelMap(selectors, 10, func(sel string) *dkimKey {
		txt, _, err := env.DNS.LookupTXT(ctx, fmt.Sprintf("%s._domainkey.%s", sel, domain))
		if err != nil {
			return nil
		}
		for _, t := range txt {
			tags := parseTags(t)
			if _, ok := tags["p"]; ok || strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dkim1") {
				return &dkimKey{selector: sel, record: t}
			}
		}
		return nil
	})

	var found []*dkimKey
	for _, k := range results {
		if k != nil {
			found = append(found, k)
		}
	}

	if len(found) == 0 {
		node := "_domainkey." + domain
		m, err := env.DNS.Lookup(ctx, node, dns.TypeTXT)
		if err == nil && m.Rcode == dns.RcodeNameError {
			r.Add(core.Fail(core.SeverityLow, domain, "no DKIM key published: _domainkey does not exist",
				"messages cannot be DKIM-signed, DMARC relies on SPF alone").WithPoC("dig TXT %s", node))
		} else {
			r.Add(core.Info(domain, fmt.Sprintf("no DKIM key found among %d common selectors", len(selectors)),
				"keys may use custom selectors: read the DKIM-Signature header (s= tag) of a message from the domain and pass it with -dkim-selectors"))
		}
		return nil
	}

	for _, k := range found {
		evaluateKey(r, domain, k)
	}
	return nil
}

func selectorList(domain string, extra []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range extra {
		add(s)
	}
	add(strings.Split(domain, ".")[0])
	for _, s := range DefaultSelectors {
		add(s)
	}
	return out
}

func evaluateKey(r *core.Result, domain string, k *dkimKey) {
	subject := fmt.Sprintf("%s._domainkey.%s", k.selector, domain)
	poc := fmt.Sprintf("dig TXT %s +short", subject)
	tags := parseTags(k.record)
	p := strings.Join(strings.Fields(tags["p"]), "")
	if p == "" {
		r.Add(core.Info(subject, "revoked DKIM key (empty p= tag)").WithPoC("%s", poc))
		return
	}
	keyType := strings.ToLower(tags["k"])
	if keyType == "" {
		keyType = "rsa"
	}
	var issues []core.Finding
	desc := keyType
	if keyType == "rsa" {
		bits, err := rsaBits(p)
		switch {
		case err != nil:
			issues = append(issues, core.Fail(core.SeverityLow, subject, fmt.Sprintf("DKIM public key cannot be parsed: %v", err)))
		case bits < 1024:
			issues = append(issues, core.Fail(core.SeverityHigh, subject, fmt.Sprintf("DKIM RSA key is only %d bits: it can be factored to forge signed e-mail (RFC 8301 requires 1024+)", bits)))
		case bits < 2048:
			issues = append(issues, core.Fail(core.SeverityLow, subject, fmt.Sprintf("DKIM RSA key is %d bits: 2048 bits are recommended", bits)))
		}
		if err == nil {
			desc = fmt.Sprintf("rsa %d bits", bits)
		}
	}
	if strings.Contains(strings.ToLower(tags["t"]), "y") {
		issues = append(issues, core.Fail(core.SeverityLow, subject, "DKIM key is in testing mode (t=y): receivers treat signed and unsigned mail alike"))
	}
	if h := strings.ToLower(tags["h"]); h != "" && !strings.Contains(h, "sha256") {
		issues = append(issues, core.Fail(core.SeverityMedium, subject, fmt.Sprintf("DKIM key only allows the %s hash (SHA-1 is forbidden by RFC 8301)", h)))
	}
	for i := range issues {
		issues[i] = issues[i].WithPoC("%s", poc)
	}
	r.Add(issues...)
	if len(issues) == 0 {
		r.Add(core.Pass(subject, fmt.Sprintf("DKIM key found (selector %q, %s)", k.selector, desc)).WithPoC("%s", poc))
	}
}

// rsaBits returns the modulus size of a base64 DKIM RSA public key
// (SubjectPublicKeyInfo, or bare PKCS#1 as used by some signers).
func rsaBits(p string) (int, error) {
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return 0, fmt.Errorf("invalid base64: %w", err)
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return 0, fmt.Errorf("not an RSA key")
		}
		return rk.N.BitLen(), nil
	}
	rk, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return 0, fmt.Errorf("not a valid RSA public key")
	}
	return rk.N.BitLen(), nil
}
