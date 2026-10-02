package dnschecks

import (
	"context"
	"fmt"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/miekg/dns"
)

// CAA checks whether the domain restricts which certificate authorities may
// issue certificates for it.
var CAA = &core.Check{
	ID:       "caa",
	Name:     "CAA record",
	Category: core.CategoryDNS,
	Description: "Certification Authority Authorization (CAA) records list the CAs allowed to issue " +
		"certificates for the domain. Without them any public CA may issue a certificate, which widens " +
		"the attack surface for mis-issuance.",
	References: []string{
		"https://www.rfc-editor.org/rfc/rfc8659",
	},
	Run: runCAA,
}

func runCAA(ctx context.Context, env *core.Env, r *core.Result) error {
	domain := env.Target.Domain
	// RFC 8659 §3: climb the tree until a non-empty CAA RRset is found.
	for name := domain; !dnsutil.IsPublicSuffix(name); name = dnsutil.Parent(name) {
		resp, err := env.DNS.Lookup(ctx, name, dns.TypeCAA)
		if err != nil {
			return err
		}
		var caa []*dns.CAA
		for _, rr := range resp.Answer {
			if c, ok := rr.(*dns.CAA); ok {
				caa = append(caa, c)
			}
		}
		if len(caa) == 0 {
			continue
		}
		evaluateCAA(r, domain, name, caa)
		return nil
	}
	r.Add(core.Fail(core.SeverityLow, domain, "no CAA record: any certificate authority may issue certificates for the domain").
		WithPoC("dig CAA %s +short", domain))
	return nil
}

func evaluateCAA(r *core.Result, domain, owner string, caa []*dns.CAA) {
	var issuers, wild, iodef, other []string
	for _, c := range caa {
		tag := strings.ToLower(c.Tag)
		switch tag {
		case "issue":
			issuers = append(issuers, caaValue(c.Value))
		case "issuewild":
			wild = append(wild, caaValue(c.Value))
		case "iodef":
			iodef = append(iodef, c.Value)
		default:
			other = append(other, fmt.Sprintf("%d %s %q", c.Flag, c.Tag, c.Value))
		}
	}
	details := []string{}
	if owner != domain {
		details = append(details, "inherited from "+owner)
	}
	if len(issuers) > 0 {
		details = append(details, "issue: "+strings.Join(issuers, ", "))
	}
	if len(wild) > 0 {
		details = append(details, "issuewild: "+strings.Join(wild, ", "))
	}
	if len(iodef) > 0 {
		details = append(details, "iodef: "+strings.Join(iodef, ", "))
	}
	if len(other) > 0 {
		details = append(details, "other: "+strings.Join(other, "; "))
	}
	if len(issuers) == 0 && len(wild) > 0 {
		r.Add(core.Fail(core.SeverityLow, domain, "CAA only restricts wildcard issuance: any CA may issue non-wildcard certificates", details...))
		return
	}
	if len(issuers) == 0 {
		r.Add(core.Fail(core.SeverityLow, domain, "CAA records present but without an issue property: issuance is not restricted", details...))
		return
	}
	r.Add(core.Pass(domain, "CAA restricts certificate issuance", details...))
	if len(iodef) == 0 {
		r.Add(core.Info(domain, "no iodef property: CAs cannot report rejected issuance requests"))
	}
}

func caaValue(v string) string {
	v = strings.TrimSpace(v)
	if v == ";" || v == "" {
		return "none (issuance forbidden)"
	}
	return v
}
