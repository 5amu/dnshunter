package dnschecks

import (
	"fmt"
	"net"

	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
)

type AXFRCheck struct {
	description []string
	client      *dns.Client
	output      *output.CheckOutput
}

func (c *AXFRCheck) Init(client *dns.Client) error {
	c.client = client
	c.description = []string{
		"The nameserver allows zone transfers from unauthorized sources, this",
		"leads to the disclosure of all the zone's domains handled by the ns",
		"(at best). In the worse case scenario, the attacker might be able to",
		"get ownership on the zone handled by the dns.",
	}
	return nil
}

func (c *AXFRCheck) Start(domain string, nameservers *utils.Nameservers) error {
	c.output = &output.CheckOutput{
		Name:        "Unprotected Zone Transfer",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Description: c.description,
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAXFR)

	for _, fqdn := range nameservers.FQDNs {
		var res output.SingleCheckResult
		res.Nameserver = fqdn
		res.Zone = domain
		res.Vulnerable = false

		conn, err := net.Dial("tcp", net.JoinHostPort(nameservers.GetIP(fqdn).String(), "53"))
		if err != nil {
			continue
		}
		transfer := &dns.Transfer{Conn: &dns.Conn{Conn: conn}}
		channel, err := transfer.In(m, nameservers.GetIP(fqdn).String())
		if err != nil {
			continue
		}

		var vuln []dns.RR
		for r := range channel {
			if r.Error != nil || len(r.RR) == 0 {
				continue
			}
			res.Vulnerable = true
			vuln = append(vuln, r.RR...)
		}

		if res.Vulnerable {
			for _, v := range vuln {
				switch t := v.(type) {
				case *dns.A:
					res.Information = append(res.Information, fmt.Sprintf("%v ==> (%v) %v\n", t.Hdr.Name, "A", t.A))
				case *dns.AAAA:
					res.Information = append(res.Information, fmt.Sprintf("%v ==> (%v) %v\n", t.Hdr.Name, "AAAA", t.AAAA))
				case *dns.TXT:
					res.Information = append(res.Information, fmt.Sprintf("%v ==> (%v) %v\n", t.Hdr.Name, "TXT", t.Txt[0]))
				case *dns.MX:
					res.Information = append(res.Information, fmt.Sprintf("%v ==> (%v) %v\n", t.Hdr.Name, "MX", t.Mx))
				}
			}
		}
		c.output.Results = append(c.output.Results, res)
	}
	return nil
}

func (c *AXFRCheck) Results() *output.CheckOutput {
	return c.output
}
