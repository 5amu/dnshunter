package dnschecks

import (
	"fmt"
	"net"
	"strings"

	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
)

type DMARCCheck struct {
	description []string
	poc         string
	client      *dns.Client
	output      *output.CheckOutput
}

func (c *DMARCCheck) Init(client *dns.Client) error {
	c.client = client
	c.description = []string{
		"DMARC is a record that correlates SPF and DKIM and takes action",
		"according to its policy: none, quarantine, reject.",
	}
	c.poc = "dig -t TXT +noall +answer _dmarc.%v @%v"
	return nil
}

func (c *DMARCCheck) Start(domain string, nameservers *utils.Nameservers) error {
	c.output = &output.CheckOutput{
		Name:        "DMARC Record",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Description: c.description,
	}

	for _, fqdn := range nameservers.FQDNs {
		var res output.SingleCheckResult
		res.Nameserver = fqdn
		res.Zone = domain

		r, err := utils.MakeQuery(
			c.client,
			dns.Fqdn(fmt.Sprintf("_dmarc.%v", domain)),
			net.JoinHostPort(nameservers.GetIP(fqdn).String(), "53"),
			dns.TypeTXT,
		)
		if err != nil {
			return err
		}

		for _, a := range r.Answer {
			switch t := a.(type) {
			case *dns.TXT:
				if strings.Contains(t.Txt[0], "v=dmarc") {
					if strings.Contains(t.Txt[0], "p=quarantine") {
						res.Vulnerable = true
						res.Information = append(res.Information, "partially secure policy: quarantine")
						msg := fmt.Sprintf(c.poc, domain, fqdn)
						res.Information = append(res.Information, msg)
					}
					if strings.Contains(t.Txt[0], "p=none") {
						res.Vulnerable = true
						res.Information = append(res.Information, "insecure policy: none")
						msg := fmt.Sprintf(c.poc, domain, fqdn)
						res.Information = append(res.Information, msg)
					}
					break
				}
			}
		}
		c.output.Results = append(c.output.Results, res)
	}
	return nil
}

func (c *DMARCCheck) Results() *output.CheckOutput {
	return c.output
}
