package dnschecks

import (
	"fmt"
	"net"
	"strings"

	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
)

type DKIMCheck struct {
	description []string
	client      *dns.Client
	output      *output.CheckOutput
}

func (c *DKIMCheck) Init(client *dns.Client) error {
	c.client = client
	c.description = []string{
		"DKIM is a TXT record that guarantees that a particular email comes",
		"from the advertised organization.",
	}
	return nil
}

func (c *DKIMCheck) Start(domain string, nameservers *utils.Nameservers) error {
	splittedDomain := strings.Split(domain, ".")
	sld := splittedDomain[len(splittedDomain)-2]
	selectors := []string{
		sld,
		"default",
		"dkim",
		"dkim-shared",
		"dkimpal",
		"email",
		"gamma",
		"google",
		"mail",
		"mdaemon",
		"selector",
		"selector1",
		"selector2",
		"selector3",
		"selector4",
		"selector5",
	}

	var resArray []output.SingleCheckResult
	for _, fqdn := range nameservers.FQDNs {
		var res output.SingleCheckResult
		res.Nameserver = fqdn
		res.Zone = domain
		res.Vulnerable = true

		for _, selector := range selectors {
			r, _ := utils.MakeQuery(
				c.client,
				fmt.Sprintf("%v._domainkey.%v.", selector, domain),
				net.JoinHostPort(nameservers.GetIP(fqdn).String(), "53"),
				dns.TypeTXT,
			)

			if r != nil && r.Rcode == dns.RcodeSuccess {
				res.Vulnerable = false
				msg := fmt.Sprintf("selector = %v", selector)
				res.Information = append(res.Information, msg)
			}
		}
		if res.Vulnerable {
			msg := "no DKIM record found on nameserver"
			res.Information = append(res.Information, msg)
		}
		resArray = append(resArray, res)
	}

	c.output = &output.CheckOutput{
		Name:        "DKIM Record",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Description: c.description,
		Results:     resArray,
	}
	return nil
}

func (c *DKIMCheck) Results() *output.CheckOutput {
	return c.output
}
