package dnschecks

import (
	"fmt"
	"net"
	"strings"

	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

type DKIMCheck struct {
	client *dns.Client
	output *output.CheckOutput
}

func (c *DKIMCheck) Init(client *dns.Client) error {
	c.client = client
	return nil
}

func (c *DKIMCheck) Start(domain string, nameservers *common.Nameservers) error {
	var isVuln bool
	var message string

	message += "\nDKIM is a TXT record that guarantees that a particular email comes\n"
	message += "from the advertised organization.\n\n"

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

	for _, fqdn := range nameservers.FQDNs {
		found := true

		for _, selector := range selectors {
			r, _ := common.MakeQuery(
				c.client,
				fmt.Sprintf("%v._domainkey.%v.", selector, domain),
				net.JoinHostPort(nameservers.GetIP(fqdn).String(), "53"),
				dns.TypeTXT,
			)

			if r != nil && r.Rcode == dns.RcodeSuccess {
				found = false
				message += fmt.Sprintf("record DKIM (selector=%v) found on nameserver %v\n", selector, fqdn)
			}
		}
		if found {
			message += common.Warn(fmt.Sprintf("no DKIM record found on nameserver %v\n", fqdn))
		}
		isVuln = isVuln || found
	}

	c.output = &output.CheckOutput{
		Name:        "DKIM Record",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Vulnerable:  isVuln,
		Message:     message,
	}
	return nil
}

func (c *DKIMCheck) Results() *output.CheckOutput {
	return c.output
}
