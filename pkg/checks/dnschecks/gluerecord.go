package dnschecks

import (
	"net"
	"strings"

	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
)

type GLUECheck struct {
	description []string
	client      *dns.Client
	output      *output.CheckOutput
}

func (c *GLUECheck) Init(client *dns.Client) error {
	c.client = client
	c.description = []string{
		"Looking for glue records for nameservers. Glue records are meant to avoid",
		"cyclic queries between nameservers, you should 'Glue' records for NS in",
		"the additional section of the answer. The severity of this misconfiguration",
		"is arguably medium",
	}
	return nil
}

func (c *GLUECheck) Start(domain string, nameservers *utils.Nameservers) error {
	c.output = &output.CheckOutput{
		Name:        "GLUE Record",
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
			dns.Fqdn(domain),
			net.JoinHostPort(nameservers.GetIP(fqdn).String(), "53"),
			dns.TypeNS,
		)
		if err != nil {
			return err
		}

		// Check every record in the additional section, every nameserver should have its
		// own A or AAAA record inside of it
		res.Vulnerable = true
		for _, a := range r.Extra {
			switch t := a.(type) {
			case *dns.A, *dns.AAAA:
				if strings.Contains(t.String(), string(nameservers.GetIP(fqdn))) {
					res.Vulnerable = false
				}
			}
		}
		c.output.Results = append(c.output.Results, res)
	}
	return nil
}

func (c *GLUECheck) Results() *output.CheckOutput {
	return c.output
}
