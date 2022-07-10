package dnschecks

import (
	"fmt"
	"net"

	"github.com/5amu/dnshunter/pkg/defaults"
	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
)

type ANYCheck struct {
	description []string
	poc         string
	client      *dns.Client
	output      *output.CheckOutput
}

func (c *ANYCheck) Init(client *dns.Client) error {
	c.client = client
	c.description = []string{
		"Answering to ANY queries might get the nameserver to suffer from",
		"DNS Amplification Attacks, basically ddos attacks based on the fact",
		"that the answer given by the DNS is much larger that the request",
		"made by the host. More information on the severity here:",
		"https://www.cisa.gov/uscert/ncas/alerts/TA13-088A",
	}
	c.poc = "PoC: dig -t ANY +noall +answer %v @%v"
	return nil
}

func (c *ANYCheck) Start(domain string, nameservers *utils.Nameservers) error {
	var resArray []output.SingleCheckResult
	for _, fqdn := range nameservers.FQDNs {
		var res output.SingleCheckResult
		res.Nameserver = fqdn
		res.Zone = domain

		r, err := utils.MakeQuery(
			c.client,
			dns.Fqdn(domain),
			net.JoinHostPort(nameservers.GetIP(fqdn).String(), "53"),
			dns.TypeANY,
		)
		if err != nil {
			return err
		}

		if len(r.Answer) > defaults.DNSAmplificationThreshold {
			res.Vulnerable = true
		}

		poc := fmt.Sprintf(c.poc, domain, fqdn)
		res.Information = append(res.Information, poc)

		resArray = append(resArray, res)
	}

	c.output = &output.CheckOutput{
		Name:        "DNS Amplification",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Description: c.description,
		Results:     resArray,
	}
	return nil
}

func (c *ANYCheck) Results() *output.CheckOutput {
	return c.output
}
