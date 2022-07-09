package dnschecks

import (
	"fmt"
	"net"

	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

type ANYCheck struct {
	client *dns.Client
	output *output.CheckOutput
}

func (c *ANYCheck) Init(client *dns.Client) error {
	c.client = client
	return nil
}

func (c *ANYCheck) Start(domain string, nameservers *common.Nameservers) error {
	var isVuln bool
	var message string

	message += "\nAnswering to ANY queries might get the nameserver to suffer from\n"
	message += "DNS Amplification Attacks, basically ddos attacks based on the fact\n"
	message += "that the answer given by the DNS is much larger that the request\n"
	message += "made by the host. More information on the severity here:\n"
	message += "https://www.cisa.gov/uscert/ncas/alerts/TA13-088A\n\n"

	for _, fqdn := range nameservers.FQDNs {

		r, err := common.MakeQuery(
			c.client,
			dns.Fqdn(domain),
			net.JoinHostPort(nameservers.GetIP(fqdn).String(), "53"),
			dns.TypeANY,
		)
		if err != nil {
			return err
		}

		if len(r.Answer) > common.DNSAmplificationThreshold {
			isVuln = true
		}

		if isVuln {
			message += common.Warn(fmt.Sprintf("nameserver %v is vulnerable to DNS amplification\n", fqdn))
		} else {
			message += fmt.Sprintf("nameserver %v isn't vulnerable to DNS amplification\n", fqdn)
		}
	}

	c.output = &output.CheckOutput{
		Name:        "DNS amplification",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Vulnerable:  isVuln,
		Message:     message,
	}

	return nil
}

func (c *ANYCheck) Results() *output.CheckOutput {
	return c.output
}
