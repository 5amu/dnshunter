package dnschecks

import (
	"fmt"
	"net"

	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

type DNSSECCheck struct {
	client *dns.Client
	output *output.CheckOutput
}

func (c *DNSSECCheck) Init(client *dns.Client) error {
	c.client = client
	return nil
}

func (c *DNSSECCheck) Start(domain string, nameservers *common.Nameservers) error {
	var isVuln bool
	var message string

	message += "\nDNSSEC is a suite of extensions aimed to guarantee secure data\n"
	message += "exchange between the name server and the client. It guarantees data\n"
	message += "integrity and denial of exitence. Its mean is to avoid zone\n"
	message += "enumeration and prevent from manipulated answers and cache poisoning\n\n"

	for _, fqdn := range nameservers.FQDNs {
		r, err := common.MakeQuery(
			c.client,
			dns.Fqdn(domain),
			net.JoinHostPort(nameservers.GetIP(fqdn).String(), "53"),
			dns.TypeDNSKEY,
		)
		if err != nil {
			return err
		}

		if len(r.Answer) == 0 {
			isVuln = true
		}

		if isVuln {
			message += common.Warn(fmt.Sprintf("nameserver %v does not provide DNSSEC key\n", fqdn))
		} else {
			// TODO: implement key signature verification
			message += fmt.Sprintf("nameserver %v provides DNSSEC key!\n", fqdn)
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

func (c *DNSSECCheck) Results() *output.CheckOutput {
	return c.output
}
