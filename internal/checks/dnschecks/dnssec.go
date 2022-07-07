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

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.RecursionDesired = true

	var isVuln bool
	var message string

	message += "\nDNSSEC is a suite of extensions aimed to guarantee secure data\n"
	message += "exchange between the name server and the client. It guarantees data\n"
	message += "integrity and denial of exitence. Its mean is to avoid zone\n"
	message += "enumeration and prevent from manipulated answers and cache poisoning\n\n"

	for _, ns := range nameservers.IPs {

		fqdn, err := nameservers.IPv4ToFQDN(ns.String())
		if err != nil {
			return err
		}

		r, _, err := c.client.Exchange(m, net.JoinHostPort(ns.String(), "53"))
		if err != nil {
			return err
		}

		if r.Rcode != dns.RcodeSuccess {
			return fmt.Errorf("invalid answer from %v after KEY query for %v", fqdn, domain)
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
		Nameservers: nameservers.ToFQDNs(),
		Vulnerable:  isVuln,
		Message:     message,
	}

	return nil
}

func (c *DNSSECCheck) Results() *output.CheckOutput {
	return c.output
}
