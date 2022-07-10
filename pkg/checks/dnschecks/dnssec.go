package dnschecks

import (
	"fmt"
	"net"

	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
)

type DNSSECCheck struct {
	description []string
	poc         string
	client      *dns.Client
	output      *output.CheckOutput
}

func (c *DNSSECCheck) Init(client *dns.Client) error {
	c.client = client
	c.description = []string{
		"DNSSEC is a suite of extensions aimed to guarantee secure data",
		"exchange between the name server and the client. It guarantees data",
		"integrity and denial of exitence. Its mean is to avoid zone",
		"enumeration and prevent from manipulated answers and cache poisoning",
	}
	c.poc = "dig -t DNSKEY +noall +answer %v @%v"
	return nil
}

func (c *DNSSECCheck) Start(domain string, nameservers *utils.Nameservers) error {
	var resArray []output.SingleCheckResult
	for _, fqdn := range nameservers.FQDNs {
		var res output.SingleCheckResult
		res.Nameserver = fqdn
		res.Zone = domain

		r, err := utils.MakeQuery(
			c.client,
			dns.Fqdn(domain),
			net.JoinHostPort(nameservers.GetIP(fqdn).String(), "53"),
			dns.TypeDNSKEY,
		)
		if err != nil {
			return err
		}

		if len(r.Answer) == 0 {
			res.Vulnerable = true
			msg := fmt.Sprintf(c.poc, domain, fqdn)
			res.Information = append(res.Information, msg)
		}
		resArray = append(resArray, res)
	}

	c.output = &output.CheckOutput{
		Name:        "DNSSEC implementation",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Description: c.description,
		Results:     resArray,
	}
	return nil
}

func (c *DNSSECCheck) Results() *output.CheckOutput {
	return c.output
}
