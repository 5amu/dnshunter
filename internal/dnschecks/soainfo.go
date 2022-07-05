package dnschecks

import (
	"fmt"
	"net"

	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

type SOACheck struct {
	client *dns.Client
	output *output.CheckOutput
}

func (c *SOACheck) Init(client *dns.Client) error {
	c.client = client
	return nil
}

func (c *SOACheck) Start(domain string, nameservers []string) error {

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.RecursionDesired = false

	r, _, err := c.client.Exchange(m, net.JoinHostPort(common.DefaultNameserver, "53"))
	if err != nil {
		return err
	}

	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("invalid answer from %v after SOA query for %v", common.DefaultNameserver, domain)
	}

	var isVuln bool
	var parsed string

	for _, soa := range r.Answer {
		isVuln, parsed = parseSOA(soa.String())
	}

	c.output = &output.CheckOutput{
		Name:        "SOA Record",
		Domain:      domain,
		Nameservers: []string{common.DefaultNameserver},
		Vulnerable:  isVuln,
		Message:     parsed,
	}

	return nil
}

func (c *SOACheck) Results() *output.CheckOutput {
	return c.output
}

func parseSOA(soa string) (bool, string) {
	fmt.Println("Parsing soa:", soa)
	return false, ""
}
