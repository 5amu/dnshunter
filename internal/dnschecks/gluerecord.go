package dnschecks

import (
	"fmt"
	"net"
	"strings"

	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

type GLUECheck struct {
	client *dns.Client
	output *output.CheckOutput
}

func (c *GLUECheck) Init(client *dns.Client) error {
	c.client = client
	return nil
}

func (c *GLUECheck) Start(domain string, nameservers []string) error {

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.RecursionDesired = true

	var isVuln bool
	var message string

	message += "\nLooking for glue records for nameservers. Glue records are meant to avoid\n"
	message += "cyclic queries between nameservers, you should 'Glue' records for NS in \n"
	message += "the additional section of the answer. The severity of this misconfiguration \n"
	message += "is arguably medium\n\n"

	for _, ns := range nameservers {
		r, _, err := c.client.Exchange(m, net.JoinHostPort(ns, "53"))
		if err != nil {
			return err
		}

		if r.Rcode != dns.RcodeSuccess {
			return fmt.Errorf("invalid answer from %v after A query for %v", ns, domain)
		}

		// Check every record in the additional section, every nameserver should have its
		// own A or AAAA record inside of it
		isVuln = true
		for _, a := range r.Extra {
			switch t := a.(type) {
			case *dns.A, *dns.AAAA:
				if strings.Contains(t.String(), ns) {
					isVuln = false
				}
			}
		}

		if isVuln {
			message += common.Warn(fmt.Sprintf("GLUE record not set for nameserver %v in ADDITIONAL section\n", ns))
		} else {
			message += fmt.Sprintf("GLUE record set for nameserver %v in ADDITIONAL section\n", ns)
		}
	}

	c.output = &output.CheckOutput{
		Name:        "GLUE Record",
		Domain:      domain,
		Nameservers: nameservers,
		Vulnerable:  isVuln,
		Message:     message,
	}

	return nil
}

func (c *GLUECheck) Results() *output.CheckOutput {
	return c.output
}
