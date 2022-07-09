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

func (c *GLUECheck) Start(domain string, nameservers *common.Nameservers) error {
	var isVuln bool
	var message string

	message += "\nLooking for glue records for nameservers. Glue records are meant to avoid\n"
	message += "cyclic queries between nameservers, you should 'Glue' records for NS in \n"
	message += "the additional section of the answer. The severity of this misconfiguration \n"
	message += "is arguably medium\n\n"

	for _, fqdn := range nameservers.FQDNs {
		r, err := common.MakeQuery(
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
		isVuln = true
		for _, a := range r.Extra {
			switch t := a.(type) {
			case *dns.A, *dns.AAAA:
				if strings.Contains(t.String(), string(nameservers.GetIP(fqdn))) {
					isVuln = false
				}
			}
		}

		if isVuln {
			message += common.Warn(fmt.Sprintf("GLUE record not set for nameserver %v in ADDITIONAL section\n", fqdn))
		} else {
			message += fmt.Sprintf("GLUE record set for nameserver %v in ADDITIONAL section\n", fqdn)
		}
	}

	c.output = &output.CheckOutput{
		Name:        "GLUE Record",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Vulnerable:  isVuln,
		Message:     message,
	}

	return nil
}

func (c *GLUECheck) Results() *output.CheckOutput {
	return c.output
}
