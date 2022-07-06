package dnschecks

import (
	"fmt"
	"net"

	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

type AXFRCheck struct {
	client *dns.Client
	output *output.CheckOutput
}

func (c *AXFRCheck) Init(client *dns.Client) error {
	c.client = client
	return nil
}

func (c *AXFRCheck) Start(domain string, nameservers *common.Nameservers) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAXFR)

	var isVuln bool
	var message string

	message += "\nThe nameserver allows zone transfers from unauthorized sources, this\n"
	message += "leads to the disclosure of all the zone's domains handled by the dns\n"
	message += "(at best). In the worse case scenario, the attacker might be able to\n"
	message += "get ownership on the zone handled by the dns.\n\n"

	for _, ns := range nameservers.IPs {
		vulnerable := false
		fqdn, err := nameservers.IPv4ToFQDN(ns.String())
		if err != nil {
			message += fmt.Sprintf("nameserver %v don't accept unauthenticated zone transfers\n", fqdn)
			continue
		}

		conn, err := net.Dial("tcp", net.JoinHostPort(ns.String(), "53"))
		if err != nil {
			message += fmt.Sprintf("nameserver %v don't accept unauthenticated zone transfers\n", fqdn)
			continue
		}
		transfer := &dns.Transfer{Conn: &dns.Conn{Conn: conn}}
		channel, err := transfer.In(m, ns.String())
		if err != nil {
			message += fmt.Sprintf("nameserver %v don't accept unauthenticated zone transfers\n", fqdn)
			continue
		}

		var vuln []dns.RR
		for r := range channel {
			if r.Error != nil || len(r.RR) == 0 {
				message += fmt.Sprintf("nameserver %v don't accept unauthenticated zone transfers\n", fqdn)
				continue
			}
			vulnerable = true
			vuln = append(vuln, r.RR...)
		}

		if vulnerable {
			message += common.Warn(fmt.Sprintf("nameserver %v accepts unauthenticated zone transfers\n", fqdn))
			for _, v := range vuln {
				message += common.Warn(fmt.Sprintln(v.String()))
			}
		}
		isVuln = vulnerable || isVuln
	}

	c.output = &output.CheckOutput{
		Name:        "Unprotected Zone Transfer",
		Domain:      domain,
		Nameservers: nameservers.ToFQDNs(),
		Vulnerable:  isVuln,
		Message:     message,
	}

	return nil
}

func (c *AXFRCheck) Results() *output.CheckOutput {
	return c.output
}
