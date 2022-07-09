package dnschecks

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

type SPFCheck struct {
	client    *dns.Client
	output    *output.CheckOutput
	currentNS string
}

func (c *SPFCheck) Init(client *dns.Client) error {
	c.client = client
	return nil
}

func (c *SPFCheck) Start(domain string, nameservers *common.Nameservers) error {
	var isVuln bool
	var message string

	message += "\nSPF is a TXT record that prevents mail spoofing by verifying servers\n"
	message += "that are allowed to send emails using the specified domain. To better\n"
	message += "understand the syntax, refer to this link: https://dmarcian.com/spf-syntax-table/\n\n"

	var spfRecords []string

	for _, fqdn := range nameservers.FQDNs {
		c.currentNS = nameservers.GetIP(fqdn).String()

		r, err := common.MakeQuery(
			c.client,
			dns.Fqdn(domain),
			net.JoinHostPort(nameservers.GetIP(fqdn).String(), "53"),
			dns.TypeTXT,
		)
		if err != nil {
			return err
		}

		for _, spf := range r.Answer {
			switch t := spf.(type) {
			case *dns.TXT:
				if strings.Contains(t.Txt[0], "spf") {
					ok := true
					for _, previous := range spfRecords {
						if t.Txt[0] == previous {
							ok = false
						}
					}
					if !ok {
						continue
					}
					spfRecords = append(spfRecords, t.Txt[0])
					message += c.recursiveSPFCheck(t.Txt[0], domain, "", "", 0, &isVuln)
				}
			}
		}
	}

	c.output = &output.CheckOutput{
		Name:        "Checking SPF Record",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Vulnerable:  isVuln,
		Message:     message,
	}
	return nil
}

func (c *SPFCheck) Results() *output.CheckOutput {
	return c.output
}

func (c *SPFCheck) recursiveSPFCheck(record string, domain string, message string, spacing string, depth int, isVuln *bool) string {
	stop := false

	if depth == 3 {
		return ""
	}

	if record == "" {
		message += common.SpfNotOK(fmt.Sprintf("%vNo SPF for %v\n", spacing, domain))
	} else if strings.Contains(record, "-all") {
		message += common.OK(fmt.Sprintf("%vSecure (-all) SPF for %v\n", spacing, domain))
		stop = true
	} else if strings.Contains(record, "~all") {
		*isVuln = true
		message += common.SpfNotOK(fmt.Sprintf("%vPartially secure (~all) SPF for %v\n", spacing, domain))
	} else if strings.Contains(record, "+all") {
		*isVuln = true
		message += common.SpfNotOK(fmt.Sprintf("%vInsecure (+all) SPF for %v\n", spacing, domain))
	} else if strings.Contains(record, "?all") {
		*isVuln = true
		message += common.SpfNotOK(fmt.Sprintf("%vInsecure (?all) SPF for %v\n", spacing, domain))
	}

	if !stop {
		r := regexp.MustCompile(`(redirect=|include:)[^ \"]*`)
		for _, d := range r.FindAllString(record, -1) {
			d := strings.Split(d, ":")[1]
			spf := c.getSPF(d)
			message += c.recursiveSPFCheck(spf, d, message, spacing+"    ", depth+1, isVuln)
		}
	}
	return message
}

func (c *SPFCheck) getSPF(domain string) string {

	r, err := common.MakeQuery(
		c.client,
		dns.Fqdn(domain),
		net.JoinHostPort(c.currentNS, "53"),
		dns.TypeTXT,
	)
	if err != nil {
		return ""
	}

	for _, spf := range r.Answer {
		switch t := spf.(type) {
		case *dns.TXT:
			if strings.Contains(t.Txt[0], "v=spf") {
				return t.Txt[0]
			}
		}
	}
	return ""
}
