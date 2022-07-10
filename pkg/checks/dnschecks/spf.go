package dnschecks

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
)

type SPFCheck struct {
	description []string
	client      *dns.Client
	output      *output.CheckOutput
	currentNS   string
}

func (c *SPFCheck) Init(client *dns.Client) error {
	c.client = client
	c.description = []string{
		"SPF is a TXT record that prevents mail spoofing by verifying servers",
		"that are allowed to send emails using the specified domain. To better",
		"understand the syntax, refer to this link: https://dmarcian.com/spf-syntax-table/",
	}
	return nil
}

func (c *SPFCheck) Start(domain string, nameservers *utils.Nameservers) error {
	var spfRecords []string
	c.output = &output.CheckOutput{
		Name:        "SPF Record",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Description: c.description,
	}

	for _, fqdn := range nameservers.FQDNs {
		var res output.SingleCheckResult
		res.Nameserver = fqdn
		res.Zone = domain

		c.currentNS = nameservers.GetIP(fqdn).String()
		if spf := c.getSPF(domain); spf != "" {
			var present bool
			for _, v := range spfRecords {
				if v == spf {
					present = true
					break
				}
			}

			if !present {
				spfRecords = append(spfRecords, spf)
				res.Information = c.recursiveSPFCheck(spf, domain, []string{}, "", 0, &res.Vulnerable)
			}
		}
		c.output.Results = append(c.output.Results, res)
	}
	return nil
}

func (c *SPFCheck) Results() *output.CheckOutput {
	return c.output
}

func (c *SPFCheck) recursiveSPFCheck(record string, domain string, message []string, spacing string, depth int, isVuln *bool) []string {
	stop := false

	if depth == 3 {
		return nil
	}

	if record == "" {
		message = append(message, fmt.Sprintf("%vNo SPF for %v", spacing, domain))
	} else if strings.Contains(record, "-all") {
		message = append(message, fmt.Sprintf("%vSecure (-all) SPF for %v", spacing, domain))
		stop = true
	} else if strings.Contains(record, "~all") {
		*isVuln = true
		message = append(message, fmt.Sprintf("%vPartially secure (~all) SPF for %v", spacing, domain))
	} else if strings.Contains(record, "+all") {
		*isVuln = true
		message = append(message, fmt.Sprintf("%vInsecure (+all) SPF for %v", spacing, domain))
	} else if strings.Contains(record, "?all") {
		*isVuln = true
		message = append(message, fmt.Sprintf("%vInsecure (?all) SPF for %v", spacing, domain))
	}

	if !stop {
		r := regexp.MustCompile(`(redirect=|include:)[^ \"]*`)
		for _, d := range r.FindAllString(record, -1) {
			d := strings.Split(d, ":")[1]
			spf := c.getSPF(d)
			message = append(message, c.recursiveSPFCheck(spf, d, message, spacing+"    ", depth+1, isVuln)...)
		}
	}
	return message
}

func (c *SPFCheck) getSPF(domain string) string {

	r, err := utils.MakeQuery(
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
