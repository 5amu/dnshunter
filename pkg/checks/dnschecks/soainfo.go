package dnschecks

import (
	"fmt"
	"net"
	"time"

	"github.com/5amu/dnshunter/pkg/defaults"
	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
)

type SOACheck struct {
	description []string
	client      *dns.Client
	output      *output.CheckOutput
}

func (c *SOACheck) Init(client *dns.Client) error {
	c.client = client
	c.description = []string{
		"SOA record should follow RIPE-203 standard",
		"more info at https://www.ripe.net/publications/docs/ripe-203",
	}
	return nil
}

func (c *SOACheck) Start(domain string, nameservers *utils.Nameservers) error {
	var res output.SingleCheckResult
	res.Nameserver = defaults.DefaultNameserver
	res.Zone = domain
	c.output = &output.CheckOutput{
		Name:        "SOA Record",
		Domain:      domain,
		Nameservers: []string{defaults.DefaultNameserver},
		Description: c.description,
	}

	r, err := utils.MakeQuery(
		c.client,
		dns.Fqdn(domain),
		net.JoinHostPort(defaults.DefaultNameserver, "53"),
		dns.TypeSOA,
	)
	if err != nil {
		return err
	}

	for _, soa := range r.Answer {
		switch t := soa.(type) {
		case *dns.SOA:
			res.Information = append(res.Information, fmt.Sprintf("Zone name: %v", t.Ns))
			res.Information = append(res.Information, fmt.Sprintf("Start of Authority: %v", t.Mbox))
			res.Information = append(res.Information, parseSerial(fmt.Sprint(t.Serial), &res.Vulnerable))
			res.Information = append(res.Information, parseRefresh(fmt.Sprint(t.Refresh), &res.Vulnerable))
			res.Information = append(res.Information, parseRetry(fmt.Sprint(t.Retry), &res.Vulnerable))
			res.Information = append(res.Information, parseExpire(fmt.Sprint(t.Expire), &res.Vulnerable))
			res.Information = append(res.Information, fmt.Sprintf("TTL: %v", t.Hdr.Ttl))
		}
	}
	c.output.Results = append(c.output.Results, res)
	return nil
}

func (c *SOACheck) Results() *output.CheckOutput {
	return c.output
}

func parseSerial(serial string, isVuln *bool) string {
	if len(serial) < 8 {
		return fmt.Sprintf("Serial number: %v - should follow standards (RIPE-203)\n", serial)
	}
	serialDate, _ := time.Parse("%Y%m%d", string(serial)[:7])
	dummyLower, _ := time.Parse("%s", "0")
	dummyUpper, _ := time.Parse("%s", fmt.Sprintf("%v", time.Now().Unix()))
	if serialDate.After(dummyUpper) || serialDate.Before(dummyLower) {
		*isVuln = true
		return fmt.Sprintf("Serial number: %v - should follow standards (RIPE-203)", serial)
	} else {
		return fmt.Sprintf("Serial number: %v", serial)
	}
}

func parseRefresh(refresh string, isVuln *bool) string {
	r, _ := time.ParseDuration(fmt.Sprintf("%vs", refresh))
	if r < (24 * time.Hour) {
		*isVuln = true
		return fmt.Sprintf("Refresh: %v - should follow standards (RIPE-203)", refresh)
	} else {
		return fmt.Sprintf("Refresh: %v", refresh)
	}
}

func parseRetry(retry string, isVuln *bool) string {
	r, _ := time.ParseDuration(fmt.Sprintf("%vs", retry))
	if r < (2 * time.Hour) {
		*isVuln = true
		return fmt.Sprintf("Retry: %v - should follow standards (RIPE-203)", retry)
	} else {
		return fmt.Sprintf("Retry: %v", retry)
	}
}

func parseExpire(expire string, isVuln *bool) string {
	e, _ := time.ParseDuration(fmt.Sprintf("%vs", expire))

	if e < (1000 * time.Hour) {
		*isVuln = true
		return fmt.Sprintf("Expire: %v - should follow standards (RIPE-203)", expire)
	} else {
		return fmt.Sprintf("Expire: %v", expire)
	}
}
