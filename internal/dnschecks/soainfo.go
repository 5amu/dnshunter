package dnschecks

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

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
	m.RecursionDesired = true

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

const (
	SOAName = iota + 1
	SOARecord
	SOASerial
	SOARefresh
	SOARetry
	SOAExpire
	SOATTL
)

func (c *SOACheck) Results() *output.CheckOutput {
	return c.output
}

func parseSOA(soa string) (isVuln bool, message string) {
	message += "\n"

	splitted := strings.Split(soa, "SOA")
	if len(splitted) < 2 {
		message += "Invalid answer"
		return true, message
	}

	// get answer section and remove whitespaces
	s := regexp.MustCompile(`\s+`)
	record := string(s.ReplaceAll([]byte(splitted[1]), []byte(" ")))

	message += "Checking if SOA record follows RIPE-203 standard\n"
	message += "more info at https://www.ripe.net/publications/docs/ripe-203\n\n"

	for i, part := range strings.Split(record, " ") {
		switch i {
		case SOAName:
			message += fmt.Sprintf("Zone name: %v\n", part)
		case SOARecord:
			message += fmt.Sprintf("Start of Authority: %v\n", part)
		case SOASerial:
			serialDate, _ := time.Parse("%Y%m%d", part[:len(part)-2])
			dummyLower, _ := time.Parse("%s", "0")
			dummyUpper, _ := time.Parse("%s", fmt.Sprintf("%v", time.Now().Unix()))

			if serialDate.After(dummyUpper) || serialDate.Before(dummyLower) {
				message += fmt.Sprintf("[WARNING] Serial number: %v - should follow standards (RIPE-203)\n", part)
			} else {
				message += fmt.Sprintf("Serial number: %v\n", part)
			}
		case SOARefresh:
			refresh, _ := time.ParseDuration(fmt.Sprintf("%vs", part))

			if refresh < (24 * time.Hour) {
				message += fmt.Sprintf("[WARNING] Refresh: %v - should follow standards (RIPE-203)\n", part)
			} else {
				message += fmt.Sprintf("Refresh: %v\n", part)
			}
		case SOARetry:
			retry, _ := time.ParseDuration(fmt.Sprintf("%vs", part))

			if retry < (2 * time.Hour) {
				message += fmt.Sprintf("[WARNING] Retry: %v - should follow standards (RIPE-203)\n", part)
			} else {
				message += fmt.Sprintf("Retry: %v\n", part)
			}
		case SOAExpire:
			expire, _ := time.ParseDuration(fmt.Sprintf("%vs", part))

			if expire < (1000 * time.Hour) {
				message += fmt.Sprintf("[WARNING] Expire: %v - should follow standards (RIPE-203)\n", part)
			} else {
				message += fmt.Sprintf("Expire: %v\n", part)
			}
		case SOATTL:
			message += fmt.Sprintf("TTL: %v\n", part)
		}
	}
	message += "\n"
	return
}
