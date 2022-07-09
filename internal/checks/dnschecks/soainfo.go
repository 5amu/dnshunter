package dnschecks

import (
	"fmt"
	"net"
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

func (c *SOACheck) Start(domain string, nameservers *common.Nameservers) error {

	r, err := common.MakeQuery(
		c.client,
		dns.Fqdn(domain),
		net.JoinHostPort(common.DefaultNameserver, "53"),
		dns.TypeSOA,
	)
	if err != nil {
		return err
	}

	var isVuln bool
	var parsed string

	for _, soa := range r.Answer {
		isVuln, parsed = parseSOA(soa.(*dns.SOA))
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

func parseSOA(soa *dns.SOA) (isVuln bool, message string) {
	message += "\nChecking if SOA record follows RIPE-203 standard\n"
	message += "more info at https://www.ripe.net/publications/docs/ripe-203\n\n"
	message += fmt.Sprintf("Zone name: %v\n", soa.Ns)
	message += fmt.Sprintf("Start of Authority: %v\n", soa.Mbox)
	message += parseSerial(fmt.Sprint(soa.Serial), &isVuln)
	message += parseRefresh(fmt.Sprint(soa.Refresh), &isVuln)
	message += parseRetry(fmt.Sprint(soa.Retry), &isVuln)
	message += parseExpire(fmt.Sprint(soa.Expire), &isVuln)
	message += fmt.Sprintf("TTL: %v\n", soa.Hdr.Ttl)
	return
}

func parseSerial(serial string, isVuln *bool) string {
	serialDate, _ := time.Parse("%Y%m%d", string(serial)[:4])
	dummyLower, _ := time.Parse("%s", "0")
	dummyUpper, _ := time.Parse("%s", fmt.Sprintf("%v", time.Now().Unix()))
	if serialDate.After(dummyUpper) || serialDate.Before(dummyLower) {
		*isVuln = true
		return common.Warn(fmt.Sprintf("Serial number: %v - should follow standards (RIPE-203)\n", serial))
	} else {
		return fmt.Sprintf("Serial number: %v\n", serial)
	}
}

func parseRefresh(refresh string, isVuln *bool) string {
	r, _ := time.ParseDuration(fmt.Sprintf("%vs", refresh))
	if r < (24 * time.Hour) {
		*isVuln = true
		return common.Warn(fmt.Sprintf("Refresh: %v - should follow standards (RIPE-203)\n", refresh))
	} else {
		return fmt.Sprintf("Refresh: %v\n", refresh)
	}
}

func parseRetry(retry string, isVuln *bool) string {
	r, _ := time.ParseDuration(fmt.Sprintf("%vs", retry))
	if r < (2 * time.Hour) {
		*isVuln = true
		return common.Warn(fmt.Sprintf("Retry: %v - should follow standards (RIPE-203)\n", retry))
	} else {
		return fmt.Sprintf("Retry: %v\n", retry)
	}
}

func parseExpire(expire string, isVuln *bool) string {
	e, _ := time.ParseDuration(fmt.Sprintf("%vs", expire))

	if e < (1000 * time.Hour) {
		*isVuln = true
		return common.Warn(fmt.Sprintf("Expire: %v - should follow standards (RIPE-203)\n", expire))
	} else {
		return fmt.Sprintf("Expire: %v\n", expire)
	}
}
