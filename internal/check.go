package internal

import (
	"github.com/5amu/dnshunter/internal/dnschecks"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

type Check interface {
	Init(client *dns.Client) error
	Start(domain string, nameservers []string) error
	Results() *output.CheckOutput
}

var CheckList = []Check{
	new(dnschecks.SOACheck),
	new(dnschecks.GLUECheck),
}
