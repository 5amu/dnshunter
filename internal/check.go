package internal

import (
	"github.com/5amu/dnshunter/internal/dnschecks"
	"github.com/5amu/dnshunter/internal/output"
)

type Check interface {
	Start(domain string, nameservers []string) error
	Results() *output.CheckOutput
}

var CheckList = []Check{
	new(dnschecks.SOACheck),
}
