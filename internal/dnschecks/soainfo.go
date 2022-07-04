package dnschecks

import "github.com/5amu/dnshunter/internal/output"

type SOACheck struct{}

func (c *SOACheck) Start(domain string, nameservers []string) error {
	return nil
}

func (c *SOACheck) Results() *output.CheckOutput {
	return &output.CheckOutput{}
}
