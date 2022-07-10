package utils

import (
	"fmt"

	"github.com/miekg/dns"
)

func MakeQuery(c *dns.Client, query, nameserver string, qType uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.RecursionDesired = true
	m.SetQuestion(query, qType)

	r, _, err := c.Exchange(m, nameserver)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("invalid answer from %v after query for %v", nameserver, query)
	}
	return r, nil
}
