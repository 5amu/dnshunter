package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

func MakeQuery(c *dns.Client, query, nameserver string, qType uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.RecursionDesired = true
	m.SetQuestion(query, qType)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	r, _, err := c.ExchangeContext(ctx, m, nameserver)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("invalid answer from %v after query for %v", nameserver, query)
	}
	return r, nil
}
