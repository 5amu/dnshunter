package main

import (
	"fmt"

	"github.com/5amu/dnshunter/internal"
	"github.com/miekg/dns"
)

func run(outfile string, nsfile string, domain string) error {

	c := new(dns.Client)
	for _, check := range internal.CheckList {
		check.Init(c)
		check.Start("google.com", []string{})
		fmt.Println(check.Results())
	}

	return nil
}
