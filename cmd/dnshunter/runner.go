package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/5amu/dnshunter/internal"
	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

func run(outfile string, nsfile string, domain string) error {
	c := new(dns.Client)

	nameservers, err := getNameservers(domain, nsfile)
	if err != nil {
		return err
	}
	common.Info(fmt.Sprintf("Using nameservers: %v\n", nameservers))

	var results []*output.CheckOutput
	for _, check := range internal.CheckList {
		check.Init(c)
		check.Start(domain, nameservers)

		r := check.Results()
		results = append(results, r)
		fmt.Println(r)
	}

	if outfile != "" {
		if data, err := json.Marshal(results); err != nil {
			return err
		} else {
			if err := os.WriteFile(outfile, data, os.ModeAppend); err != nil {
				return err
			}
		}
	}

	return nil
}

func getNameservers(domain string, nsfile string) ([]string, error) {
	if data, err := os.ReadFile(nsfile); err != nil || nsfile != "" {
		return nameserversFromDNS(domain)
	} else {
		return strings.Split(string(data), "\n"), nil
	}
}

func nameserversFromDNS(domain string) (result []string, err error) {
	c := new(dns.Client)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, net.JoinHostPort(common.DefaultNameserver, "53"))
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("invalid answer from %v after NS query for %v", common.DefaultNameserver, domain)
	}

	for _, r := range r.Answer {
		// google.com.	14332	IN	NS	ns3.google.com.
		splitted := strings.Split(r.String(), "\t")
		last := splitted[len(splitted)-1]

		result = append(result, last)
	}

	return result, nil
}
