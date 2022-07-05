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

	initialInfo := common.Info(fmt.Sprintf("scanning domain   : %v\n", domain))
	initialInfo += common.Info(fmt.Sprintf("using nameservers : %v\n", nameservers))

	nameservers, err = nameserversToIPv4(nameservers)
	if err != nil {
		return err
	}

	initialInfo += common.Info(fmt.Sprintf("with IPv4 version : %v\n", nameservers))
	if outfile != "" {
		initialInfo += common.Info(fmt.Sprintf("saving output to  : %v\n", outfile))
	} else {
		initialInfo += common.Info("saving output to  : /dev/null\n")
	}
	fmt.Println(initialInfo)

	var results []*output.CheckOutput
	for _, check := range internal.CheckList {
		check.Init(c)

		if err := check.Start(domain, nameservers); err != nil {
			return err
		}

		r := check.Results()
		fmt.Println(r.String())
		results = append(results, r)
	}

	if outfile != "" {
		if data, err := json.Marshal(results); err != nil {
			return err
		} else {
			if err := os.WriteFile(outfile, data, 0644); err != nil {
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
		switch t := r.(type) {
		case *dns.NS:
			// google.com.	14332	IN	NS	ns3.google.com.
			splitted := strings.Split(t.String(), "\t")
			last := splitted[len(splitted)-1]
			result = append(result, last)
		}
	}

	return result, nil
}

func nameserversToIPv4(fqdns []string) (result []string, err error) {
	for _, fqdn := range fqdns {

		c := new(dns.Client)
		m := new(dns.Msg)
		m.SetQuestion(fqdn, dns.TypeA)

		r, _, err := c.Exchange(m, net.JoinHostPort(common.DefaultNameserver, "53"))
		if err != nil {
			return nil, err
		}

		if r.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("invalid answer from %v after A query for %v", common.DefaultNameserver, fqdn)
		}

		for _, r := range r.Answer {
			switch t := r.(type) {
			case *dns.A:
				// google.com.	14332	IN	NS	ns3.google.com.
				splitted := strings.Split(t.String(), "\t")
				last := splitted[len(splitted)-1]
				result = append(result, last)
			}
		}
	}
	return
}
