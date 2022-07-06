package common

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
)

type Nameservers struct {
	IPs   []net.IP
	FQDNs []string
}

func NewNameserversFromFile(fname string) (*Nameservers, error) {
	if data, err := os.ReadFile(fname); err != nil {
		return nil, err
	} else {
		nsStrings := strings.Split(string(data), "\n")
		if len(nsStrings) == 0 {
			return nil, fmt.Errorf("no nameservers in file %v", fname)
		}

		nsIps, err := nameserversToIPv4(nsStrings)
		if err != nil {
			return nil, err
		}

		return &Nameservers{
			IPs:   nsIps,
			FQDNs: nsStrings,
		}, nil
	}
}

func NewNameserversFromDomain(domain string) (*Nameservers, error) {
	c := new(dns.Client)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, net.JoinHostPort(DefaultNameserver, "53"))
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("invalid answer from %v after NS query for %v", DefaultNameserver, domain)
	}

	var result []string
	for _, r := range r.Answer {
		switch t := r.(type) {
		case *dns.NS:
			// google.com.	14332	IN	NS	ns3.google.com.
			splitted := strings.Split(t.String(), "\t")
			last := splitted[len(splitted)-1]
			result = append(result, last)
		}
	}

	ips, err := nameserversToIPv4(result)
	if err != nil {
		return nil, err
	}

	return &Nameservers{
		FQDNs: result,
		IPs:   ips,
	}, nil
}

func (n *Nameservers) ToIPv4() (res []string) {
	for _, i := range n.IPs {
		res = append(res, i.String())
	}
	return res
}

func (n *Nameservers) ToFQDNs() []string {
	return n.FQDNs
}

func (n *Nameservers) IPv4ToFQDN(ip string) (string, error) {
	for i, t := range n.IPs {
		if t.String() == ip {
			return n.FQDNs[i], nil
		}
	}
	return "", fmt.Errorf("no fqdn for given IP %v", ip)
}

func nameserversToIPv4(fqdns []string) (result []net.IP, err error) {
	for _, fqdn := range fqdns {

		c := new(dns.Client)
		m := new(dns.Msg)
		m.SetQuestion(fqdn, dns.TypeA)

		r, _, err := c.Exchange(m, net.JoinHostPort(DefaultNameserver, "53"))
		if err != nil {
			return nil, err
		}

		if r.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("invalid answer from %v after A query for %v", DefaultNameserver, fqdn)
		}

		for _, r := range r.Answer {
			switch t := r.(type) {
			case *dns.A:
				// google.com.	14332	IN	NS	ns3.google.com.
				splitted := strings.Split(t.String(), "\t")
				last := splitted[len(splitted)-1]
				result = append(result, net.ParseIP(last))
			}
		}
	}
	return
}
