package utils

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/5amu/dnshunter/pkg/defaults"
	"github.com/miekg/dns"
)

type Nameservers struct {
	IPs      []net.IP
	FQDNs    []string
	fqdnToIP map[string]net.IP
}

func NewNameserversFromFile(fname string) (*Nameservers, error) {
	if data, err := os.ReadFile(fname); err != nil {
		return nil, err
	} else {
		nsStrings := strings.Split(string(data), "\n")
		if len(nsStrings) == 0 {
			return nil, fmt.Errorf("no nameservers in file %v", fname)
		}

		n := &Nameservers{FQDNs: nsStrings}
		if err := n.prepare(); err != nil {
			return nil, err
		}
		return n, nil
	}
}

func NewNameserversFromDomain(domain string) (*Nameservers, error) {
	r, err := MakeQuery(new(dns.Client), dns.Fqdn(domain), net.JoinHostPort(defaults.DefaultNameserver, "53"), dns.TypeNS)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, r := range r.Answer {
		switch t := r.(type) {
		case *dns.NS:
			result = append(result, strings.Trim(t.Ns, "."))
		}
	}

	n := &Nameservers{FQDNs: result}
	if err := n.prepare(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *Nameservers) GetIP(fqdn string) net.IP {
	return n.fqdnToIP[fqdn]
}

func (n *Nameservers) prepare() (err error) {
	client := new(dns.Client)
	n.fqdnToIP = make(map[string]net.IP)
	for _, fqdn := range n.FQDNs {
		if n.fqdnToIP[fqdn], err = nsToIPv4(client, fqdn); err != nil {
			return err
		}
		n.IPs = append(n.IPs, n.fqdnToIP[fqdn])
	}
	return nil
}

func nsToIPv4(client *dns.Client, fqdn string) (net.IP, error) {
	r, err := MakeQuery(client, dns.Fqdn(fqdn), net.JoinHostPort(defaults.DefaultNameserver, "53"), dns.TypeA)
	if err != nil {
		return nil, err
	}

	for _, r := range r.Answer {
		switch t := r.(type) {
		case *dns.A:
			return t.A, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address found for %v", fqdn)
}
