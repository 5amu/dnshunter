package utils

import (
	"fmt"
	"net"
	"strings"

	"github.com/5amu/dnshunter/pkg/defaults"
	"github.com/likexian/whois"
)

type ASN struct {
	ID   string
	IP   net.IP
	Name string
}

func NewASN(nameserver net.IP) (*ASN, error) {
	r, err := whois.Whois(nameserver.String(), defaults.DefaultWhoisServer)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(r, "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("no result found")
	}

	fields := strings.Split(strings.TrimSpace(lines[1]), "|")
	if len(fields) != 3 {
		return nil, fmt.Errorf("not enough fields")
	}
	return &ASN{
		ID:   fields[0],
		IP:   net.ParseIP(strings.ReplaceAll(fields[1], " ", "")),
		Name: fields[2],
	}, nil
}
