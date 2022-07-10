package checks

import (
	"github.com/5amu/dnshunter/pkg/checks/dnschecks"
	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
)

type Check interface {
	Init(client *dns.Client) error
	Start(domain string, ns *utils.Nameservers) error
	Results() *output.CheckOutput
}

const (
	SOA     = "soa"
	ANY     = "any"
	GLUE    = "glue"
	ZONE    = "zone"
	DNSSSEC = "dnssec"
	SPF     = "spf"
	DMARC   = "dmarc"
	DKIM    = "dkim"
	GEO     = "geo"
	IRR     = "irr"
	ROA     = "roa"
)

func NewCheck(id string) Check {
	switch id {
	case SOA:
		return new(dnschecks.SOACheck)
	case ANY:
		return new(dnschecks.ANYCheck)
	case GLUE:
		return new(dnschecks.GLUECheck)
	case ZONE:
		return new(dnschecks.AXFRCheck)
	case DNSSSEC:
		return new(dnschecks.DNSSECCheck)
	case SPF:
		return new(dnschecks.SPFCheck)
	case DMARC:
		return nil
	case DKIM:
		return new(dnschecks.DKIMCheck)
	case GEO:
		return nil
	case IRR:
		return nil
	case ROA:
		return nil
	default:
		return nil
	}
}

func AllChecks() []Check {
	return []Check{
		new(dnschecks.SOACheck),
		new(dnschecks.ANYCheck),
		new(dnschecks.GLUECheck),
		new(dnschecks.AXFRCheck),
		new(dnschecks.DNSSECCheck),
		new(dnschecks.SPFCheck),
		new(dnschecks.DKIMCheck),
	}
}
