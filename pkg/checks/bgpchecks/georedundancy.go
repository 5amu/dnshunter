package bgpchecks

import (
	"fmt"
	"strings"

	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
)

type GEOCkeck struct {
	description []string
	client      *dns.Client
	output      *output.CheckOutput
}

func (c *GEOCkeck) Init(client *dns.Client) error {
	c.client = client
	c.description = []string{
		"For, ASNs, one important thing to check is georedundancy",
		"Always check the geographic zone in which an ASN is located.",
		"This is important to guarantee availability.",
	}
	return nil
}

func (c *GEOCkeck) Start(domain string, nameservers *utils.Nameservers) error {
	c.output = &output.CheckOutput{
		Name:        "BGP Georedundancy",
		Domain:      domain,
		Nameservers: nameservers.FQDNs,
		Description: c.description,
	}

	locations := map[string]int{}
	for _, fqdn := range nameservers.FQDNs {
		var res output.SingleCheckResult
		res.Nameserver = fqdn
		res.Zone = domain

		asn, err := utils.NewASN(nameservers.GetIP(fqdn))
		if err != nil {
			continue
		}

		nameSplitted := strings.Split(asn.Name, ",")
		if len(nameSplitted) > 1 {
			key := strings.ReplaceAll(nameSplitted[1], " ", "")
			locations[key] += 1
		}
		c.output.Results = append(c.output.Results, res)
	}

	var totalASN, totalGeo int
	var countries []string
	for k, v := range locations {
		totalASN += v
		totalGeo += 1
		countries = append(countries, k)
	}

	if totalASN < 2 {
		for i := range c.output.Results {
			c.output.Results[i].Vulnerable = true
			c.output.Results[i].Information = append(c.output.Results[i].Information, "bad georedundancy: 1 location")
		}
	}

	if totalASN/2 > totalGeo {
		for i := range c.output.Results {
			c.output.Results[i].Vulnerable = true
			msg := "ideally, you should have every 1 or 2 ASNs in different countries"
			c.output.Results[i].Information = append(c.output.Results[i].Information, msg)
		}
	}

	for i := range c.output.Results {
		msg := fmt.Sprintf("%d distrubuted over %d locations", totalASN, totalGeo)
		c.output.Results[i].Information = append(c.output.Results[i].Information, msg)
		msg = fmt.Sprintf("countries: %v", countries)
		c.output.Results[i].Information = append(c.output.Results[i].Information, msg)
	}
	return nil
}

func (c *GEOCkeck) Results() *output.CheckOutput {
	return c.output
}
