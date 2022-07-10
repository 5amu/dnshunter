package output

import (
	"fmt"

	"github.com/projectdiscovery/gologger"
)

type CheckOutput struct {
	Name        string              `json:"name"`
	Domain      string              `json:"domain"`
	Nameservers []string            `json:"nameservers"`
	Description []string            `json:"description"`
	Results     []SingleCheckResult `json:"results"`
}

type SingleCheckResult struct {
	Nameserver  string   `json:"nameserver"`
	Zone        string   `json:"zone"`
	Vulnerable  bool     `json:"is_vulnerable"`
	Information []string `json:"info"`
}

func (o *CheckOutput) PrintSilent() {
	for _, res := range o.Results {
		if res.Vulnerable {
			gologger.Error().Label("FAILED").Msgf("%v is positive to check: %v\n", o.Domain, o.Name)
			return
		}
	}
	gologger.Debug().Label("PASSED").Msgf("%v is negative to check: %v\n", o.Domain, o.Name)
}

func (o *CheckOutput) PrintVerbose() {
	gologger.Info().Label(o.Name).Msgf("Name: %v", o.Name)
	gologger.Info().Label(o.Name).Msgf("Domain: %v", o.Domain)
	gologger.Info().Label(o.Name).Msgf("")
	gologger.Info().Label(o.Name).Msgf("Description:\n")
	for _, d := range o.Description {
		gologger.Info().Label(o.Name).Msgf("%v", d)
	}
	gologger.Info().Label(o.Name).Msgf("")
	for _, r := range o.Results {
		if r.Vulnerable {
			gologger.Warning().Label(o.Name).Msgf("%v failed this check on %v", r.Nameserver, o.Domain)
			for _, i := range r.Information {
				gologger.Warning().Label(o.Name).Msgf("%v\n", i)
			}
		} else {
			gologger.Debug().Label(o.Name).Msgf("%v passed this check on %v", r.Nameserver, o.Domain)
		}
	}

	fmt.Println("")
}
