package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/5amu/dnshunter/pkg/checks"
	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func (a *Args) Run() error {
	gologger.Print().Msgf("\033[0;35m%v\033[0m\n", Banner)
	c := new(dns.Client)

	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	var err error
	var nameservers *utils.Nameservers
	if a.NSFile != "" {
		nameservers, err = utils.NewNameserversFromFile(a.NSFile)
	} else {
		nameservers, err = utils.NewNameserversFromDomain(a.Domain)
	}
	if err != nil {
		return err
	}

	gologger.Info().Label("INFO").Msgf("scanning domain   : %v\n", a.Domain)
	gologger.Info().Label("INFO").Msgf("using nameservers : %v\n", nameservers.FQDNs)
	gologger.Info().Label("INFO").Msgf("with IPv4 version : %v\n", nameservers.IPs)
	gologger.Info().Label("INFO").Msgf("saving output to  : %v\n\n", a.Outfile)

	var wg sync.WaitGroup
	resChan := make(chan *output.CheckOutput, 1)
	for _, check := range a.CheckList {
		wg.Add(1)
		go func(ch checks.Check) {
			ch.Init(c)
			if err := ch.Start(a.Domain, nameservers); err != nil {
				gologger.Error().Label("ERR").Msgf("check failed with error: %v", err)
			}
			resChan <- ch.Results()
			wg.Done()
		}(check)
	}

	done := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	var results []*output.CheckOutput
	for {
		select {
		case <-done:
			fmt.Println("")
			if a.Outfile != "" {
				if data, err := json.Marshal(results); err != nil {
					return err
				} else {
					if err := os.WriteFile(a.Outfile, data, 0644); err != nil {
						return err
					}
				}
			}
			return nil
		case r := <-resChan:
			if a.Silent {
				r.PrintSilent()
			} else {
				r.PrintVerbose()
			}
			results = append(results, r)
		}
	}
}
