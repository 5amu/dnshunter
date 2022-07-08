package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/5amu/dnshunter/internal/checks"
	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

func (a *Args) Run() error {
	c := new(dns.Client)

	var err error
	var nameservers *common.Nameservers
	if a.NSFile != "" {
		nameservers, err = common.NewNameserversFromFile(a.NSFile)
	} else {
		nameservers, err = common.NewNameserversFromDomain(a.Domain)
	}
	if err != nil {
		return err
	}

	initialInfo := common.Info(fmt.Sprintf("scanning domain   : %v\n", a.Domain))
	initialInfo += common.Info(fmt.Sprintf("using nameservers : %v\n", nameservers.ToFQDNs()))
	initialInfo += common.Info(fmt.Sprintf("with IPv4 version : %v\n", nameservers.ToIPv4()))
	if a.Outfile != "" {
		initialInfo += common.Info(fmt.Sprintf("saving output to  : %v\n", a.Outfile))
	} else {
		initialInfo += common.Info("saving output to  : /dev/null\n")
	}
	fmt.Println(initialInfo)

	var wg sync.WaitGroup
	resChan := make(chan *output.CheckOutput, 1)
	for _, check := range a.CheckList {
		wg.Add(1)
		go func(ch checks.Check) {
			ch.Init(c)
			if err := ch.Start(a.Domain, nameservers); err != nil {
				fmt.Println(common.Error(fmt.Sprintf("check failed with error: %v", err)))
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
			fmt.Println(r)
			results = append(results, r)
		}
	}
}
