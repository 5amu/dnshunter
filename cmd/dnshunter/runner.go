package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/5amu/dnshunter/internal"
	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

func run(outfile string, nsfile string, domain string) error {
	c := new(dns.Client)

	var err error
	var nameservers *common.Nameservers
	if nsfile != "" {
		nameservers, err = common.NewNameserversFromFile(nsfile)
	} else {
		nameservers, err = common.NewNameserversFromDomain(domain)
	}
	if err != nil {
		return err
	}

	initialInfo := common.Info(fmt.Sprintf("scanning domain   : %v\n", domain))
	initialInfo += common.Info(fmt.Sprintf("using nameservers : %v\n", nameservers.ToFQDNs()))
	initialInfo += common.Info(fmt.Sprintf("with IPv4 version : %v\n", nameservers.ToIPv4()))
	if outfile != "" {
		initialInfo += common.Info(fmt.Sprintf("saving output to  : %v\n", outfile))
	} else {
		initialInfo += common.Info("saving output to  : /dev/null\n")
	}
	fmt.Println(initialInfo)

	var wg sync.WaitGroup
	resChan := make(chan *output.CheckOutput, 1)
	for _, check := range internal.CheckList {
		wg.Add(1)
		go func(ch internal.Check) {
			ch.Init(c)
			if err := ch.Start(domain, nameservers); err != nil {
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
		case r := <-resChan:
			fmt.Println(r)
			results = append(results, r)
		}
	}
}
