package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/5amu/dnshunter/internal"
	"github.com/5amu/dnshunter/internal/common"
	"github.com/5amu/dnshunter/internal/output"
	"github.com/miekg/dns"
)

func banner() {
	fmt.Println("")
	fmt.Println(common.Banner("    ·▄▄▄▄   ▐ ▄ .▄▄ ·  ▄ .▄▄• ▄▌ ▐ ▄ ▄▄▄▄▄▄▄▄ .▄▄▄   "))
	fmt.Println(common.Banner("    ██▪ ██ •█▌▐█▐█ ▀. ██▪▐██▪██▌•█▌▐█•██  ▀▄.▀·▀▄ █· "))
	fmt.Println(common.Banner("    ▐█· ▐█▌▐█▐▐▌▄▀▀▀█▄██▀▐██▌▐█▌▐█▐▐▌ ▐█.▪▐▀▀▪▄▐▀▀▄  "))
	fmt.Println(common.Banner("    ██. ██ ██▐█▌▐█▄▪▐███▌▐▀▐█▄█▌██▐█▌ ▐█▌·▐█▄▄▌▐█•█▌ "))
	fmt.Println(common.Banner("    ▀▀▀▀▀• ▀▀ █▪ ▀▀▀▀ ▀▀▀ · ▀▀▀ ▀▀ █▪ ▀▀▀  ▀▀▀ .▀  ▀ "))
	fmt.Println(common.Banner("                   -by 5amu (https://github.com/5amu)"))
	fmt.Println("")
}

func usage() {
	fmt.Println("Usage: dnshunter -h|-v [-o <outfile>] [-n <ns-file>] <domain>")
	fmt.Println("")
	fmt.Println("OPTIONS:")
	fmt.Println("    -h|-help     show the program usage and exit")
	fmt.Println("    -v|-version  show the program version and exit")
	fmt.Println("    -o           save output in JSON format")
	fmt.Println("    -n           file with nameservers (line separated)")
	fmt.Println("")
	fmt.Println("POSITIONAL:")
	fmt.Println("")
	fmt.Println("    <domain>      target domain")
	fmt.Println("")
}

func main() {

	var help1, help2, vers1, vers2 bool
	var outfile, nsfile string

	mainFlagSet := flag.NewFlagSet("dnshunter", flag.ContinueOnError)
	mainFlagSet.BoolVar(&help1, "h", false, "")
	mainFlagSet.BoolVar(&help2, "help", false, "show the program usage and exit")
	mainFlagSet.BoolVar(&vers1, "v", false, "")
	mainFlagSet.BoolVar(&vers2, "version", false, "show the program version and exit")
	mainFlagSet.StringVar(&outfile, "o", "", "save output in JSON format")
	mainFlagSet.StringVar(&nsfile, "n", "", "file with nameservers (line separated)")

	banner()

	if err := mainFlagSet.Parse(os.Args[1:]); err != nil {
		fmt.Println(common.Error(fmt.Sprintf("%v", err)))
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		usage()
		fmt.Println(common.Error("not enough arguments"))
		os.Exit(1)
	}

	if help1 || help2 {
		usage()
		os.Exit(0)
	}

	if vers1 || vers2 {
		fmt.Println(common.Error(fmt.Sprintf("version %v\n", common.DNSHunterVersion)))
		os.Exit(0)
	}

	if len(mainFlagSet.Args()) != 1 {
		usage()
		fmt.Println(common.Error("please, specify a target domain"))
		os.Exit(1)
	}

	domain := mainFlagSet.Arg(0)
	if err := run(outfile, nsfile, domain); err != nil {
		fmt.Println(common.Error(fmt.Sprintf("%v", err)))
		os.Exit(1)
	}
}

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
