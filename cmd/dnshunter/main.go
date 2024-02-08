package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/5amu/dnshunter/pkg/checks"
	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/fatih/color"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const Banner = `
    ·▄▄▄▄   ▐ ▄ .▄▄ ·  ▄ .▄▄• ▄▌ ▐ ▄ ▄▄▄▄▄▄▄▄ .▄▄▄   
    ██▪ ██ •█▌▐█▐█ ▀. ██▪▐██▪██▌•█▌▐█•██  ▀▄.▀·▀▄ █· 
    ▐█· ▐█▌▐█▐▐▌▄▀▀▀█▄██▀▐██▌▐█▌▐█▐▐▌ ▐█.▪▐▀▀▪▄▐▀▀▄  
    ██. ██ ██▐█▌▐█▄▪▐███▌▐▀▐█▄█▌██▐█▌ ▐█▌·▐█▄▄▌▐█•█▌ 
    ▀▀▀▀▀• ▀▀ █▪ ▀▀▀▀ ▀▀▀ · ▀▀▀ ▀▀ █▪ ▀▀▀  ▀▀▀ .▀  ▀ 
                   -by 5amu (https://github.com/5amu)

`

// DNSHunterVersion tracks the version of the program
const DNSHunterVersion = "v1.0"

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func uniq(strList []string) []string {
	list := []string{}
	for _, item := range strList {
		if contains(list, item) {
			list = append(list, item)
		}
	}
	return list
}

type options struct {
	verbose   bool
	outFile   string
	domain    string
	checklist goflags.StringSlice
	checks    []checks.Check
}

func (opt *options) run() (err error) {
	color.Magenta(Banner)

	c := new(dns.Client)
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	var nameservers *utils.Nameservers
	if nameservers, err = utils.NewNameserversFromDomain(opt.domain); err != nil {
		return err
	}

	gologger.Info().Label("INFO").Msgf("scanning domain   : %v\n", opt.domain)
	gologger.Info().Label("INFO").Msgf("using nameservers : %v\n", nameservers.FQDNs)
	gologger.Info().Label("INFO").Msgf("with IPv4 version : %v\n", nameservers.IPs)
	gologger.Info().Label("INFO").Msgf("saving output to  : %v\n\n", opt.outFile)

	var wg sync.WaitGroup
	resChan := make(chan *output.CheckOutput, 1)
	for _, check := range opt.checks {
		wg.Add(1)
		go func(ch checks.Check) {
			err := ch.Init(c)
			if err != nil {
				gologger.Error().Label("ERR").Msgf("check init error: %v", err)
			} else {
				if err := ch.Start(opt.domain, nameservers); err != nil {
					gologger.Error().Label("ERR").Msgf("check failed with error: %v", err)
				}
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
			if opt.outFile != "" {
				if data, err := json.Marshal(results); err != nil {
					return err
				} else {
					if err := os.WriteFile(opt.outFile, data, 0644); err != nil {
						return err
					}
				}
			}
			return nil
		case r := <-resChan:
			if opt.verbose {
				r.PrintVerbose()
			} else {
				r.PrintSilent()
			}
			results = append(results, r)
		}
	}
}

func argparse() (*options, error) {

	opt := &options{}
	flagSet := goflags.NewFlagSet()

	flagSet.SetDescription("Make DNS and BGP assessment easier.")

	flagSet.StringVarP(&opt.domain, "domain", "d", "", "provide domain to assess")
	flagSet.StringVarP(&opt.outFile, "outfile", "o", "", "save output in JSON format")
	flagSet.StringSliceVarP(&opt.checklist, "checklist", "c", []string{"all"}, "list of singular checks to be executed (comma-separated)", goflags.FileCommaSeparatedStringSliceOptions)
	flagSet.BoolVarP(&opt.verbose, "verbose", "v", false, "print more information")

	version := func() func() {
		return func() {
			fmt.Println("version", DNSHunterVersion)
		}
	}
	flagSet.CallbackVarP(version(), "version", "V", "show the program version and exit")

	flagSet.SetCustomHelpText(`POSSIBLE CHECKS:
    soa             check SOA record fields for misconfigurations
    any             check for DNS amplification vulnerability (ANY query)
    glue            check if record NS provides GLUE records
    zone            check an unauthenticated zone transfer can be performed
    dnssec          check if DNSSSEC is implemented by nameserver(s)
    spf             check security of the SPF record
    dmarc           check security of the DMARC record
    dkim            check security of the DKIM record
    geo             check geographic distribution of ASNs
    irr             check validity of IRR for ASNs
    roa             check route signatures for ASNs
	`)

	if err := flagSet.Parse(); err != nil {
		return nil, err
	}

	if opt.domain == "" {
		return nil, fmt.Errorf("missing domain! (specify with -d)")
	} else if len(strings.Split(opt.domain, ".")) != 2 {
		return nil, fmt.Errorf("please provide a second-level domain\nhttps://en.wikipedia.org/wiki/Second-level_domain")
	}

	if len(opt.checklist) == 0 || contains(opt.checklist, "all") {
		opt.checks = checks.AllChecks()
	} else {
		for _, c := range uniq(opt.checklist) {
			new := checks.NewCheck(strings.ToLower(c))
			if new == nil {
				return nil, fmt.Errorf("invalid check: %v", c)
			}
			opt.checks = append(opt.checks, new)
		}
	}
	return opt, nil
}

func main() {
	opt, err := argparse()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := opt.run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
