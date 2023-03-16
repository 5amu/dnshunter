package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/5amu/dnshunter/pkg/checks"
	"github.com/5amu/dnshunter/pkg/output"
	"github.com/5amu/dnshunter/pkg/utils"
	"github.com/miekg/dns"
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

type Args struct {
	HelpFlag    bool
	VersionFlag bool
	Silent      bool
	Outfile     string
	NSFile      string
	Domain      string
	CheckList   []checks.Check
}

func usage() {
	fmt.Println("Usage: dnshunter -h|-v [-o|-n|-c <ARG>] <domain>")
	fmt.Println("")
	fmt.Println("OPTIONS:")
	fmt.Println("    -h|-help        show the program usage and exit")
	fmt.Println("    -V|-version     show the program version and exit")
	fmt.Println("    -o|--outfile    save output in JSON format")
	fmt.Println("    -n|--nsfile     file with nameservers (line separated)")
	fmt.Println("    -c|--checklist  specify a single check (flag can be repeated)")
	fmt.Println("    -v|--verbose    Print more information")
	fmt.Println("")
	fmt.Println("POSITIONAL:")
	fmt.Println("")
	fmt.Println("    <domain>        target domain")
	fmt.Println("")
	fmt.Println("POSSIBLE CHECKS:")
	fmt.Println("")
	fmt.Println("    soa             check SOA record fields for misconfigurations")
	fmt.Println("    any             check for DNS amplification vulnerability (ANY query)")
	fmt.Println("    glue            check if record NS provides GLUE records")
	fmt.Println("    zone            check an unauthenticated zone transfer can be performed")
	fmt.Println("    dnssec          check if DNSSSEC is implemented by nameserver(s)")
	fmt.Println("    spf             check security of the SPF record")
	fmt.Println("    dmarc           check security of the DMARC record")
	fmt.Println("    dkim            check security of the DKIM record")
	fmt.Println("    geo             check geographic distribution of ASNs")
	fmt.Println("    irr             check validity of IRR for ASNs")
	fmt.Println("    roa             check route signatures for ASNs")
	fmt.Println("")
}

func ParseArgs() (*Args, error) {
	if len(os.Args) < 2 {
		usage()
		return nil, fmt.Errorf("not enough arguments")
	}

	mainFlagSet := flag.NewFlagSet("dnshunter", flag.ContinueOnError)

	var help1, help2 bool
	mainFlagSet.BoolVar(&help1, "h", false, "")
	mainFlagSet.BoolVar(&help2, "help", false, "")

	var vers1, vers2 bool
	mainFlagSet.BoolVar(&vers1, "V", false, "")
	mainFlagSet.BoolVar(&vers2, "version", false, "")

	var verbose1, verbose2 bool
	mainFlagSet.BoolVar(&verbose1, "v", false, "")
	mainFlagSet.BoolVar(&verbose2, "verbose", false, "")

	var outfile1, outfile2 string
	mainFlagSet.StringVar(&outfile1, "o", "", "")
	mainFlagSet.StringVar(&outfile2, "outfile", "", "")

	var nsfile1, nsfile2 string
	mainFlagSet.StringVar(&nsfile1, "n", "", "")
	mainFlagSet.StringVar(&nsfile2, "nsfile", "", "")

	var checklist1, checklist2 []string
	mainFlagSet.Func("c", "", func(s string) error {
		checklist1 = append(checklist1, s)
		return nil
	})
	mainFlagSet.Func("checklist", "", func(s string) error {
		checklist2 = append(checklist2, s)
		return nil
	})

	mainFlagSet.Usage = usage
	if err := mainFlagSet.Parse(os.Args[1:]); err != nil {
		return nil, err
	}

	if len(mainFlagSet.Args()) != 1 {
		usage()
		return nil, fmt.Errorf("please, specify a target domain")
	}

	if outfile1 != "" && outfile2 != "" {
		return nil, fmt.Errorf("please, specify just one output file")
	}

	if nsfile1 != "" && nsfile2 != "" {
		return nil, fmt.Errorf("please, specify just one output file")
	}

	checklist, err := parseChecklist(append(checklist1, checklist2...))
	if err != nil {
		return nil, err
	}

	return &Args{
		HelpFlag:    help1 || help2,
		VersionFlag: vers1 || vers2,
		Silent:      !(verbose1 || verbose2),
		Outfile:     outfile1 + outfile2,
		NSFile:      nsfile1 + nsfile2,
		Domain:      mainFlagSet.Arg(0),
		CheckList:   checklist,
	}, nil
}

func (a *Args) IsHelpVersion() bool {
	if a.HelpFlag {
		usage()
		return true
	}
	if a.VersionFlag {
		fmt.Println("version", DNSHunterVersion)
		return true
	}
	return false
}

func parseChecklist(checklist []string) ([]checks.Check, error) {
	if len(checklist) == 0 {
		return checks.AllChecks(), nil
	}

	var out []checks.Check
	for _, c := range checklist {
		new := checks.NewCheck(strings.ToLower(c))
		if new == nil {
			return nil, fmt.Errorf("invalid check: %v", c)
		}
		out = append(out, new)
	}
	return out, nil
}

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

func main() {
	cfg, err := ParseArgs()
	if err != nil {
		log.Fatal(err)
	}

	if cfg.IsHelpVersion() {
		os.Exit(0)
	}

	if err := cfg.Run(); err != nil {
		log.Fatal(err)
	}
}
