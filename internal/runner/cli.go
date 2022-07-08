package runner

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/5amu/dnshunter/internal/checks"
	"github.com/5amu/dnshunter/internal/common"
)

type Args struct {
	HelpFlag    bool
	VersionFlag bool
	Outfile     string
	NSFile      string
	Domain      string
	CheckList   []checks.Check
}

func usage() {
	fmt.Println("Usage: dnshunter -h|-v [-o <outfile>] [-n <ns-file>] <domain>")
	fmt.Println("")
	fmt.Println("OPTIONS:")
	fmt.Println("    -h|-help        show the program usage and exit")
	fmt.Println("    -v|-version     show the program version and exit")
	fmt.Println("    -o|--outfile    save output in JSON format")
	fmt.Println("    -n|--nsfile     file with nameservers (line separated)")
	fmt.Println("    -c|--checklist  comma separated list of checks to perform (default:all)")
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
	mainFlagSet.BoolVar(&vers1, "v", false, "")
	mainFlagSet.BoolVar(&vers2, "version", false, "")

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

	chechlist, err := parseChecklist(append(checklist1, checklist2...))
	if err != nil {
		return nil, err
	}

	return &Args{
		HelpFlag:    help1 || help2,
		VersionFlag: vers1 || vers2,
		Outfile:     outfile1 + outfile2,
		NSFile:      nsfile1 + nsfile2,
		Domain:      mainFlagSet.Arg(0),
		CheckList:   chechlist,
	}, nil
}

func (a *Args) IsHelpVersion() bool {
	if a.HelpFlag {
		usage()
		return true
	}
	if a.VersionFlag {
		fmt.Println("version", common.DNSHunterVersion)
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
