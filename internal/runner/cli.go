package runner

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/5amu/dnshunter/internal/common"
)

type Args struct {
	HelpFlag    bool
	VersionFlag bool
	Outfile     string
	NSFile      string
	Domain      string
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

func ParseArgs() (*Args, error) {

	if len(os.Args) < 2 {
		usage()
		log.Fatal("not enough arguments")
	}

	mainFlagSet := flag.NewFlagSet("dnshunter", flag.ContinueOnError)

	var help1, help2 bool
	mainFlagSet.BoolVar(&help1, "h", false, "")
	mainFlagSet.BoolVar(&help2, "help", false, "show the program usage and exit")

	var vers1, vers2 bool
	mainFlagSet.BoolVar(&vers1, "v", false, "")
	mainFlagSet.BoolVar(&vers2, "version", false, "show the program version and exit")

	var outfile string
	mainFlagSet.StringVar(&outfile, "o", "", "save output in JSON format")

	var nsfile string
	mainFlagSet.StringVar(&nsfile, "n", "", "file with nameservers (line separated)")

	if err := mainFlagSet.Parse(os.Args[1:]); err != nil {
		return nil, err
	}

	if len(mainFlagSet.Args()) != 1 {
		usage()
		return nil, fmt.Errorf("please, specify a target domain")
	}

	return &Args{
		HelpFlag:    help1 || help2,
		VersionFlag: vers1 || vers2,
		Outfile:     outfile,
		NSFile:      nsfile,
		Domain:      mainFlagSet.Arg(0),
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
