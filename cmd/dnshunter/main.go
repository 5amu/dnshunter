package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/5amu/dnshunter/internal/common"
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
