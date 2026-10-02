// Command dnshunter assesses the security of a domain: its DNS zone and
// nameservers, e-mail authentication records and the routing (BGP)
// infrastructure behind its nameservers and addresses.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/5amu/dnshunter/pkg/bgp"
	"github.com/5amu/dnshunter/pkg/checks"
	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/5amu/dnshunter/pkg/report"
	"github.com/5amu/dnshunter/pkg/scanner"
	"github.com/5amu/dnshunter/pkg/target"
	"github.com/fatih/color"
)

// Version of the program, overridden at build time by goreleaser.
var Version = "v2.0.0"

const banner = `
    ·▄▄▄▄   ▐ ▄ .▄▄ ·  ▄ .▄▄• ▄▌ ▐ ▄ ▄▄▄▄▄▄▄▄ .▄▄▄
    ██▪ ██ •█▌▐█▐█ ▀. ██▪▐██▪██▌•█▌▐█•██  ▀▄.▀·▀▄ █·
    ▐█· ▐█▌▐█▐▐▌▄▀▀▀█▄██▀▐██▌▐█▌▐█▐▐▌ ▐█.▪▐▀▀▪▄▐▀▀▄
    ██. ██ ██▐█▌▐█▄▪▐███▌▐▀▐█▄█▌██▐█▌ ▐█▌·▐█▄▄▌▐█•█▌
    ▀▀▀▀▀• ▀▀ █▪ ▀▀▀▀ ▀▀▀ · ▀▀▀ ▀▀ █▪ ▀▀▀  ▀▀▀ .▀  ▀
                   -by 5amu (https://github.com/5amu)

`

// Exit codes.
const (
	exitOK       = 0
	exitError    = 1
	exitFindings = 2
)

type options struct {
	domain           string
	checks           string
	exclude          string
	resolvers        string
	timeout          time.Duration
	retries          int
	checkTimeout     time.Duration
	concurrency      int
	jsonOut          string
	jsonStdout       bool
	markdownOut      string
	verbose          bool
	silent           bool
	noColor          bool
	noBanner         bool
	ipv6             bool
	dkimSelectors    string
	includeProviders bool
	providerASNs     string
	noRIPEstat       bool
	noIRRd           bool
	ripestatURL      string
	irrdAddr         string
	maxPrefixes      int
	failOn           string
	list             bool
	version          bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	opt, fs, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if opt.noColor {
		color.NoColor = true
	}
	switch {
	case opt.version:
		_, _ = fmt.Fprintln(stdout, "dnshunter", Version)
		return exitOK
	case opt.list:
		listChecks(stdout)
		return exitOK
	case opt.domain == "":
		fs.Usage()
		_, _ = fmt.Fprintln(stderr, "\nerror: missing domain (use -d example.com)")
		return exitError
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	code, err := scan(ctx, opt, stdout, stderr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	return code
}

func parseFlags(args []string, stderr io.Writer) (*options, *flag.FlagSet, error) {
	opt := &options{}
	fs := flag.NewFlagSet("dnshunter", flag.ContinueOnError)
	fs.SetOutput(stderr)

	str := func(p *string, names []string, def, usage string) {
		for _, n := range names {
			fs.StringVar(p, n, def, usage)
		}
	}
	boolean := func(p *bool, names []string, usage string) {
		for _, n := range names {
			fs.BoolVar(p, n, false, usage)
		}
	}

	str(&opt.domain, []string{"d", "domain"}, "", "domain to assess (can also be given as argument)")
	str(&opt.checks, []string{"c", "checks", "checklist"}, "all", "comma-separated checks or groups to run (all, dns, mail, bgp)")
	str(&opt.exclude, []string{"x", "exclude"}, "", "comma-separated checks or groups to skip")
	str(&opt.resolvers, []string{"r", "resolvers"}, strings.Join(dnsutil.DefaultResolvers, ","), "comma-separated recursive resolvers")
	fs.DurationVar(&opt.timeout, "t", 3*time.Second, "timeout of a single DNS query")
	fs.DurationVar(&opt.timeout, "timeout", 3*time.Second, "timeout of a single DNS query")
	fs.IntVar(&opt.retries, "retries", 1, "retries of a DNS query on network errors")
	fs.DurationVar(&opt.checkTimeout, "check-timeout", 3*time.Minute, "maximum duration of a check")
	fs.IntVar(&opt.concurrency, "concurrency", 4, "checks running in parallel")
	str(&opt.jsonOut, []string{"o", "output"}, "", "write the JSON report to file (- for stdout)")
	boolean(&opt.jsonStdout, []string{"json"}, "print the JSON report on stdout instead of the console output")
	str(&opt.markdownOut, []string{"md", "markdown"}, "", "write a Markdown report to file")
	boolean(&opt.verbose, []string{"v", "verbose"}, "show descriptions, references, every detail and PoC")
	boolean(&opt.silent, []string{"s", "silent"}, "print one line per check")
	boolean(&opt.noColor, []string{"nc", "no-color"}, "disable colors")
	boolean(&opt.noBanner, []string{"nb", "no-banner"}, "do not print the banner")
	boolean(&opt.ipv6, []string{"6", "ipv6"}, "also query nameservers over IPv6")
	str(&opt.dkimSelectors, []string{"dkim-selectors"}, "", "comma-separated DKIM selectors to probe in addition to the common ones")
	boolean(&opt.includeProviders, []string{"include-providers"}, "analyze routing data of cloud/CDN/hosting provider networks too")
	str(&opt.providerASNs, []string{"provider-asns"}, "", "comma-separated ASNs to treat as providers (skipped by BGP checks)")
	boolean(&opt.noRIPEstat, []string{"no-ripestat"}, "do not query the RIPEstat API (disables RPKI, visibility and AS coverage analysis)")
	boolean(&opt.noIRRd, []string{"no-irrd"}, "do not query the RADb whois server (IRR fallback)")
	str(&opt.ripestatURL, []string{"ripestat-url"}, bgp.DefaultRIPEstatURL, "RIPEstat Data API base URL")
	str(&opt.irrdAddr, []string{"irrd"}, bgp.DefaultIRRd, "IRRd whois server (host:port)")
	fs.IntVar(&opt.maxPrefixes, "max-prefixes", 20, "announced prefixes sampled per AS for RPKI coverage")
	str(&opt.failOn, []string{"fail-on"}, "", "exit with code 2 when a finding of this severity or higher is found (low, medium, high, critical)")
	boolean(&opt.list, []string{"l", "list"}, "list the available checks and exit")
	boolean(&opt.version, []string{"V", "version"}, "print the version and exit")

	fs.Usage = func() { usage(fs, stderr) }
	if err := fs.Parse(args); err != nil {
		return nil, fs, err
	}
	rest := fs.Args()
	if opt.domain == "" && len(rest) > 0 {
		opt.domain, rest = rest[0], rest[1:]
		// Allow flags after the domain argument.
		if err := fs.Parse(rest); err != nil {
			return nil, fs, err
		}
		rest = fs.Args()
	}
	if len(rest) > 0 {
		return nil, fs, fmt.Errorf("unexpected arguments: %s", strings.Join(rest, " "))
	}
	if opt.failOn != "" {
		sev, err := core.ParseSeverity(opt.failOn)
		if err != nil {
			return nil, fs, err
		}
		if sev == core.SeverityNone {
			return nil, fs, fmt.Errorf("-fail-on must be low, medium, high or critical")
		}
	}
	return opt, fs, nil
}

func usage(fs *flag.FlagSet, w io.Writer) {
	_, _ = fmt.Fprintf(w, `DNSHunter %s - assess the DNS, e-mail and BGP security of a domain.

Usage:
  dnshunter [flags] -d example.com
  dnshunter [flags] example.com

Flags:
`, Version)
	seen := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		if seen[f.Usage] {
			return
		}
		seen[f.Usage] = true
		var names []string
		fs.VisitAll(func(g *flag.Flag) {
			if g.Usage == f.Usage {
				names = append(names, "-"+g.Name)
			}
		})
		def := ""
		if f.DefValue != "" && f.DefValue != "false" {
			def = fmt.Sprintf(" (default %s)", f.DefValue)
		}
		_, _ = fmt.Fprintf(w, "  %-34s %s%s\n", strings.Join(names, ", "), f.Usage, def)
	})
	_, _ = fmt.Fprintln(w)
	listChecks(w)
	_, _ = fmt.Fprintln(w, `
Exit codes: 0 success, 1 error, 2 findings at or above -fail-on severity.`)
}

func listChecks(w io.Writer) {
	_, _ = fmt.Fprintf(w, "Checks (groups: all, %s):\n", strings.Join(checks.GroupNames(), ", "))
	for _, c := range checks.All() {
		id := c.ID
		if len(c.Aliases) > 0 {
			id += " (" + strings.Join(c.Aliases, ", ") + ")"
		}
		_, _ = fmt.Fprintf(w, "  %-28s %-5s %s\n", id, c.Category, c.Name)
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func scan(ctx context.Context, opt *options, stdout, stderr io.Writer) (int, error) {
	selected, err := checks.Select(splitList(opt.checks), splitList(opt.exclude))
	if err != nil {
		return exitError, err
	}

	consoleOut := stdout
	if opt.jsonStdout || opt.jsonOut == "-" {
		consoleOut = io.Discard
	}
	con := &report.Console{W: consoleOut, Verbose: opt.verbose, Silent: opt.silent}
	warn := func(rep *report.Report, format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		rep.Warnings = append(rep.Warnings, msg)
		if consoleOut == io.Discard {
			_, _ = fmt.Fprintln(stderr, "warning:", msg)
		} else {
			con.Warning("%s", msg)
		}
	}

	if !opt.noBanner && !opt.silent {
		con.Banner(banner)
	}

	client := dnsutil.New(splitList(opt.resolvers), opt.timeout, opt.retries)
	svc := bgp.NewService(bgp.Config{
		DNS:             client,
		RIPEstatURL:     opt.ripestatURL,
		IRRdAddr:        opt.irrdAddr,
		DisableRIPEstat: opt.noRIPEstat,
		DisableIRRd:     opt.noIRRd,
	})
	for _, a := range splitList(opt.providerASNs) {
		asn, err := bgp.ParseASN(a)
		if err != nil {
			return exitError, err
		}
		svc.Providers.Add(asn, "")
	}

	rep := &report.Report{Tool: "dnshunter", Version: Version, Resolvers: client.Resolvers, StartedAt: time.Now()}

	if intercepted, err := client.DetectInterception(ctx); err != nil {
		warn(rep, "could not verify direct DNS connectivity to authoritative servers (%v): nameserver checks may fail", err)
	} else if intercepted {
		warn(rep, "DNS traffic appears to be intercepted by a transparent resolver: per-nameserver results (recursion, AXFR, ANY, version, glue, lame delegation) may describe the interceptor, not the real servers")
	}

	t, err := target.Discover(ctx, client, opt.domain)
	if err != nil {
		return exitError, err
	}
	rep.Target = t
	con.Target(t, client.Resolvers)

	env := &core.Env{
		Target: t,
		DNS:    client,
		BGP:    svc,
		Opts: core.Options{
			IPv6:             opt.ipv6,
			DKIMSelectors:    splitList(opt.dkimSelectors),
			IncludeProviders: opt.includeProviders,
			MaxPrefixes:      opt.maxPrefixes,
		},
	}
	rep.Results = scanner.Run(ctx, env, selected, opt.concurrency, opt.checkTimeout, con.Result)
	rep.DurationMS = time.Since(rep.StartedAt).Milliseconds()
	rep.Summary = report.Summarize(rep.Results)
	con.Summary(rep)

	if opt.jsonStdout {
		opt.jsonOut = "-"
	}
	if opt.jsonOut != "" {
		if err := report.WriteJSON(rep, opt.jsonOut); err != nil {
			return exitError, fmt.Errorf("writing JSON report: %w", err)
		}
	}
	if opt.markdownOut != "" {
		if err := report.WriteMarkdown(rep, opt.markdownOut); err != nil {
			return exitError, fmt.Errorf("writing Markdown report: %w", err)
		}
	}
	if ctx.Err() != nil {
		return exitError, fmt.Errorf("interrupted")
	}
	if rep.Summary.Errors == len(rep.Results) {
		return exitError, fmt.Errorf("every check failed to complete: no result can be trusted")
	}
	if opt.failOn != "" {
		threshold, _ := core.ParseSeverity(opt.failOn)
		if rep.Summary.MaxSeverity >= threshold {
			return exitFindings, nil
		}
	}
	return exitOK, nil
}
