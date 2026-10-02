package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/target"
	"github.com/fatih/color"
)

// Console prints results to a terminal.
type Console struct {
	W io.Writer
	// Verbose prints descriptions, references, every detail and PoC.
	Verbose bool
	// Silent prints a single line per check.
	Silent bool
	// MaxDetails caps the details printed per finding (non verbose mode).
	MaxDetails int
}

var (
	cBold    = color.New(color.Bold)
	cDim     = color.New(color.Faint)
	cPass    = color.New(color.FgGreen)
	cInfo    = color.New(color.FgCyan)
	cSkip    = color.New(color.FgHiBlack)
	cError   = color.New(color.FgYellow)
	cLow     = color.New(color.FgHiYellow)
	cMedium  = color.New(color.FgHiMagenta)
	cHigh    = color.New(color.FgHiRed)
	cCrit    = color.New(color.FgRed, color.Bold)
	cBanner  = color.New(color.FgMagenta)
	cWarning = color.New(color.FgYellow, color.Bold)
)

// Banner prints the program banner.
func (c *Console) Banner(banner string) { _, _ = cBanner.Fprint(c.W, banner) }

// Warning prints a warning line.
func (c *Console) Warning(format string, args ...any) {
	_, _ = cWarning.Fprint(c.W, "[WARN] ")
	_, _ = fmt.Fprintf(c.W, format+"\n", args...)
}

// Target prints what was discovered about the domain.
func (c *Console) Target(t *target.Target, resolvers []string) {
	if c.Silent {
		return
	}
	line := func(k, v string) {
		_, _ = cInfo.Fprintf(c.W, "[INF] ")
		_, _ = fmt.Fprintf(c.W, "%-13s: %s\n", k, v)
	}
	line("domain", t.Domain)
	if t.Zone != t.Domain {
		line("zone", t.Zone)
	}
	line("resolvers", strings.Join(resolvers, ", "))
	for _, ns := range t.Nameservers {
		v := ns.Name
		if len(ns.IPs) > 0 {
			v += " (" + joinIPs(ns) + ")"
		} else {
			v += " (" + ns.Error + ")"
		}
		line("nameserver", v)
	}
	if t.Delegation != nil {
		line("delegated by", fmt.Sprintf("%s (%s)", t.Delegation.Server, t.Delegation.Parent))
	}
	addrs := make([]string, 0, len(t.Addresses))
	for _, ip := range t.Addresses {
		addrs = append(addrs, ip.String())
	}
	if len(addrs) == 0 {
		addrs = []string{"none"}
	}
	line("addresses", fmt.Sprintf("%s -> %s", t.AddressHost, strings.Join(addrs, ", ")))
	_, _ = fmt.Fprintln(c.W)
}

func joinIPs(ns target.Nameserver) string {
	var s []string
	for _, ip := range ns.IPs {
		s = append(s, ip.String())
	}
	return strings.Join(s, ", ")
}

func statusLabel(r *core.Result) string {
	switch r.Status {
	case core.StatusFail:
		return severityColor(r.Severity).Sprintf("FAIL (%s)", r.Severity)
	case core.StatusPass:
		return cPass.Sprint("PASS")
	case core.StatusError:
		return cError.Sprint("ERROR")
	case core.StatusSkip:
		return cSkip.Sprint("SKIPPED")
	default:
		return cInfo.Sprint("INFO")
	}
}

func severityColor(s core.Severity) *color.Color {
	switch s {
	case core.SeverityCritical:
		return cCrit
	case core.SeverityHigh:
		return cHigh
	case core.SeverityMedium:
		return cMedium
	default:
		return cLow
	}
}

func findingTag(f core.Finding) string {
	switch f.Status {
	case core.StatusFail:
		return severityColor(f.Severity).Sprintf("%-6s", strings.ToUpper(f.Severity.String()))
	case core.StatusPass:
		return cPass.Sprintf("%-6s", "PASS")
	case core.StatusError:
		return cError.Sprintf("%-6s", "ERROR")
	case core.StatusSkip:
		return cSkip.Sprintf("%-6s", "SKIP")
	default:
		return cInfo.Sprintf("%-6s", "INFO")
	}
}

// Result prints the outcome of a check.
func (c *Console) Result(r *core.Result) {
	head := fmt.Sprintf("[%s] %s", r.ID, r.Name)
	if c.Silent {
		_, _ = fmt.Fprintf(c.W, "%-55s %s\n", head, statusLabel(r))
		return
	}
	_, _ = cBold.Fprintf(c.W, "%-55s ", head)
	_, _ = fmt.Fprintln(c.W, statusLabel(r))
	if c.Verbose {
		for _, l := range wrap(r.Description, 90) {
			_, _ = cDim.Fprintf(c.W, "    %s\n", l)
		}
		for _, ref := range r.References {
			_, _ = cDim.Fprintf(c.W, "    ref: %s\n", ref)
		}
	}
	for _, f := range r.Findings {
		c.finding(f)
	}
	if r.Error != "" {
		_, _ = cError.Fprintf(c.W, "    %-6s ", "ERROR")
		_, _ = fmt.Fprintf(c.W, "check did not complete: %s\n", firstLine(r.Error))
	}
	_, _ = fmt.Fprintln(c.W)
}

func (c *Console) finding(f core.Finding) {
	_, _ = fmt.Fprintf(c.W, "    %s ", findingTag(f))
	if f.Subject != "" {
		_, _ = cBold.Fprintf(c.W, "%s", f.Subject)
		_, _ = fmt.Fprint(c.W, ": ")
	}
	_, _ = fmt.Fprintln(c.W, f.Title)
	showDetails := c.Verbose || f.Status == core.StatusFail || f.Status == core.StatusInfo || f.Status == core.StatusSkip
	if showDetails {
		max := c.MaxDetails
		if max <= 0 {
			max = 8
		}
		for i, d := range f.Details {
			if !c.Verbose && i >= max {
				_, _ = cDim.Fprintf(c.W, "           ... %d more (use -v to show all)\n", len(f.Details)-max)
				break
			}
			_, _ = fmt.Fprintf(c.W, "           %s\n", d)
		}
	}
	if f.PoC != "" && (c.Verbose || f.Status == core.StatusFail) {
		_, _ = cDim.Fprintf(c.W, "           PoC: %s\n", f.PoC)
	}
}

// Summary prints the final summary and the list of issues.
func (c *Console) Summary(rep *Report) {
	s := rep.Summary
	_, _ = cBold.Fprintf(c.W, "Summary for %s: ", rep.Target.Domain)
	_, _ = fmt.Fprintf(c.W, "%d checks, %d with issues, %d errors - findings: ", s.Checks, s.Failed, s.Errors)
	var parts []string
	for _, sev := range []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow} {
		parts = append(parts, severityColor(sev).Sprintf("%d %s", s.Findings[sev.String()], sev))
	}
	_, _ = fmt.Fprintln(c.W, strings.Join(parts, ", "))
	if c.Silent {
		return
	}
	for _, is := range Issues(rep.Results) {
		_, _ = fmt.Fprintf(c.W, "    %s [%s] ", findingTag(is.Finding), is.Check.ID)
		if is.Finding.Subject != "" {
			_, _ = fmt.Fprintf(c.W, "%s: ", is.Finding.Subject)
		}
		_, _ = fmt.Fprintln(c.W, is.Finding.Title)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func wrap(s string, width int) []string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(s) {
		if len(line)+len(w)+1 > width && line != "" {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
