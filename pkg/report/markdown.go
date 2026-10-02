package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/5amu/dnshunter/pkg/core"
)

// WriteMarkdown writes the report as a Markdown document to path.
func WriteMarkdown(rep *Report, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := Markdown(f, rep); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Markdown renders the report as Markdown.
func Markdown(w io.Writer, rep *Report) error {
	var b strings.Builder
	t := rep.Target
	fmt.Fprintf(&b, "# DNSHunter report for %s\n\n", t.Domain)
	fmt.Fprintf(&b, "- **Date:** %s\n", rep.StartedAt.UTC().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "- **Tool:** %s %s\n", rep.Tool, rep.Version)
	if t.Zone != t.Domain {
		fmt.Fprintf(&b, "- **Zone:** %s\n", t.Zone)
	}
	for _, ns := range t.Nameservers {
		var ips []string
		for _, ip := range ns.IPs {
			ips = append(ips, ip.String())
		}
		fmt.Fprintf(&b, "- **Nameserver:** %s (%s)\n", ns.Name, strings.Join(ips, ", "))
	}
	var addrs []string
	for _, ip := range t.Addresses {
		addrs = append(addrs, ip.String())
	}
	fmt.Fprintf(&b, "- **Addresses of %s:** %s\n", t.AddressHost, strings.Join(addrs, ", "))
	for _, w := range rep.Warnings {
		fmt.Fprintf(&b, "- **Warning:** %s\n", w)
	}

	s := rep.Summary
	fmt.Fprintf(&b, "\n## Summary\n\n%d checks, %d with issues, %d errors, %d partial.\n\n", s.Checks, s.Failed, s.Errors, s.Partial)
	b.WriteString("| Severity | Findings |\n|---|---|\n")
	for _, sev := range []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow} {
		fmt.Fprintf(&b, "| %s | %d |\n", sev, s.Findings[sev.String()])
	}
	if issues := Issues(rep.Results); len(issues) > 0 {
		b.WriteString("\n| Severity | Check | Subject | Issue |\n|---|---|---|---|\n")
		for _, is := range issues {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", is.Finding.Severity, is.Check.ID, cell(is.Finding.Subject), cell(is.Finding.Title))
		}
	}

	b.WriteString("\n## Checks\n")
	for _, r := range rep.Results {
		status := string(r.Status)
		if r.Status == core.StatusFail {
			status = fmt.Sprintf("fail (%s)", r.Severity)
		}
		fmt.Fprintf(&b, "\n### %s (`%s`): %s\n\n%s\n", r.Name, r.ID, status, r.Description)
		if len(r.References) > 0 {
			b.WriteString("\nReferences:\n")
			for _, ref := range r.References {
				fmt.Fprintf(&b, "- <%s>\n", ref)
			}
		}
		if r.Error != "" {
			fmt.Fprintf(&b, "\n> **Error:** %s\n", firstLine(r.Error))
		}
		b.WriteString("\n")
		for _, f := range r.Findings {
			tag := strings.ToUpper(string(f.Status))
			if f.Status == core.StatusFail {
				tag = strings.ToUpper(f.Severity.String())
			}
			subject := ""
			if f.Subject != "" {
				subject = "`" + f.Subject + "`: "
			}
			fmt.Fprintf(&b, "- **%s** %s%s\n", tag, subject, f.Title)
			for _, d := range f.Details {
				fmt.Fprintf(&b, "  - %s\n", d)
			}
			if f.PoC != "" {
				fmt.Fprintf(&b, "  - PoC: `%s`\n", f.PoC)
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ")
}
