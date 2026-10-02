// Package report renders scan results as colored console output, JSON or
// Markdown.
package report

import (
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/target"
)

// Report is the full outcome of a scan.
type Report struct {
	Tool       string         `json:"tool"`
	Version    string         `json:"version"`
	Target     *target.Target `json:"target"`
	Resolvers  []string       `json:"resolvers"`
	Warnings   []string       `json:"warnings,omitempty"`
	StartedAt  time.Time      `json:"started_at"`
	DurationMS int64          `json:"duration_ms"`
	Summary    Summary        `json:"summary"`
	Results    []*core.Result `json:"results"`
}

// Summary counts the outcome of the checks.
type Summary struct {
	Checks int `json:"checks"`
	// Failed is the number of checks with at least one failed finding.
	Failed int `json:"failed"`
	// Errors is the number of checks that could not complete.
	Errors int `json:"errors"`
	// Findings counts failed findings by severity.
	Findings map[string]int `json:"findings_by_severity"`
	// MaxSeverity is the highest severity among failed findings.
	MaxSeverity core.Severity `json:"max_severity"`
}

// Summarize computes the summary of results.
func Summarize(results []*core.Result) Summary {
	s := Summary{Checks: len(results), Findings: map[string]int{}}
	for _, sev := range []core.Severity{core.SeverityLow, core.SeverityMedium, core.SeverityHigh, core.SeverityCritical} {
		s.Findings[sev.String()] = 0
	}
	for _, r := range results {
		switch r.Status {
		case core.StatusFail:
			s.Failed++
		case core.StatusError:
			s.Errors++
		}
		for _, f := range r.Failed() {
			s.Findings[f.Severity.String()]++
			if f.Severity > s.MaxSeverity {
				s.MaxSeverity = f.Severity
			}
		}
	}
	return s
}

// Issue is a failed finding together with the check that produced it.
type Issue struct {
	Check   *core.Result
	Finding core.Finding
}

// Issues returns every failed finding, most severe first.
func Issues(results []*core.Result) []Issue {
	var out []Issue
	for _, r := range results {
		for _, f := range r.Failed() {
			out = append(out, Issue{Check: r, Finding: f})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Finding.Severity > out[j].Finding.Severity })
	return out
}

// WriteJSON writes the report to path ("-" for standard output).
func WriteJSON(rep *Report, path string) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
