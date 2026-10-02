// Package core defines the types shared by every check: the check
// definition, its execution environment and the results it produces.
package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/5amu/dnshunter/pkg/bgp"
	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/5amu/dnshunter/pkg/target"
)

// Check categories.
const (
	CategoryDNS  = "dns"
	CategoryMail = "mail"
	CategoryBGP  = "bgp"
)

// Check is a single security test.
type Check struct {
	ID          string
	Aliases     []string
	Name        string
	Category    string
	Description string
	References  []string
	// Run executes the check, appending findings to r. A returned error means
	// the check could not complete; findings already added are kept.
	Run func(ctx context.Context, env *Env, r *Result) error
}

// Options tune the behaviour of checks.
type Options struct {
	// IPv6 enables queries to nameservers over IPv6.
	IPv6 bool
	// DKIMSelectors are probed in addition to the built-in list.
	DKIMSelectors []string
	// IncludeProviders makes BGP checks analyze addresses that belong to
	// known cloud/CDN/hosting providers instead of skipping them.
	IncludeProviders bool
	// MaxPrefixes caps the number of announced prefixes sampled per ASN.
	MaxPrefixes int
}

// Env is the execution environment handed to every check.
type Env struct {
	Target *target.Target
	DNS    *dnsutil.Client
	BGP    *bgp.Service
	Opts   Options
}

// Severity of a failed finding.
type Severity int

// Severities, from the least to the most severe.
const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = []string{"none", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	*s = v
	return err
}

// ParseSeverity parses a severity name.
func ParseSeverity(s string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(n, strings.TrimSpace(s)) {
			return Severity(i), nil
		}
	}
	return SeverityNone, fmt.Errorf("unknown severity %q (valid: %s)", s, strings.Join(severityNames[1:], ", "))
}

// Status of a finding.
type Status string

// Finding statuses.
const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusInfo  Status = "info"
	StatusSkip  Status = "skipped"
	StatusError Status = "error"
	// StatusPartial marks a result without failures where part of the
	// subjects could not be tested.
	StatusPartial Status = "partial"
)

// Finding is a single observation produced by a check.
type Finding struct {
	Status   Status   `json:"status"`
	Severity Severity `json:"severity,omitempty"`
	// Subject is what the finding is about (nameserver, IP, record...).
	Subject string   `json:"subject,omitempty"`
	Title   string   `json:"title"`
	Details []string `json:"details,omitempty"`
	// PoC is a command reproducing the finding.
	PoC string `json:"poc,omitempty"`
}

// Pass builds a passed finding.
func Pass(subject, title string, details ...string) Finding {
	return Finding{Status: StatusPass, Subject: subject, Title: title, Details: details}
}

// Fail builds a failed finding with the given severity.
func Fail(sev Severity, subject, title string, details ...string) Finding {
	return Finding{Status: StatusFail, Severity: sev, Subject: subject, Title: title, Details: details}
}

// Info builds an informational finding.
func Info(subject, title string, details ...string) Finding {
	return Finding{Status: StatusInfo, Subject: subject, Title: title, Details: details}
}

// Skip builds a skipped finding.
func Skip(subject, title string, details ...string) Finding {
	return Finding{Status: StatusSkip, Subject: subject, Title: title, Details: details}
}

// Errorf builds an error finding.
func Errorf(subject, format string, args ...any) Finding {
	return Finding{Status: StatusError, Subject: subject, Title: fmt.Sprintf(format, args...)}
}

// WithPoC returns a copy of f with a proof of concept command.
func (f Finding) WithPoC(format string, args ...any) Finding {
	f.PoC = fmt.Sprintf(format, args...)
	return f
}

// Result is the outcome of a check.
type Result struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	References  []string  `json:"references,omitempty"`
	Status      Status    `json:"status"`
	Severity    Severity  `json:"severity,omitempty"`
	Findings    []Finding `json:"findings"`
	Error       string    `json:"error,omitempty"`
	DurationMS  int64     `json:"duration_ms"`
}

// NewResult creates an empty result for check c.
func NewResult(c *Check) *Result {
	return &Result{
		ID:          c.ID,
		Name:        c.Name,
		Category:    c.Category,
		Description: c.Description,
		References:  c.References,
		Findings:    []Finding{},
	}
}

// Add appends findings to the result.
func (r *Result) Add(f ...Finding) { r.Findings = append(r.Findings, f...) }

// Finalize computes the overall status and severity of the result.
func (r *Result) Finalize() {
	r.Severity = SeverityNone
	var fail, errs, pass, info, skip int
	for _, f := range r.Findings {
		switch f.Status {
		case StatusFail:
			fail++
			if f.Severity > r.Severity {
				r.Severity = f.Severity
			}
		case StatusError:
			errs++
		case StatusPass:
			pass++
		case StatusInfo:
			info++
		case StatusSkip:
			skip++
		}
	}
	switch {
	case fail > 0:
		r.Status = StatusFail
	case r.Error != "" || (errs > 0 && pass == 0):
		r.Status = StatusError
	case errs > 0:
		r.Status = StatusPartial
	case pass > 0:
		r.Status = StatusPass
	case info > 0:
		r.Status = StatusInfo
	case skip > 0:
		r.Status = StatusSkip
	default:
		r.Status = StatusPass
	}
}

// Failed returns the failed findings.
func (r *Result) Failed() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Status == StatusFail {
			out = append(out, f)
		}
	}
	return out
}
