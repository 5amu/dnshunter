package report

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/target"
	"github.com/fatih/color"
)

func sample() *Report {
	r1 := &core.Result{ID: "spf", Name: "SPF record", Category: "mail", Description: "desc"}
	r1.Add(core.Fail(core.SeverityMedium, "example.com", "no SPF record").WithPoC("dig TXT example.com"))
	r1.Finalize()
	r2 := &core.Result{ID: "zone", Name: "AXFR", Category: "dns"}
	r2.Add(core.Fail(core.SeverityHigh, "ns1 (192.0.2.1)", "zone transfer allowed", "a.example.com A 192.0.2.10"), core.Pass("ns2", "refused"))
	r2.Finalize()
	r3 := &core.Result{ID: "asn", Name: "ASN", Category: "bgp", Error: "ripestat unreachable"}
	r3.Finalize()
	results := []*core.Result{r1, r2, r3}
	return &Report{
		Tool: "dnshunter", Version: "test", StartedAt: time.Unix(0, 0),
		Target: &target.Target{Domain: "example.com", Zone: "example.com", AddressHost: "example.com",
			Nameservers: []target.Nameserver{{Name: "ns1.example.com", IPs: []net.IP{net.ParseIP("192.0.2.1")}}}},
		Results: results, Summary: Summarize(results),
	}
}

func TestSummarize(t *testing.T) {
	s := sample().Summary
	if s.Checks != 3 || s.Failed != 2 || s.Errors != 1 || s.Findings["high"] != 1 || s.Findings["medium"] != 1 || s.MaxSeverity != core.SeverityHigh {
		t.Fatalf("summary = %+v", s)
	}
	is := Issues(sample().Results)
	if len(is) != 2 || is[0].Finding.Severity != core.SeverityHigh {
		t.Fatalf("issues = %+v", is)
	}
}

func TestJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := WriteJSON(sample(), path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var back struct {
		Summary struct {
			MaxSeverity string `json:"max_severity"`
		} `json:"summary"`
		Results []struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Severity string `json:"severity"`
			Findings []struct {
				Severity string `json:"severity"`
				PoC      string `json:"poc"`
			} `json:"findings"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Summary.MaxSeverity != "high" || back.Results[0].Status != "fail" || back.Results[0].Severity != "medium" || back.Results[0].Findings[0].PoC == "" {
		t.Fatalf("unexpected JSON:\n%s", data)
	}
}

func TestMarkdownAndConsole(t *testing.T) {
	var md bytes.Buffer
	if err := Markdown(&md, sample()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# DNSHunter report for example.com", "| high | zone | ns1 (192.0.2.1) | zone transfer allowed |", "- **MEDIUM** `example.com`: no SPF record", "  - PoC: `dig TXT example.com`", "> **Error:** ripestat unreachable"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown missing %q:\n%s", want, md.String())
		}
	}

	color.NoColor = true
	var out bytes.Buffer
	c := &Console{W: &out}
	rep := sample()
	for _, r := range rep.Results {
		c.Result(r)
	}
	c.Summary(rep)
	for _, want := range []string{"FAIL (high)", "HIGH   ns1 (192.0.2.1): zone transfer allowed", "PoC: dig TXT example.com", "check did not complete: ripestat unreachable", "3 checks, 2 with issues, 1 errors"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("console missing %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	(&Console{W: &out, Silent: true}).Result(rep.Results[0])
	if strings.Count(out.String(), "\n") != 1 {
		t.Errorf("silent output = %q", out.String())
	}
}
