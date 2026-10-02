package core

import (
	"strings"
	"testing"
)

func TestFinalize(t *testing.T) {
	cases := []struct {
		findings []Finding
		err      string
		want     Status
		sev      Severity
	}{
		{[]Finding{Pass("a", "ok"), Fail(SeverityLow, "b", "x"), Fail(SeverityHigh, "c", "y")}, "", StatusFail, SeverityHigh},
		{[]Finding{Pass("a", "ok"), Errorf("b", "unreachable")}, "", StatusPartial, SeverityNone},
		{[]Finding{Errorf("b", "unreachable"), Info("c", "i")}, "", StatusError, SeverityNone},
		{[]Finding{Pass("a", "ok")}, "boom", StatusError, SeverityNone},
		{[]Finding{Info("a", "i"), Skip("b", "s")}, "", StatusInfo, SeverityNone},
		{nil, "", StatusPass, SeverityNone},
	}
	for i, c := range cases {
		r := &Result{Findings: c.findings, Error: c.err}
		r.Finalize()
		if r.Status != c.want || r.Severity != c.sev {
			t.Errorf("case %d: %s/%s, want %s/%s", i, r.Status, r.Severity, c.want, c.sev)
		}
	}
}

func TestParallelMap(t *testing.T) {
	got := ParallelMap([]int{1, 2, 3, 4, 5}, 2, func(i int) int { return i * i })
	if len(got) != 5 || got[4] != 25 || got[0] != 1 {
		t.Fatalf("ParallelMap = %v", got)
	}
	defer func() {
		p := recover()
		if p == nil || !strings.Contains(p.(string), "worker boom") {
			t.Fatalf("panic not propagated: %v", p)
		}
	}()
	ParallelMap([]int{1, 2}, 2, func(i int) int {
		if i == 2 {
			panic("worker boom")
		}
		return i
	})
}

func TestSeverity(t *testing.T) {
	if s, err := ParseSeverity("HIGH"); err != nil || s != SeverityHigh {
		t.Fatalf("ParseSeverity = %v, %v", s, err)
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Fatal("expected error")
	}
	b, _ := SeverityMedium.MarshalText()
	var s Severity
	if err := s.UnmarshalText(b); err != nil || s != SeverityMedium {
		t.Fatalf("round trip = %v, %v", s, err)
	}
}
