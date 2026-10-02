package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLI(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-V"}, &out, &errOut); code != exitOK || !strings.Contains(out.String(), Version) {
		t.Fatalf("-V: %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"-list"}, &out, &errOut); code != exitOK || !strings.Contains(out.String(), "roa (rpki)") {
		t.Fatalf("-list: %d %q", code, out.String())
	}
	errOut.Reset()
	if code := run(nil, &out, &errOut); code != exitError || !strings.Contains(errOut.String(), "missing domain") {
		t.Fatalf("no domain: %d %q", code, errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"-fail-on", "huge", "example.com"}, &out, &errOut); code != exitError || !strings.Contains(errOut.String(), "unknown severity") {
		t.Fatalf("bad severity: %d %q", code, errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"-c", "bogus", "-nb", "example.com"}, &out, &errOut); code != exitError || !strings.Contains(errOut.String(), "unknown check") {
		t.Fatalf("bad check: %d %q", code, errOut.String())
	}
	if code := run([]string{"-h"}, &out, &errOut); code != exitOK {
		t.Fatalf("-h: %d", code)
	}
}

func TestParseFlagsDomainArgument(t *testing.T) {
	var errOut bytes.Buffer
	opt, _, err := parseFlags([]string{"example.com", "-c", "spf,dmarc", "-v"}, &errOut)
	if err != nil || opt.domain != "example.com" || opt.checks != "spf,dmarc" || !opt.verbose {
		t.Fatalf("parseFlags = %+v, %v", opt, err)
	}
	if _, _, err := parseFlags([]string{"a.com", "b.com"}, &errOut); err == nil {
		t.Fatal("expected error for extra arguments")
	}
}
