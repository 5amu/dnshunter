package testenv

import (
	"net"
	"testing"
)

func parseIP(t testing.TB, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("invalid IP %q", s)
	}
	return ip
}
