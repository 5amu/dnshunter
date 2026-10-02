package bgp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultIRRd is the RADb whois server, which mirrors the major IRR databases
// (RIPE, ARIN, APNIC, AFRINIC, LACNIC, NTTCOM, LEVEL3, ALTDB...).
const DefaultIRRd = "whois.radb.net:43"

// IRRd is a minimal client for the IRRd whois query language.
type IRRd struct {
	Addr    string
	Timeout time.Duration

	mu   sync.Mutex
	down error
}

// RouteOrigins returns the origin ASes of the route/route6 objects registered
// for exactly prefix, using the IRRd "!r<prefix>,o" query.
func (c *IRRd) RouteOrigins(ctx context.Context, prefix string) ([]uint32, error) {
	resp, err := c.query(ctx, fmt.Sprintf("!r%s,o", prefix))
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, f := range strings.Fields(resp) {
		if n, err := ParseASN(f); err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

// query sends a single IRRd command and returns the response payload. IRRd
// answers "A<length>\n<payload>C\n" on success, "C\n" for an empty success,
// "D\n" when the key was not found and "F <message>\n" on error.
func (c *IRRd) query(ctx context.Context, q string) (string, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	addr := c.Addr
	if addr == "" {
		addr = DefaultIRRd
	}
	c.mu.Lock()
	down := c.down
	c.mu.Unlock()
	if down != nil {
		return "", down
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		err = fmt.Errorf("irrd %s unreachable: %w", addr, err)
		c.mu.Lock()
		c.down = err
		c.mu.Unlock()
		return "", err
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := fmt.Fprintf(conn, "%s\n", q); err != nil {
		return "", fmt.Errorf("irrd: %w", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("irrd: reading response: %w", err)
	}
	status = strings.TrimRight(status, "\r\n")
	switch {
	case status == "C", status == "D":
		return "", nil
	case strings.HasPrefix(status, "F"):
		return "", fmt.Errorf("irrd: %s", strings.TrimSpace(strings.TrimPrefix(status, "F")))
	case strings.HasPrefix(status, "A"):
		n, err := strconv.Atoi(status[1:])
		if err != nil || n < 0 || n > 1<<20 {
			return "", fmt.Errorf("irrd: invalid response header %q", status)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", fmt.Errorf("irrd: reading payload: %w", err)
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("irrd: unexpected response %q", status)
	}
}
