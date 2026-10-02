// Package dnschecks implements checks on the zone and its authoritative
// nameservers.
package dnschecks

import (
	"context"
	"fmt"

	"github.com/5amu/dnshunter/pkg/core"
	"github.com/5amu/dnshunter/pkg/dnsutil"
	"github.com/5amu/dnshunter/pkg/target"
	"github.com/miekg/dns"
)

// parallelism is the number of nameserver endpoints queried concurrently.
const parallelism = 8

// errNoEndpoint is returned when no nameserver address could be resolved.
var errNoEndpoint = fmt.Errorf("no nameserver address available")

// endpointResult pairs an endpoint with the answer it gave.
type endpointResult struct {
	ep  target.Endpoint
	msg *dns.Msg
	err error
}

// queryAll sends the same query to every nameserver endpoint.
func queryAll(ctx context.Context, env *core.Env, name string, qtype uint16, opts ...dnsutil.QueryOption) []endpointResult {
	eps := env.Target.Endpoints(env.Opts.IPv6)
	return core.ParallelMap(eps, parallelism, func(ep target.Endpoint) endpointResult {
		m := dnsutil.NewMsg(name, qtype, append([]dnsutil.QueryOption{dnsutil.NoRecurse()}, opts...)...)
		r, err := env.DNS.Exchange(ctx, m, env.DNS.Addr(ep.IP))
		return endpointResult{ep: ep, msg: r, err: err}
	})
}

func rcode(m *dns.Msg) string { return dns.RcodeToString[m.Rcode] }

// digAt formats a dig command querying a nameserver endpoint.
func digAt(ep target.Endpoint, args string) string {
	return fmt.Sprintf("dig %s @%s", args, ep.IP)
}
