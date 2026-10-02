// Package bgp gathers routing information about IP addresses and autonomous
// systems: IP to ASN mapping (Team Cymru), RPKI/IRR/visibility data (RIPEstat,
// RADb) and identification of cloud/CDN/hosting providers.
package bgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/5amu/dnshunter/pkg/dnsutil"
)

// Origin is the BGP origin information of an IP address.
type Origin struct {
	IP        net.IP   `json:"ip"`
	ASNs      []uint32 `json:"asns"`
	Prefix    string   `json:"prefix"`
	Country   string   `json:"country,omitempty"`
	Registry  string   `json:"registry,omitempty"`
	Allocated string   `json:"allocated,omitempty"`
	Source    string   `json:"source"`
}

// ASN returns the first origin AS.
func (o *Origin) ASN() uint32 {
	if o == nil || len(o.ASNs) == 0 {
		return 0
	}
	return o.ASNs[0]
}

func (o *Origin) prefixLen() int {
	p, err := netip.ParsePrefix(o.Prefix)
	if err != nil {
		return -1
	}
	return p.Bits()
}

// ASInfo describes an autonomous system.
type ASInfo struct {
	ASN       uint32 `json:"asn"`
	Name      string `json:"name"`
	Country   string `json:"country,omitempty"`
	Registry  string `json:"registry,omitempty"`
	Allocated string `json:"allocated,omitempty"`
}

// Profile gathers what is known about an IP address.
type Profile struct {
	IP net.IP `json:"ip"`
	// Reserved is set when the address is not globally routable.
	Reserved string    `json:"reserved,omitempty"`
	Origin   *Origin   `json:"origin,omitempty"`
	AS       *ASInfo   `json:"as,omitempty"`
	Provider *Provider `json:"provider,omitempty"`
}

// Service is the entry point of the package. It is safe for concurrent use
// and caches every lookup.
type Service struct {
	Cymru     *Cymru
	Stat      *RIPEstat
	IRRd      *IRRd
	Providers *ProviderDB

	profiles memo[string, *Profile]
	ases     memo[uint32, *ASInfo]
}

// Config configures a Service.
type Config struct {
	DNS         *dnsutil.Client
	RIPEstatURL string
	IRRdAddr    string
	Timeout     time.Duration
	// DisableRIPEstat and DisableIRRd turn off the respective data sources.
	DisableRIPEstat bool
	DisableIRRd     bool
}

// NewService builds a Service.
func NewService(cfg Config) *Service {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	s := &Service{
		Cymru:     &Cymru{DNS: cfg.DNS},
		Providers: NewProviderDB(),
	}
	if !cfg.DisableRIPEstat {
		s.Stat = NewRIPEstat(cfg.RIPEstatURL, cfg.Timeout)
	}
	if !cfg.DisableIRRd {
		s.IRRd = &IRRd{Addr: cfg.IRRdAddr, Timeout: cfg.Timeout}
	}
	return s
}

// ErrNoSource is returned when a data source needed by a lookup is disabled.
var ErrNoSource = errors.New("data source disabled")

// Profile returns the routing profile of ip.
func (s *Service) Profile(ctx context.Context, ip net.IP) (*Profile, error) {
	return s.profiles.do(ip.String(), func() (*Profile, error) {
		p := &Profile{IP: ip}
		if r := ReservedRange(ip); r != "" {
			p.Reserved = r
			return p, nil
		}
		o, err := s.Cymru.Origin(ctx, ip)
		if err != nil && s.Stat != nil {
			if so, serr := s.Stat.NetworkInfo(ctx, ip); serr == nil {
				o, err = so, nil
			}
		}
		if err != nil {
			return p, err
		}
		p.Origin = o
		as, err := s.AS(ctx, o.ASN())
		if err == nil {
			p.AS = as
			if p.Origin.Country == "" {
				p.Origin.Country = as.Country
			}
		} else {
			p.AS = &ASInfo{ASN: o.ASN()}
		}
		p.Provider = s.Providers.Classify(o.ASN(), p.AS.Name)
		return p, nil
	})
}

// AS returns registration details of asn.
func (s *Service) AS(ctx context.Context, asn uint32) (*ASInfo, error) {
	return s.ases.do(asn, func() (*ASInfo, error) {
		as, err := s.Cymru.AS(ctx, asn)
		if err != nil && s.Stat != nil {
			if sa, serr := s.Stat.ASOverview(ctx, asn); serr == nil {
				return sa, nil
			}
		}
		return as, err
	})
}

// Upstreams returns the upstream/peer ASes of asn ("left" neighbours as seen
// by RIPE RIS). When RIPEstat is unavailable it falls back to Team Cymru's
// peer data for ip.
func (s *Service) Upstreams(ctx context.Context, asn uint32, ip net.IP) ([]uint32, string, error) {
	if s.Stat != nil {
		nbs, err := s.Stat.Neighbours(ctx, asn)
		if err == nil {
			var out []uint32
			for _, n := range nbs {
				if n.Type == "left" {
					out = append(out, n.ASN)
				}
			}
			return out, "RIPE RIS", nil
		}
		if ip == nil || ip.To4() == nil {
			return nil, "", err
		}
	}
	if ip == nil {
		return nil, "", ErrNoSource
	}
	peers, err := s.Cymru.Peers(ctx, ip)
	return peers, "Team Cymru", err
}

// IRRStatus describes IRR route objects for an exact prefix.
type IRRStatus struct {
	// Origins maps each registered origin AS to its IRR sources (may be
	// empty when the source is unknown).
	Origins map[uint32][]string
	// Covering lists less-specific route objects (prefix -> origins).
	Covering map[string][]uint32
	Source   string
}

// IRR returns the IRR route objects registered for prefix, using RIPEstat
// with a fallback to RADb.
func (s *Service) IRR(ctx context.Context, prefix string) (*IRRStatus, error) {
	want, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, err
	}
	var statErr error
	if s.Stat != nil {
		routes, err := s.Stat.PrefixRoutingConsistency(ctx, prefix)
		if err == nil {
			st := &IRRStatus{Origins: map[uint32][]string{}, Covering: map[string][]uint32{}, Source: "RIPEstat"}
			for _, r := range routes {
				if !r.InWhois {
					continue
				}
				p, err := netip.ParsePrefix(r.Prefix)
				if err != nil {
					continue
				}
				switch {
				case p.Masked() == want.Masked():
					st.Origins[r.Origin] = append(st.Origins[r.Origin], r.IRRSources...)
				case p.Bits() < want.Bits() && p.Contains(want.Addr()):
					st.Covering[p.String()] = append(st.Covering[p.String()], r.Origin)
				}
			}
			return st, nil
		}
		statErr = err
	}
	if s.IRRd != nil {
		origins, err := s.IRRd.RouteOrigins(ctx, prefix)
		if err == nil {
			st := &IRRStatus{Origins: map[uint32][]string{}, Source: "RADb"}
			for _, o := range origins {
				st.Origins[o] = nil
			}
			return st, nil
		}
		if statErr != nil {
			return nil, fmt.Errorf("%v; %v", statErr, err)
		}
		return nil, err
	}
	if statErr != nil {
		return nil, statErr
	}
	return nil, ErrNoSource
}

// memo caches the result of a function per key, running it once.
type memo[K comparable, V any] struct {
	mu sync.Mutex
	m  map[K]*memoEntry[V]
}

type memoEntry[V any] struct {
	once sync.Once
	v    V
	err  error
}

func (m *memo[K, V]) do(k K, fn func() (V, error)) (V, error) {
	m.mu.Lock()
	if m.m == nil {
		m.m = map[K]*memoEntry[V]{}
	}
	e, ok := m.m[k]
	if !ok {
		e = &memoEntry[V]{}
		m.m[k] = e
	}
	m.mu.Unlock()
	e.once.Do(func() { e.v, e.err = fn() })
	return e.v, e.err
}
