package bgp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultRIPEstatURL is the base URL of the RIPEstat Data API.
const DefaultRIPEstatURL = "https://stat.ripe.net/data"

// RIPEstat is a minimal client for the RIPEstat Data API
// (https://stat.ripe.net/docs/data-api). Responses are cached for the lifetime
// of the client so that several checks can share them.
type RIPEstat struct {
	BaseURL   string
	SourceApp string
	HTTP      *http.Client

	sem   chan struct{}
	mu    sync.Mutex
	cache map[string]*cacheEntry
	// down is set after a transport error: RIPEstat is then considered
	// unreachable and later calls fail immediately instead of timing out.
	down error
}

type cacheEntry struct {
	once sync.Once
	data json.RawMessage
	err  error
}

// NewRIPEstat returns a client. RIPEstat asks clients not to exceed 8
// concurrent requests; we stay well below that.
func NewRIPEstat(baseURL string, timeout time.Duration) *RIPEstat {
	if baseURL == "" {
		baseURL = DefaultRIPEstatURL
	}
	return &RIPEstat{
		BaseURL:   strings.TrimSuffix(baseURL, "/"),
		SourceApp: "dnshunter",
		HTTP:      &http.Client{Timeout: timeout},
		sem:       make(chan struct{}, 4),
		cache:     map[string]*cacheEntry{},
	}
}

type ripeEnvelope struct {
	Status     string            `json:"status"`
	StatusCode int               `json:"status_code"`
	Messages   []json.RawMessage `json:"messages"`
	Data       json.RawMessage   `json:"data"`
}

// get fetches /<call>/data.json?<params> and decodes the "data" member.
func (r *RIPEstat) get(ctx context.Context, call string, params url.Values, out any) error {
	params.Set("sourceapp", r.SourceApp)
	u := fmt.Sprintf("%s/%s/data.json?%s", r.BaseURL, call, params.Encode())

	r.mu.Lock()
	e, ok := r.cache[u]
	if !ok {
		e = &cacheEntry{}
		r.cache[u] = e
	}
	r.mu.Unlock()

	e.once.Do(func() { e.data, e.err = r.fetch(ctx, u) })
	if e.err != nil {
		return e.err
	}
	if err := json.Unmarshal(e.data, out); err != nil {
		return fmt.Errorf("ripestat %s: decoding data: %w", call, err)
	}
	return nil
}

func (r *RIPEstat) fetch(ctx context.Context, u string) (json.RawMessage, error) {
	r.mu.Lock()
	down := r.down
	r.mu.Unlock()
	if down != nil {
		return nil, down
	}
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dnshunter (+https://github.com/5amu/dnshunter)")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		err = fmt.Errorf("ripestat unreachable: %w", unwrapURLError(err))
		r.mu.Lock()
		r.down = err
		r.mu.Unlock()
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("ripestat: reading response: %w", err)
	}
	var env ripeEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("ripestat: HTTP %d, invalid JSON response", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || (env.Status != "" && env.Status != "ok") {
		return nil, fmt.Errorf("ripestat: HTTP %d status %q %s", resp.StatusCode, env.Status, messages(env.Messages))
	}
	if len(env.Data) == 0 || bytes.Equal(env.Data, []byte("null")) {
		return nil, fmt.Errorf("ripestat: empty data")
	}
	return env.Data, nil
}

// unwrapURLError drops the method and URL from *url.Error messages.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// messages flattens RIPEstat messages ([["error", "text"], ...]).
func messages(raw []json.RawMessage) string {
	var out []string
	for _, m := range raw {
		var pair []string
		if json.Unmarshal(m, &pair) == nil && len(pair) == 2 {
			out = append(out, pair[1])
		}
	}
	return strings.Join(out, "; ")
}

// flexASN decodes an ASN encoded as a JSON number or string ("AS3333").
type flexASN uint32

func (f *flexASN) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := ParseASN(s)
	if err != nil {
		return err
	}
	*f = flexASN(n)
	return nil
}

// flexStrings decodes either a list of strings or a single string ("-"
// meaning none).
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*f = list
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*f = nil
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" && p != "-" {
			*f = append(*f, p)
		}
	}
	return nil
}

// flexInt decodes an integer encoded as a JSON number or string.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*f = flexInt(n)
	return nil
}

// ROA is a Route Origin Authorization relevant to a validation.
type ROA struct {
	Origin    uint32 `json:"origin"`
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"max_length"`
	Validity  string `json:"validity"`
	Source    string `json:"source,omitempty"`
}

// RPKIResult is the RPKI validation state of a route.
type RPKIResult struct {
	// Status is one of valid, invalid_asn, invalid_length, unknown.
	Status string `json:"status"`
	ROAs   []ROA  `json:"roas,omitempty"`
}

// RPKIValidation validates the route (prefix, asn) against RPKI.
func (r *RIPEstat) RPKIValidation(ctx context.Context, asn uint32, prefix string) (*RPKIResult, error) {
	var data struct {
		Status         string `json:"status"`
		ValidatingROAs []struct {
			Origin    flexASN `json:"origin"`
			Prefix    string  `json:"prefix"`
			MaxLength flexInt `json:"max_length"`
			Validity  string  `json:"validity"`
			Source    string  `json:"source"`
		} `json:"validating_roas"`
	}
	params := url.Values{"resource": {fmt.Sprintf("AS%d", asn)}, "prefix": {prefix}}
	if err := r.get(ctx, "rpki-validation", params, &data); err != nil {
		return nil, err
	}
	if data.Status == "" {
		return nil, fmt.Errorf("ripestat rpki-validation: missing status")
	}
	res := &RPKIResult{Status: strings.ToLower(data.Status)}
	for _, v := range data.ValidatingROAs {
		res.ROAs = append(res.ROAs, ROA{Origin: uint32(v.Origin), Prefix: v.Prefix, MaxLength: int(v.MaxLength), Validity: v.Validity, Source: v.Source})
	}
	return res, nil
}

// RouteConsistency compares a route seen in BGP with IRR route objects.
type RouteConsistency struct {
	Prefix     string   `json:"prefix"`
	Origin     uint32   `json:"origin"`
	ASName     string   `json:"asn_name,omitempty"`
	InBGP      bool     `json:"in_bgp"`
	InWhois    bool     `json:"in_whois"`
	IRRSources []string `json:"irr_sources,omitempty"`
}

// PrefixRoutingConsistency returns, for prefix and related prefixes, whether
// each (prefix, origin) is seen in BGP and/or registered in an IRR.
func (r *RIPEstat) PrefixRoutingConsistency(ctx context.Context, prefix string) ([]RouteConsistency, error) {
	var data struct {
		Routes []struct {
			Prefix     string      `json:"prefix"`
			Origin     flexASN     `json:"origin"`
			ASName     string      `json:"asn_name"`
			InBGP      bool        `json:"in_bgp"`
			InWhois    bool        `json:"in_whois"`
			IRRSources flexStrings `json:"irr_sources"`
		} `json:"routes"`
	}
	if err := r.get(ctx, "prefix-routing-consistency", url.Values{"resource": {prefix}}, &data); err != nil {
		return nil, err
	}
	out := make([]RouteConsistency, 0, len(data.Routes))
	for _, rt := range data.Routes {
		out = append(out, RouteConsistency{Prefix: rt.Prefix, Origin: uint32(rt.Origin), ASName: rt.ASName, InBGP: rt.InBGP, InWhois: rt.InWhois, IRRSources: rt.IRRSources})
	}
	return out, nil
}

// PrefixConsistency is the IRR registration status of a prefix of an AS.
type PrefixConsistency struct {
	Prefix     string   `json:"prefix"`
	InBGP      bool     `json:"in_bgp"`
	InWhois    bool     `json:"in_whois"`
	IRRSources []string `json:"irr_sources,omitempty"`
}

// ASRoutingConsistency returns the IRR registration status of every prefix
// originated by asn.
func (r *RIPEstat) ASRoutingConsistency(ctx context.Context, asn uint32) ([]PrefixConsistency, error) {
	var data struct {
		Prefixes []struct {
			Prefix     string      `json:"prefix"`
			InBGP      bool        `json:"in_bgp"`
			InWhois    bool        `json:"in_whois"`
			IRRSources flexStrings `json:"irr_sources"`
		} `json:"prefixes"`
	}
	if err := r.get(ctx, "as-routing-consistency", url.Values{"resource": {fmt.Sprintf("AS%d", asn)}}, &data); err != nil {
		return nil, err
	}
	out := make([]PrefixConsistency, 0, len(data.Prefixes))
	for _, p := range data.Prefixes {
		out = append(out, PrefixConsistency{Prefix: p.Prefix, InBGP: p.InBGP, InWhois: p.InWhois, IRRSources: p.IRRSources})
	}
	return out, nil
}

// Neighbour is a BGP neighbour of an AS. Type is "left" (upstream or peer,
// closer to the route collectors), "right" (downstream) or "uncertain".
type Neighbour struct {
	ASN   uint32 `json:"asn"`
	Type  string `json:"type"`
	Power int    `json:"power"`
}

// Neighbours returns the BGP neighbours of asn observed by RIS.
func (r *RIPEstat) Neighbours(ctx context.Context, asn uint32) ([]Neighbour, error) {
	type nb struct {
		ASN   flexASN `json:"asn"`
		Type  string  `json:"type"`
		Power flexInt `json:"power"`
	}
	var data struct {
		Neighbours []nb `json:"neighbours"`
		Neighbors  []nb `json:"neighbors"`
	}
	if err := r.get(ctx, "asn-neighbours", url.Values{"resource": {fmt.Sprintf("AS%d", asn)}}, &data); err != nil {
		return nil, err
	}
	list := data.Neighbours
	if len(list) == 0 {
		list = data.Neighbors
	}
	out := make([]Neighbour, 0, len(list))
	for _, n := range list {
		out = append(out, Neighbour{ASN: uint32(n.ASN), Type: strings.ToLower(n.Type), Power: int(n.Power)})
	}
	return out, nil
}

// Visibility is the number of RIS full-table peers seeing a resource.
type Visibility struct {
	Seeing int `json:"seeing"`
	Total  int `json:"total"`
}

// RoutingStatus summarizes the BGP state of a prefix.
type RoutingStatus struct {
	FirstSeen     string         `json:"first_seen,omitempty"`
	VisibilityV4  Visibility     `json:"visibility_v4"`
	VisibilityV6  Visibility     `json:"visibility_v6"`
	Origins       []RouteOrigin  `json:"origins"`
	MoreSpecifics []PrefixOrigin `json:"more_specifics,omitempty"`
}

// RouteOrigin is an origin AS announcing a prefix and its IRR route objects.
type RouteOrigin struct {
	Origin       uint32   `json:"origin"`
	RouteObjects []string `json:"route_objects,omitempty"`
}

// PrefixOrigin is a (prefix, origin) pair.
type PrefixOrigin struct {
	Prefix string `json:"prefix"`
	Origin uint32 `json:"origin"`
}

// RoutingStatus returns the BGP status (visibility, origins...) of resource.
func (r *RIPEstat) RoutingStatus(ctx context.Context, resource string) (*RoutingStatus, error) {
	type vis struct {
		Seeing flexInt `json:"ris_peers_seeing"`
		Total  flexInt `json:"total_ris_peers"`
	}
	var data struct {
		FirstSeen struct {
			Time string `json:"time"`
		} `json:"first_seen"`
		Visibility struct {
			V4 vis `json:"v4"`
			V6 vis `json:"v6"`
		} `json:"visibility"`
		Origins []struct {
			Origin       flexASN     `json:"origin"`
			RouteObjects flexStrings `json:"route_objects"`
		} `json:"origins"`
		MoreSpecifics []struct {
			Prefix string  `json:"prefix"`
			Origin flexASN `json:"origin"`
		} `json:"more_specifics"`
	}
	if err := r.get(ctx, "routing-status", url.Values{"resource": {resource}}, &data); err != nil {
		return nil, err
	}
	rs := &RoutingStatus{
		FirstSeen:    data.FirstSeen.Time,
		VisibilityV4: Visibility{Seeing: int(data.Visibility.V4.Seeing), Total: int(data.Visibility.V4.Total)},
		VisibilityV6: Visibility{Seeing: int(data.Visibility.V6.Seeing), Total: int(data.Visibility.V6.Total)},
	}
	for _, o := range data.Origins {
		rs.Origins = append(rs.Origins, RouteOrigin{Origin: uint32(o.Origin), RouteObjects: o.RouteObjects})
	}
	for _, m := range data.MoreSpecifics {
		rs.MoreSpecifics = append(rs.MoreSpecifics, PrefixOrigin{Prefix: m.Prefix, Origin: uint32(m.Origin)})
	}
	return rs, nil
}

// AnnouncedPrefixes returns the prefixes originated by asn.
func (r *RIPEstat) AnnouncedPrefixes(ctx context.Context, asn uint32) ([]string, error) {
	var data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	}
	if err := r.get(ctx, "announced-prefixes", url.Values{"resource": {fmt.Sprintf("AS%d", asn)}}, &data); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(data.Prefixes))
	for _, p := range data.Prefixes {
		out = append(out, p.Prefix)
	}
	return out, nil
}

// NetworkInfo returns the origin ASNs and the announced prefix covering ip.
func (r *RIPEstat) NetworkInfo(ctx context.Context, ip net.IP) (*Origin, error) {
	var data struct {
		ASNs   []flexASN `json:"asns"`
		Prefix string    `json:"prefix"`
	}
	if err := r.get(ctx, "network-info", url.Values{"resource": {ip.String()}}, &data); err != nil {
		return nil, err
	}
	if len(data.ASNs) == 0 || data.Prefix == "" {
		return nil, ErrNotRouted
	}
	o := &Origin{IP: ip, Prefix: data.Prefix, Source: "ripestat"}
	for _, a := range data.ASNs {
		o.ASNs = append(o.ASNs, uint32(a))
	}
	return o, nil
}

// ASOverview returns the holder name of asn.
func (r *RIPEstat) ASOverview(ctx context.Context, asn uint32) (*ASInfo, error) {
	var data struct {
		Holder string `json:"holder"`
	}
	if err := r.get(ctx, "as-overview", url.Values{"resource": {fmt.Sprintf("AS%d", asn)}}, &data); err != nil {
		return nil, err
	}
	if data.Holder == "" {
		return nil, fmt.Errorf("AS%d: unknown holder", asn)
	}
	return &ASInfo{ASN: asn, Name: data.Holder}, nil
}

// AbuseContacts returns the abuse contacts registered for resource.
func (r *RIPEstat) AbuseContacts(ctx context.Context, resource string) ([]string, error) {
	var data struct {
		AbuseContacts []string `json:"abuse_contacts"`
		Legacy        struct {
			AbuseC []struct {
				Email string `json:"email"`
			} `json:"abuse_c"`
		} `json:"anti_abuse_contacts"`
	}
	if err := r.get(ctx, "abuse-contact-finder", url.Values{"resource": {resource}}, &data); err != nil {
		return nil, err
	}
	out := data.AbuseContacts
	for _, c := range data.Legacy.AbuseC {
		if c.Email != "" {
			out = append(out, c.Email)
		}
	}
	return out, nil
}

// WhoisAttr is a key/value pair of a registry object.
type WhoisAttr struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Whois returns the registry objects (inetnum/NetRange/aut-num...) for resource.
func (r *RIPEstat) Whois(ctx context.Context, resource string) ([][]WhoisAttr, error) {
	var data struct {
		Records [][]WhoisAttr `json:"records"`
	}
	if err := r.get(ctx, "whois", url.Values{"resource": {resource}}, &data); err != nil {
		return nil, err
	}
	return data.Records, nil
}

// Location is the geolocation of an address.
type Location struct {
	Country string `json:"country"`
	City    string `json:"city,omitempty"`
}

// Geolocation returns the (MaxMind GeoLite) location of resource.
func (r *RIPEstat) Geolocation(ctx context.Context, resource string) (*Location, error) {
	var data struct {
		LocatedResources []struct {
			Locations []struct {
				Country string `json:"country"`
				City    string `json:"city"`
			} `json:"locations"`
		} `json:"located_resources"`
	}
	if err := r.get(ctx, "maxmind-geo-lite", url.Values{"resource": {resource}}, &data); err != nil {
		return nil, err
	}
	for _, lr := range data.LocatedResources {
		for _, l := range lr.Locations {
			if l.Country != "" {
				return &Location{Country: l.Country, City: l.City}, nil
			}
		}
	}
	return nil, fmt.Errorf("no geolocation for %s", resource)
}
