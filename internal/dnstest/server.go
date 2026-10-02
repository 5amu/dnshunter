// Package dnstest provides an in-process DNS server serving static records,
// used to test dnshunter against controlled (mis)configurations.
package dnstest

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type key struct {
	name  string
	qtype uint16
}

// Server is a DNS server answering from a static record set over UDP and TCP.
type Server struct {
	Addr string

	// All the fields below are protected by mu and changed with setters.
	mu      sync.Mutex
	records map[key][]dns.RR
	chaos   map[string]string
	// authoritative sets the AA flag on answers (default true).
	authoritative bool
	// recursion sets the RA flag on answers.
	recursion bool
	// axfrZone enables zone transfers of the given zone.
	axfrZone string
	// rcode, when non-zero, is returned for every query (e.g. REFUSED).
	rcode int
	// denial records (NSEC/NSEC3) are added to the authority section of
	// negative answers when the DO bit is set.
	denial []dns.RR
	// hook can answer a query itself; it returns false to fall back to the
	// static records.
	hook func(w dns.ResponseWriter, r *dns.Msg) bool

	udp, tcp *dns.Server
}

// Start launches a server on a random loopback port. It is stopped when the
// test ends.
func Start(t testing.TB) *Server {
	t.Helper()
	s := &Server{records: map[key][]dns.RR{}, chaos: map[string]string{}, authoritative: true}
	var pc net.PacketConn
	var ln net.Listener
	var err error
	for i := 0; i < 20; i++ {
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		ln, err = net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			break
		}
		_ = pc.Close()
	}
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	s.Addr = pc.LocalAddr().String()

	started := make(chan struct{}, 2)
	notify := func() { started <- struct{}{} }
	s.udp = &dns.Server{PacketConn: pc, Handler: s, NotifyStartedFunc: notify}
	s.tcp = &dns.Server{Listener: ln, Handler: s, NotifyStartedFunc: notify}
	go func() { _ = s.udp.ActivateAndServe() }()
	go func() { _ = s.tcp.ActivateAndServe() }()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("dns test server did not start")
		}
	}
	t.Cleanup(func() {
		_ = s.udp.Shutdown()
		_ = s.tcp.Shutdown()
	})
	return s
}

func (s *Server) set(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// SetAuthoritative sets the AA flag of answers.
func (s *Server) SetAuthoritative(v bool) { s.set(func() { s.authoritative = v }) }

// SetRecursion sets the RA flag of answers.
func (s *Server) SetRecursion(v bool) { s.set(func() { s.recursion = v }) }

// SetAXFR allows zone transfers of zone.
func (s *Server) SetAXFR(zone string) { s.set(func() { s.axfrZone = zone }) }

// SetRcode makes the server answer every query with rcode.
func (s *Server) SetRcode(rcode int) { s.set(func() { s.rcode = rcode }) }

// SetDenial sets the NSEC/NSEC3 records returned in negative answers.
func (s *Server) SetDenial(rrs ...dns.RR) { s.set(func() { s.denial = rrs }) }

// SetHook installs a function that can answer queries itself.
func (s *Server) SetHook(fn func(w dns.ResponseWriter, r *dns.Msg) bool) {
	s.set(func() { s.hook = fn })
}

// Add parses and adds records in zone file format.
func (s *Server) Add(t testing.TB, rrs ...string) {
	t.Helper()
	for _, txt := range rrs {
		rr, err := dns.NewRR(txt)
		if err != nil {
			t.Fatalf("invalid record %q: %v", txt, err)
		}
		s.AddRR(rr)
	}
}

// AddRR adds parsed records.
func (s *Server) AddRR(rrs ...dns.RR) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rr := range rrs {
		h := rr.Header()
		k := key{strings.ToLower(h.Name), h.Rrtype}
		if sig, ok := rr.(*dns.RRSIG); ok {
			k.qtype = sig.TypeCovered | 0x8000 // stored alongside the covered type
		}
		s.records[k] = append(s.records[k], rr)
	}
}

// Remove deletes the records of name/qtype.
func (s *Server) Remove(name string, qtype uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, key{strings.ToLower(dns.Fqdn(name)), qtype})
}

// SetChaos sets the answer to a CHAOS TXT query (e.g. version.bind).
func (s *Server) SetChaos(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chaos[strings.ToLower(dns.Fqdn(name))] = value
}

func (s *Server) nameExists(name string) (exact, below bool) {
	for k := range s.records {
		if k.name == name {
			exact = true
		} else if dns.IsSubDomain(name, k.name) {
			below = true
		}
	}
	return exact, below
}

func (s *Server) lookup(name string, qtype uint16, do bool) []dns.RR {
	rrs := append([]dns.RR(nil), s.records[key{name, qtype}]...)
	if do && len(rrs) > 0 {
		rrs = append(rrs, s.records[key{name, qtype | 0x8000}]...)
	}
	return rrs
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	s.mu.Lock()
	hook := s.hook
	s.mu.Unlock()
	if hook != nil && hook(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = s.authoritative
	m.RecursionAvailable = s.recursion
	do := false
	if o := r.IsEdns0(); o != nil {
		do = o.Do()
		m.SetEdns0(o.UDPSize(), do)
	}
	if s.rcode != 0 {
		m.Rcode = s.rcode
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(q.Name)

	if q.Qclass == dns.ClassCHAOS {
		if v, ok := s.chaos[name]; ok {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS}, Txt: []string{v}})
		} else {
			m.Rcode = dns.RcodeRefused
		}
		_ = w.WriteMsg(m)
		return
	}

	if q.Qtype == dns.TypeAXFR {
		s.axfr(w, r, name)
		return
	}

	switch q.Qtype {
	case dns.TypeANY:
		for k, rrs := range s.records {
			if k.name == name {
				m.Answer = append(m.Answer, rrs...)
			}
		}
	default:
		target := name
		for i := 0; i < 8; i++ {
			if rrs := s.lookup(target, q.Qtype, do); len(rrs) > 0 {
				m.Answer = append(m.Answer, rrs...)
				break
			}
			cname := s.lookup(target, dns.TypeCNAME, do)
			if len(cname) == 0 || q.Qtype == dns.TypeCNAME {
				break
			}
			m.Answer = append(m.Answer, cname...)
			target = strings.ToLower(cname[0].(*dns.CNAME).Target)
		}
	}
	if len(m.Answer) == 0 {
		exact, below := s.nameExists(name)
		if !exact && !below {
			m.Rcode = dns.RcodeNameError
		}
		if do {
			m.Ns = append(m.Ns, s.denial...)
		}
	}
	// Additional section: addresses of NS targets.
	for _, rr := range m.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			n := strings.ToLower(ns.Ns)
			m.Extra = append(m.Extra, s.records[key{n, dns.TypeA}]...)
			m.Extra = append(m.Extra, s.records[key{n, dns.TypeAAAA}]...)
		}
	}
	write(w, r, m)
}

// write sends m, truncating it to the client buffer size over UDP.
func write(w dns.ResponseWriter, r, m *dns.Msg) {
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		size := dns.MinMsgSize
		if o := r.IsEdns0(); o != nil {
			size = int(o.UDPSize())
		}
		m.Truncate(size)
	}
	_ = w.WriteMsg(m)
}

func (s *Server) axfr(w dns.ResponseWriter, r *dns.Msg, zone string) {
	if s.axfrZone == "" || !strings.EqualFold(dns.Fqdn(s.axfrZone), zone) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	soa := s.records[key{zone, dns.TypeSOA}]
	var all []dns.RR
	all = append(all, soa...)
	for k, rrs := range s.records {
		if k.qtype&0x8000 != 0 || k.qtype == dns.TypeSOA || !dns.IsSubDomain(zone, k.name) {
			continue
		}
		all = append(all, rrs...)
	}
	all = append(all, soa...)
	ch := make(chan *dns.Envelope, 1)
	ch <- &dns.Envelope{RR: all}
	close(ch)
	tr := new(dns.Transfer)
	_ = tr.Out(w, r, ch)
	_ = w.Close()
}
