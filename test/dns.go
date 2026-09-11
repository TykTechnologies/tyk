package test

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"

	"time"

	"sync"

	"github.com/miekg/dns"
)

var (
	DomainsToAddresses = map[string][]string{
		"host1.": {"127.0.0.1"},
		"host2.": {"127.0.0.1"},
		"host3.": {"127.0.0.1"},
	}
	DomainsToIgnore = []string{
		"redis.",
		"tyk-redis.",
		"mongo.", // For dashboard integration tests
		"tyk-mongo.",
	}
)

type dnsMockHandler struct {
	domainsToAddresses map[string][]string
	domainsToErrors    map[string]int

	muDomainsToAddresses sync.RWMutex
}

func (d *dnsMockHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeA:
		msg.Authoritative = true
		domain := msg.Question[0].Name

		d.muDomainsToAddresses.RLock()
		defer d.muDomainsToAddresses.RUnlock()

		if rcode, ok := d.domainsToErrors[domain]; ok {
			m := new(dns.Msg)
			m.SetRcode(r, rcode)
			w.WriteMsg(m)
			return
		}

		for _, ignore := range DomainsToIgnore {
			if strings.HasPrefix(domain, ignore) {
				resolver := &net.Resolver{}
				ipAddrs, err := resolver.LookupIPAddr(context.Background(), domain)
				if err != nil {
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeServerFailure)
					w.WriteMsg(m)
					return
				}
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ipAddrs[0].IP,
				})
				w.WriteMsg(&msg)
				return
			}
		}

		var addresses []string

		for d, ips := range d.domainsToAddresses {
			if strings.HasPrefix(domain, d) {
				addresses = ips
			}
		}

		if len(addresses) == 0 {
			// ^ 				start of line
			// localhost\.		match literally
			// ()* 				match between 0 and unlimited times
			// [[:alnum:]]+\.	match single character in [a-zA-Z0-9] minimum one time and ending in . literally
			reg := regexp.MustCompile(`^localhost\.([[:alnum:]]+\.)*`)
			if matched := reg.MatchString(domain); !matched {
				panic(fmt.Sprintf("domain not mocked: %s", domain))
			}

			addresses = []string{"127.0.0.1"}
		}

		for _, addr := range addresses {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(addr),
			})
		}
	}
	w.WriteMsg(&msg)
}

type DnsMockHandle struct {
	id              string
	mockServer      *dns.Server
	ShutdownDnsMock func() error
}

var (
	mockOnce   sync.Once
	sharedMock *DnsMockHandle
	sharedErr  error
)

// PushDomains registers domainsMap and domainsErrorMap with the mock server and
// returns a function that restores what was registered before, so a test can
// scope its own domains and leave the server as it found it.
//
// A domain already registered is replaced, not added to. Appending would make
// a second push of an overlapping set — which is how a scale event is
// simulated: same name, more addresses — answer with the addresses it has in
// common twice over.
func (h *DnsMockHandle) PushDomains(domainsMap map[string][]string, domainsErrorMap map[string]int) func() {
	handler := h.mockServer.Handler.(*dnsMockHandler)
	handler.muDomainsToAddresses.Lock()
	defer handler.muDomainsToAddresses.Unlock()

	dta := handler.domainsToAddresses
	dte := handler.domainsToErrors

	prevDta := map[string][]string{}
	prevDte := map[string]int{}

	for key, value := range dta {
		prevDta[key] = value
	}

	for key, value := range dte {
		prevDte[key] = value
	}

	pullDomainsFunc := func() {
		handler := h.mockServer.Handler.(*dnsMockHandler)
		handler.muDomainsToAddresses.Lock()
		defer handler.muDomainsToAddresses.Unlock()

		handler.domainsToAddresses = prevDta
		handler.domainsToErrors = prevDte
	}

	for key, ips := range domainsMap {
		dta[key] = ips
	}

	for key, rCode := range domainsErrorMap {
		dte[key] = rCode
	}

	return pullDomainsFunc
}

// InitDNSMock initializes dns server on udp:0 address and replaces net.DefaultResolver in order
// to route all dns queries within tests to this server.
// InitDNSMock returns handle, which can be used to add/remove dns query mock responses or initialization error.
//
// Only one mock server exists per process, because net.DefaultResolver can only
// point at one of them. Every call registers its domains with that one server
// and returns a handle to it, so a second caller neither loses its mappings nor
// makes the first caller's domains unresolvable. Registering the same domain
// twice replaces the earlier mapping; use DnsMockHandle.PushDomains for a
// scoped, restorable override.
func InitDNSMock(domainsMap map[string][]string, domainsErrorMap map[string]int) (*DnsMockHandle, error) {
	mockOnce.Do(func() {
		sharedMock, sharedErr = startDNSMock()
	})
	if sharedErr != nil {
		return sharedMock, sharedErr
	}

	if domainsMap == nil {
		domainsMap = DomainsToAddresses
	}

	handler := sharedMock.mockServer.Handler.(*dnsMockHandler)
	handler.muDomainsToAddresses.Lock()
	defer handler.muDomainsToAddresses.Unlock()

	for domain, addresses := range domainsMap {
		handler.domainsToAddresses[domain] = addresses
	}
	for domain, rcode := range domainsErrorMap {
		handler.domainsToErrors[domain] = rcode
	}

	return sharedMock, nil
}

// startDNSMock brings up the single process-wide mock server and points
// net.DefaultResolver at it.
func startDNSMock() (*DnsMockHandle, error) {
	addr, _ := net.ResolveUDPAddr("udp", ":0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return &DnsMockHandle{}, err
	}

	startResultChannel := make(chan error)
	started := func() {
		startResultChannel <- nil
	}

	mockServer := &dns.Server{PacketConn: conn, NotifyStartedFunc: started}
	handle := &DnsMockHandle{id: time.Now().String(), mockServer: mockServer}

	// Both maps are non-nil for the life of the server: callers register into
	// them rather than replacing them, and PushDomains writes into them too.
	dnsMux := &dnsMockHandler{
		domainsToAddresses: map[string][]string{},
		domainsToErrors:    map[string]int{},
	}

	mockServer.Handler = dnsMux

	go func() {
		startResultChannel <- mockServer.ActivateAndServe()
	}()

	err = <-startResultChannel
	if err != nil {
		close(startResultChannel)
		return handle, err
	}

	mockResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, mockServer.PacketConn.LocalAddr().String())
		},
	}

	net.DefaultResolver = mockResolver

	handle.ShutdownDnsMock = func() error {
		// We run tests against O(1) packages, we can
		// afford a dirty shutdown, if it means less
		// flaky tests.
		return nil // mockServer.Shutdown()
	}

	return handle, nil
}

func IsDnsRecordsAddrsEqualsTo(itemAddrs, addrs []string) bool {
	return reflect.DeepEqual(itemAddrs, addrs)
}
