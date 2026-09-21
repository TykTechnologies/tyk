package test

import (
	"context"
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

		// Longest match wins. The map is process-wide, so prefix-related
		// names are easy to end up with and iteration order is random.
		matched := ""
		for d, ips := range d.domainsToAddresses {
			if strings.HasPrefix(domain, d) && len(d) > len(matched) {
				matched, addresses = d, ips
			}
		}

		if len(addresses) == 0 {
			// ^ 				start of line
			// localhost\.		match literally
			// ()* 				match between 0 and unlimited times
			// [[:alnum:]]+\.	match single character in [a-zA-Z0-9] minimum one time and ending in . literally
			reg := regexp.MustCompile(`^localhost\.([[:alnum:]]+\.)*`)
			if matched := reg.MatchString(domain); !matched {
				// On the server's goroutine: a panic aborts the binary.
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeNameError)
				w.WriteMsg(m)
				return
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

// PushDomains returns a function restoring what was registered before. A
// domain already registered is replaced rather than added to, or a second push
// of an overlapping set, as a scale event is, would answer twice over.
func (h *DnsMockHandle) PushDomains(domainsMap map[string][]string, domainsErrorMap map[string]int) func() {
	handler := h.mockServer.Handler.(*dnsMockHandler)
	handler.muDomainsToAddresses.Lock()
	defer handler.muDomainsToAddresses.Unlock()

	// Key by key, or registrations made by others in this window are lost.
	priorAddrs := make(map[string][]string, len(domainsMap))
	addedAddrs := make(map[string]struct{}, len(domainsMap))
	for key, ips := range domainsMap {
		if existing, ok := handler.domainsToAddresses[key]; ok {
			priorAddrs[key] = existing
		} else {
			addedAddrs[key] = struct{}{}
		}
		handler.domainsToAddresses[key] = ips
	}

	priorErrs := make(map[string]int, len(domainsErrorMap))
	addedErrs := make(map[string]struct{}, len(domainsErrorMap))
	for key, rCode := range domainsErrorMap {
		if existing, ok := handler.domainsToErrors[key]; ok {
			priorErrs[key] = existing
		} else {
			addedErrs[key] = struct{}{}
		}
		handler.domainsToErrors[key] = rCode
	}

	return func() {
		handler := h.mockServer.Handler.(*dnsMockHandler)
		handler.muDomainsToAddresses.Lock()
		defer handler.muDomainsToAddresses.Unlock()

		for key := range addedAddrs {
			delete(handler.domainsToAddresses, key)
		}
		for key, ips := range priorAddrs {
			handler.domainsToAddresses[key] = ips
		}

		for key := range addedErrs {
			delete(handler.domainsToErrors, key)
		}
		for key, rCode := range priorErrs {
			handler.domainsToErrors[key] = rCode
		}
	}
}

// InitDNSMock initializes dns server on udp:0 address and replaces net.DefaultResolver in order
// to route all dns queries within tests to this server.
// InitDNSMock returns handle, which can be used to add/remove dns query mock responses or initialization error.
//
// One mock server per process, since net.DefaultResolver can only point at
// one, so every call registers into it rather than replacing it. Use
// PushDomains for a scoped, restorable override.
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

// startDNSMock points net.DefaultResolver at the process-wide mock server.
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

	// Non-nil for the life of the server: callers register into them.
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
