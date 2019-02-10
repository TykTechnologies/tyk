package test

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"regexp"

	"time"

	"sync"

	"github.com/miekg/dns"
)

var (
	muDefaultResolver  sync.RWMutex
	DomainsToAddresses = map[string][]string{
		"host1.local.": {"127.0.0.1"},
		"host2.local.": {"127.0.0.1"},
		"host3.local.": {"127.0.0.1"},
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

		addresses, ok := d.domainsToAddresses[domain]
		if !ok {
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
		addr, ok := dta[key]
		if !ok {
			dta[key] = ips
		} else {
			dta[key] = append(addr, ips...)
		}
	}

	for key, rCode := range domainsErrorMap {
		dte[key] = rCode
	}

	return pullDomainsFunc
}

// InitDNSMock initializes dns server on udp:0 address and replaces net.DefaultResolver in order
// to route all dns queries within tests to this server.
// InitDNSMock returns handle, which can be used to add/remove dns query mock responses or initialization error.
func InitDNSMock(domainsMap map[string][]string, domainsErrorMap map[string]int) (*DnsMockHandle, error) {
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

	dnsMux := &dnsMockHandler{muDomainsToAddresses: sync.RWMutex{}}

	if domainsMap != nil {
		dnsMux.domainsToAddresses = domainsMap
	} else {
		dnsMux.domainsToAddresses = DomainsToAddresses
	}

	if domainsErrorMap != nil {
		dnsMux.domainsToErrors = domainsErrorMap
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

	muDefaultResolver.RLock()
	defaultResolver := net.DefaultResolver
	muDefaultResolver.RUnlock()
	mockResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}

			//Use write lock to prevent unsafe d.DialContext update of net.DefaultResolver
			muDefaultResolver.Lock()
			defer muDefaultResolver.Unlock()
			return d.DialContext(ctx, network, mockServer.PacketConn.LocalAddr().String())
		},
	}

	muDefaultResolver.Lock()
	net.DefaultResolver = mockResolver
	muDefaultResolver.Unlock()

	handle.ShutdownDnsMock = func() error {
		muDefaultResolver.Lock()
		net.DefaultResolver = defaultResolver
		muDefaultResolver.Unlock()

		return mockServer.Shutdown()
	}

	return handle, nil
}

func IsDnsRecordsAddrsEqualsTo(itemAddrs, addrs []string) bool {
	return reflect.DeepEqual(itemAddrs, addrs)
}
