package test

import (
	"context"
	"fmt"
	"net"
	"regexp"

	"github.com/miekg/dns"
	"time"
)

var DomainsToAddresses = map[string][]string{
	"host1.local.": {"127.0.0.1"},
	"host2.local.": {"127.0.0.1"},
	"host3.local.": {"127.0.0.1"},
}

type dnsMockHandler struct {
	domainsToAddresses map[string][]string
	domainsToErrors map[string]int
}

func (d *dnsMockHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeA:
		msg.Authoritative = true
		domain := msg.Question[0].Name

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
	 id string
	mockServer *dns.Server
	ShutdownDnsMock func() error
}

func (h *DnsMockHandle) PushDomains(domainsMap map[string][]string, domainsErrorMap map[string]int) func() {
	dta := h.mockServer.Handler.(*dnsMockHandler).domainsToAddresses
	dte := h.mockServer.Handler.(*dnsMockHandler).domainsToErrors

	prevDta := map[string][]string{}
	prevDte := map[string]int{}

	for key, value := range dta {
		prevDta[key] = value
	}

	for key, value := range dte {
		prevDte[key] = value
	}

	pullDomainsFunc := func() {
		h.mockServer.Handler.(*dnsMockHandler).domainsToAddresses = prevDta
		h.mockServer.Handler.(*dnsMockHandler).domainsToErrors = prevDte
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
	handle := &DnsMockHandle{ id: time.Now().String(), mockServer: mockServer, }

	if domainsMap != nil {
		mockServer.Handler = &dnsMockHandler{domainsToAddresses: domainsMap}
	} else {
		mockServer.Handler = &dnsMockHandler{domainsToAddresses: DomainsToAddresses}
	}
	if domainsErrorMap != nil {
		mockServer.Handler.(*dnsMockHandler).domainsToErrors = domainsErrorMap
	}

	go func() {
		err := mockServer.ActivateAndServe()
		if err != nil {
			startResultChannel <- err
			return
		}
		startResultChannel <- nil
	}()
	select {
	case err := <-startResultChannel:
		if err != nil {
			close(startResultChannel)
			return handle, err
		}
	}

	defaultResolver := net.DefaultResolver
	mockResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, mockServer.PacketConn.LocalAddr().String())
		},
	}

	net.DefaultResolver = mockResolver

	handle.ShutdownDnsMock = func() error {
		net.DefaultResolver = defaultResolver
		return mockServer.Shutdown()
	}

	return handle, nil
}
