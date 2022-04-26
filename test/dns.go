package test

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

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

type dnsMessageWriter func(*dns.Msg) error

type dnsMockHandler struct {
	domainsToAddresses map[string][]string
	domainsToErrors    map[string]int

	muDomainsToAddresses sync.RWMutex
}

func (d *dnsMockHandler) LookupHost(host string) (addrs []string, err error) {
	query := &dns.Msg{
		Question: []dns.Question{
			{
				Qtype: dns.TypeA,
				Name:  host,
			},
		},
	}

	var response *dns.Msg
	writeMsg := func(reply *dns.Msg) error {
		response = reply
		return nil
	}

	d.serveDNS(writeMsg, query)

	if response.Rcode != 0 {
		return nil, &net.DNSError{
			Err:    dns.RcodeToString[response.Rcode],
			Name:   host,
			Server: "mock",
		}
	}

	retval := make([]string, 0, len(response.Answer))
	for _, item := range response.Answer {
		answer, ok := item.(*dns.A)
		if !ok {
			return nil, &net.DNSError{
				Err:    fmt.Sprintf("unknown mock dns answer: %T", item),
				Name:   host,
				Server: "mock",
			}
		}
		retval = append(retval, answer.A.String())
	}
	return retval, nil
}

func (d *dnsMockHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	d.serveDNS(w.WriteMsg, r)
}

func (d *dnsMockHandler) serveDNS(writeMsg dnsMessageWriter, r *dns.Msg) {
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
			writeMsg(m)
			return
		}

		for _, ignore := range DomainsToIgnore {
			if strings.HasPrefix(domain, ignore) {
				resolver := &net.Resolver{}
				ipAddrs, err := resolver.LookupIPAddr(context.Background(), domain)
				if err != nil {
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeServerFailure)
					writeMsg(m)
					return
				}
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ipAddrs[0].IP,
				})
				writeMsg(&msg)
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
	writeMsg(&msg)
}

type DnsMockHandle struct {
	id         string
	mockServer *dns.Server

	Resolver *net.Resolver
	Dialer   *net.Dialer

	Shutdown   func() error
	LookupHost func(string) ([]string, error)
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

	dnsMux := &dnsMockHandler{}

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

	handle.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, network, mockServer.PacketConn.LocalAddr().String())
		},
	}

	handle.Dialer = &net.Dialer{
		Resolver: handle.Resolver,
	}

	handle.Shutdown = func() error {
		return mockServer.Shutdown()
	}

	handle.LookupHost = dnsMux.LookupHost

	return handle, nil
}

func IsDnsRecordsAddrsEqualsTo(itemAddrs, addrs []string) bool {
	return reflect.DeepEqual(itemAddrs, addrs)
}
