package tcp

import (
	"crypto/tls"
	"net"
	"reflect"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

func TestProxyModifier(t *testing.T) {
	// Echoing
	upstream := test.TcpMock(false, func(in []byte, err error) (out []byte) {
		return in
	})
	defer upstream.Close()

	t.Run("Without modifier", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", upstream.Addr().String(), nil)

		testRunner(t, proxy, "", false, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "ping"},
		}...)
	})

	t.Run("Modify response", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", upstream.Addr().String(), &Modifier{
			ModifyResponse: func(src, dst net.Conn, data []byte) ([]byte, error) {
				return []byte("pong"), nil
			},
		})

		testRunner(t, proxy, "", false, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "pong"},
		}...)
	})

	t.Run("Mock request", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", upstream.Addr().String(), &Modifier{
			ModifyRequest: func(src, dst net.Conn, data []byte) ([]byte, error) {
				return []byte("pong"), nil
			},
		})

		testRunner(t, proxy, "", false, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "pong"},
		}...)
	})
}
func TestProxySyncStats(t *testing.T) {
	// Echoing
	upstream := test.TcpMock(false, func(in []byte, err error) (out []byte) {
		return in
	})
	defer upstream.Close()
	stats := make(chan Stat)
	proxy := &Proxy{SyncStats: func(s Stat) {
		stats <- s
		if s.State == Closed {
			close(stats)
		}
	}}
	proxy.AddDomainHandler("", upstream.Addr().String(), nil)

	testRunner(t, proxy, "", false, []test.TCPTestCase{
		{Action: "write", Payload: "ping"},
		{Action: "read", Payload: "ping"},
	}...)
	var c []Stat
	for s := range stats {
		c = append(c, s)
	}
	expect := []Stat{
		{State: Open},
		{State: Closed, BytesIn: 4, BytesOut: 4},
	}
	if len(c) != len(expect) {
		t.Fatalf("expected %d stats got %d stats", len(expect), len(c))
	}
	if !reflect.DeepEqual(c, expect) {
		t.Errorf("expected %#v got %#v", expect, c)
	}
}

func TestProxyMultiTarget(t *testing.T) {
	target1 := test.TcpMock(false, func(in []byte, err error) (out []byte) {
		return []byte("first")
	})
	defer target1.Close()

	target2 := test.TcpMock(false, func(in []byte, err error) (out []byte) {
		return []byte("second")
	})
	defer target2.Close()

	t.Run("Single_target, no SNI", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", target1.Addr().String(), nil)

		testRunner(t, proxy, "", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "first"},
		}...)
	})

	t.Run("Single target, SNI, without domain", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", target1.Addr().String(), nil)

		testRunner(t, proxy, "localhost", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "first"},
		}...)
	})

	t.Run("Single target, SNI, domain match", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)

		testRunner(t, proxy, "localhost", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "first"},
		}...)
	})

	t.Run("Single target, SNI, domain not match", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)

		// Should cause `Can't detect service based on provided SNI information: example.com`
		testRunner(t, proxy, "example.com", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", ErrorMatch: "EOF"},
		}...)
	})

	t.Run("Multiple targets, No SNI", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)
		proxy.AddDomainHandler("example.com", target2.Addr().String(), nil)

		// Should cause `Multiple services on different domains running on the same port, but no SNI (domain) information from client
		testRunner(t, proxy, "", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", ErrorMatch: "EOF"},
		}...)
	})

	t.Run("Multiple targets, SNI", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)
		proxy.AddDomainHandler("example.com", target2.Addr().String(), nil)

		testRunner(t, proxy, "localhost", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "first"},
		}...)

		testRunner(t, proxy, "example.com", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "second"},
		}...)

		testRunner(t, proxy, "wrong", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", ErrorMatch: "EOF"},
		}...)
	})

	t.Run("Multiple targets, SNI with fallback", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", target1.Addr().String(), nil)
		proxy.AddDomainHandler("example.com", target2.Addr().String(), nil)

		testRunner(t, proxy, "example.com", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "second"},
		}...)

		// Should fallback to target defined with empty domain
		testRunner(t, proxy, "wrong", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "first"},
		}...)
	})
}

func testRunner(t *testing.T, proxy *Proxy, hostname string, useSSL bool, testCases ...test.TCPTestCase) {
	var proxyLn net.Listener
	var err error

	if useSSL {
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{test.Cert("localhost")},
			InsecureSkipVerify: true,
		}
		tlsConfig.BuildNameToCertificate()
		proxyLn, err = tls.Listen("tcp", ":0", tlsConfig)

		if err != nil {
			t.Fatalf(err.Error())
			return
		}
	} else {
		proxyLn, _ = net.Listen("tcp", ":0")
	}
	defer proxyLn.Close()

	go proxy.Serve(proxyLn)

	runner := test.TCPTestRunner{
		Target:   proxyLn.Addr().String(),
		UseSSL:   useSSL,
		Hostname: hostname,
	}
	runner.Run(t, testCases...)
}
