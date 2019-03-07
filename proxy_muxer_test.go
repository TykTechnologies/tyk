package main

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestMultiPortHTTP(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	t.Run("Multiple same port", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test1"
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test2"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test1", Code: 200},
			{Path: "/test2", Code: 200},
		}...)
	})

	t.Run("Multiple different port", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test1"
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test2"
			spec.ListenPort = 30001
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test1", Code: 200},
			{URI: "http://localhost:30001/test2", Code: 200},
		}...)
	})

	t.Run("Multiple different protocol, same port", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test1"
			spec.Protocol = "http"
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test2"
			spec.Protocol = "https"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test1", Code: 200},
			{Path: "/test2", Code: 404},
		}...)
	})

	t.Run("Multiple different protocol, different port", func(t *testing.T) {
		_, _, combinedPEM, _ := genServerCertificate()
		serverCertID, _ := CertificateManager.Add(combinedPEM, "")
		defer CertificateManager.Delete(serverCertID)

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test1"
			spec.Protocol = "http"
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test2"
			spec.Protocol = "https"
			spec.ListenPort = 30001
			spec.Certificates = []string{serverCertID}
		})

		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		}}}

		ts.Run(t, []test.TestCase{
			{Path: "/test1", Code: 200},
			{URI: "https://localhost:30001/test2", Client: client, Code: 200},
		}...)
	})

	t.Run("Multiple different protocol, different port, default https", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.UseSSL = true
		config.SetGlobal(globalConf)
		defer resetTestConfig()

		ts := newTykTestServer()
		defer ts.Close()

		_, _, combinedPEM, _ := genServerCertificate()
		serverCertID, _ := CertificateManager.Add(combinedPEM, "")
		defer CertificateManager.Delete(serverCertID)

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test1"
			spec.Certificates = []string{serverCertID}
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test2"
			spec.Protocol = "http"
			spec.ListenPort = 30001
		})

		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		}}}

		ts.Run(t, []test.TestCase{
			{Path: "/test1", Client: client, Code: 200},
			{URI: "http://localhost:30001/test2", Code: 200},
		}...)
	})
}

func TestTCPProxy(t *testing.T) {
	t.Run("TCP proxying", func(t *testing.T) {
		ts := newTykTestServer()
		defer ts.Close()
		// Echoing
		upstream := test.TcpMock(false, func(in []byte, err error) (out []byte) {
			return in
		})
		defer upstream.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Protocol = "tcp"
			spec.ListenPort = 30001
			spec.Proxy.TargetURL = "tcp://" + upstream.Addr().String()
		})

		runner := test.TCPTestRunner{
			Target: replacePort(ts.Addr, 30001),
		}

		runner.Run(t, []test.TCPTestCase{
			{"write", "ping", ""},
			{"read", "ping", ""},
		}...)
	})

	t.Run("TCP proxying with TLS target", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.ProxySSLInsecureSkipVerify = true
		config.SetGlobal(globalConf)
		defer resetTestConfig()

		ts := newTykTestServer()
		defer ts.Close()

		// With TLS
		upstream := test.TcpMock(true, func(in []byte, err error) (out []byte) {
			return in
		})
		defer upstream.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Protocol = "tcp"
			spec.ListenPort = 30001
			spec.Proxy.TargetURL = "tls://" + upstream.Addr().String()
		})

		runner := test.TCPTestRunner{
			Target: replacePort(ts.Addr, 30001),
		}

		runner.Run(t, []test.TCPTestCase{
			{"write", "ping", ""},
			{"read", "ping", ""},
		}...)
	})

	t.Run("TCP proxying, multiple services, SNI", func(t *testing.T) {
		_, _, combinedPEM, _ := genServerCertificate()
		serverCertID, _ := CertificateManager.Add(combinedPEM, "")
		defer CertificateManager.Delete(serverCertID)

		globalConf := config.Global()
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLCertificates = []string{serverCertID}
		globalConf.EnableCustomDomains = true
		config.SetGlobal(globalConf)
		defer resetTestConfig()

		ts := newTykTestServer()
		defer ts.Close()

		upstream1 := test.TcpMock(false, func(in []byte, err error) (out []byte) {
			return []byte("service1")
		})
		defer upstream1.Close()

		upstream2 := test.TcpMock(false, func(in []byte, err error) (out []byte) {
			return []byte("service2")
		})
		defer upstream2.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Protocol = "tls"
			spec.ListenPort = 30001
			spec.Domain = "service1"
			spec.Proxy.TargetURL = upstream1.Addr().String()
		}, func(spec *APISpec) {
			spec.Protocol = "tls"
			spec.ListenPort = 30001
			spec.Domain = "service2"
			spec.Proxy.TargetURL = upstream2.Addr().String()
		})

		t.Run("service1", func(t *testing.T) {
			test.TCPTestRunner{
				Target:   replacePort(ts.Addr, 30001),
				Hostname: "service1",
				UseSSL:   true,
			}.Run(t, []test.TCPTestCase{
				{"write", "ping", ""},
				{"read", "service1", ""},
			}...)
		})

		t.Run("service2", func(t *testing.T) {
			test.TCPTestRunner{
				Target:   replacePort(ts.Addr, 30001),
				Hostname: "service2",
				UseSSL:   true,
			}.Run(t, []test.TCPTestCase{
				{"write", "ping", ""},
				{"read", "service2", ""},
			}...)
		})

		t.Run("Without hostname", func(t *testing.T) {
			test.TCPTestRunner{
				Target: replacePort(ts.Addr, 30001),
				UseSSL: true,
			}.Run(t, []test.TCPTestCase{
				{"write", "ping", ""},
				{"read", "", "EOF"},
			}...)
		})
	})
}
