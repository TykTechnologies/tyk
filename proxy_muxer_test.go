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
			spec.Proxy.ListenPort = 30001
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test1", Code: 200},
			{URI: "http://localhost:30001/test2", Code: 200},
		}...)
	})

	t.Run("Multiple different protocol, same port", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test1"
			spec.Proxy.Protocol = "http"
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test2"
			spec.Proxy.Protocol = "https"
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
			spec.Proxy.Protocol = "http"
		}, func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test2"
			spec.Proxy.Protocol = "https"
			spec.Proxy.ListenPort = 30001
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
			spec.Proxy.Protocol = "http"
			spec.Proxy.ListenPort = 30001
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
