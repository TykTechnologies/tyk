package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/test"
)

// These integration tests exercise the end-to-end behaviour added by the
// embedded-PEM branch in tyk/certs/manager.go: each in-scope certificate
// field is populated with literal PEM content (rather than a SHA256 cert ID
// or a filesystem path), and the gateway must perform a successful TLS
// handshake without consulting Redis or disk.

// TestEmbeddedPEM_ClientCertificates verifies that spec.ClientCertificates
// (the mTLS client-cert allowlist) accepts an embedded PEM string.
// Exercises tyk/gateway/mw_certificate_check.go -> CertificateManager.List().
func TestEmbeddedPEM_ClientCertificates(t *testing.T) {
	serverCertPem, _, combinedServerPEM, _ := crypto.GenServerCertificate()

	conf := func(globalConf *config.Config) {
		globalConf.EnableCustomDomains = true
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLCertificates = []string{string(combinedServerPEM)}
		globalConf.HttpServerOptions.SkipClientCAAnnouncement = true
		globalConf.ProxySSLMaxVersion = tls.VersionTLS12
		globalConf.HttpServerOptions.MaxVersion = tls.VersionTLS12
	}
	ts := StartTest(conf)
	defer ts.Close()

	clientCertPem, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Domain = "localhost"
		spec.Proxy.ListenPath = "/"
		spec.UseMutualTLSAuth = true
		// Embedded PEM — no Add() call, no cert ID.
		spec.ClientCertificates = []string{string(clientCertPem)}
	})

	t.Run("client with embedded-PEM-pinned cert is accepted", func(t *testing.T) {
		tlsConfig := GetTLSConfig(&clientCert, serverCertPem)
		tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
		httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

		_, _ = ts.Run(t, test.TestCase{
			Code: http.StatusOK, Client: httpClient, Domain: "localhost",
		})
	})

	t.Run("client without cert is rejected", func(t *testing.T) {
		clientWithoutCert := GetTLSClient(nil, serverCertPem)
		_, _ = ts.Run(t, test.TestCase{
			ErrorMatch: noCertSkipAnnounceErr, Client: clientWithoutCert, Domain: "localhost",
		})
	})

	ts.Gw.CertificateManager.FlushCache()
	tlsConfigCache.Flush()
}

// TestEmbeddedPEM_UpstreamCertificates verifies that spec.UpstreamCertificates
// (the upstream mTLS domain-to-cert mapping) accepts an embedded PEM string.
// Exercises tyk/gateway/cert.go:getUpstreamCertificate -> List().
func TestEmbeddedPEM_UpstreamCertificates(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.dialCtxFn = test.LocalDialer()

	_, _, combinedClientPEM, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)
	clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf("request host is %s", r.Host)))
		w.WriteHeader(http.StatusOK)
	}))

	pool := x509.NewCertPool()
	pool.AddCert(clientCert.Leaf)
	upstream.TLS = &tls.Config{
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          pool,
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	}
	upstream.StartTLS()
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)

	globalConf := ts.Gw.GetConfig()
	globalConf.ProxySSLInsecureSkipVerify = true
	ts.Gw.SetConfig(globalConf)

	const targetHost = "host1.target"
	const proxyHost = "host2.proxy"

	api := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = fmt.Sprintf("https://%s:%s", targetHost, upstreamURL.Port())
		// Embedded PEM in the per-host map value — no Add() call.
		spec.UpstreamCertificates = map[string]string{
			"*.target:" + upstreamURL.Port(): string(combinedClientPEM),
		}
	})[0]

	ts.Gw.LoadAPI(api)

	_, _ = ts.Run(t, test.TestCase{
		Domain: proxyHost,
		BodyMatchFunc: func(b []byte) bool {
			return strings.Contains(string(b), targetHost)
		},
		Code:   http.StatusOK,
		Client: test.NewClientLocal(),
	})
}

// TestEmbeddedPEM_DomainCertificates verifies that spec.Certificates
// (per-API domain server cert) accepts an embedded PEM string.
// Exercises tyk/gateway/cert.go:getTLSConfigForClient -> List().
func TestEmbeddedPEM_DomainCertificates(t *testing.T) {
	conf := func(globalConf *config.Config) {
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.HttpServerOptions.SSLCertificates = []string{}
	}
	ts := StartTest(conf)
	defer ts.Close()

	_, _, combinedPEM, _ := crypto.GenServerCertificate()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	}}}

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		// Embedded PEM for the API's TLS-termination cert.
		spec.Certificates = []string{string(combinedPEM)}
	})

	_, _ = ts.Run(t, test.TestCase{Code: http.StatusOK, Client: client})

	ts.Gw.CertificateManager.FlushCache()
	tlsConfigCache.Flush()
}

// TestEmbeddedPEM_GlobalSSLCertificates verifies that the global
// HttpServerOptions.SSLCertificates list accepts an embedded PEM string.
// Exercises tyk/gateway/cert.go:certHandler -> List().
func TestEmbeddedPEM_GlobalSSLCertificates(t *testing.T) {
	_, _, combinedPEM, _ := crypto.GenServerCertificate()

	conf := func(globalConf *config.Config) {
		globalConf.HttpServerOptions.UseSSL = true
		// Embedded PEM directly in the gateway-wide TLS cert list.
		globalConf.HttpServerOptions.SSLCertificates = []string{string(combinedPEM)}
	}
	ts := StartTest(conf)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})

	client := GetTLSClient(nil, nil)
	_, _ = ts.Run(t, test.TestCase{Code: http.StatusOK, Client: client})

	ts.Gw.CertificateManager.FlushCache()
	tlsConfigCache.Flush()
}

// TestEmbeddedPEM_ControlAPIClientCAs verifies that Security.Certificates.ControlAPI
// (the client-CA pool used by the management API's mTLS) accepts an embedded
// PEM string. Exercises tyk/gateway/cert.go -> CertPool() -> List(), and so
// covers the CertPool entry point in addition to List().
func TestEmbeddedPEM_ControlAPIClientCAs(t *testing.T) {
	serverCertPem, _, combinedServerPEM, _ := crypto.GenServerCertificate()
	clientCertPem, _, _, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)

	conf := func(globalConf *config.Config) {
		globalConf.HttpServerOptions.UseSSL = true
		globalConf.Security.ControlAPIUseMutualTLS = true
		globalConf.ControlAPIHostname = "localhost"
		// Embedded PEM for the server cert AND for the control-API client-CA pool.
		globalConf.HttpServerOptions.SSLCertificates = []string{string(combinedServerPEM)}
		globalConf.Security.Certificates.ControlAPI = []string{string(clientCertPem)}
	}
	ts := StartTest(conf)
	defer ts.Close()
	ts.ReloadGatewayProxy()

	defer func() {
		ts.Gw.CertificateManager.FlushCache()
		tlsConfigCache.Flush()
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SSLCertificates = nil
		globalConf.Security.Certificates.ControlAPI = nil
		ts.Gw.SetConfig(globalConf)
	}()

	clientWithCert := GetTLSClient(&clientCert, serverCertPem)

	_, _ = ts.Run(t, test.TestCase{
		Path:           "/tyk/certs",
		Code:           http.StatusOK,
		ControlRequest: true,
		AdminAuth:      true,
		Client:         clientWithCert,
	})
}

// TestEmbeddedPEM_BackwardCompatibility is a focused regression check: a
// single subtest table that runs the same hot path (List() resolving a
// server cert) via all three sources — embedded PEM, SHA256 cert ID, file
// path — proving they coexist in the same code path.
func TestEmbeddedPEM_BackwardCompatibility(t *testing.T) {
	_, _, combinedPEM, _ := crypto.GenServerCertificate()

	ts := StartTest(nil)
	defer ts.Close()

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "")
	require.NoError(t, err)
	defer ts.Gw.CertificateManager.Delete(certID, "")

	tmp := t.TempDir()
	filePath := filepath.Join(tmp, "cert.pem")
	require.NoError(t, os.WriteFile(filePath, combinedPEM, 0o600))

	cases := []struct {
		name string
		id   string
	}{
		{"file path", filePath},
		{"cert ID", certID},
		{"embedded PEM", string(combinedPEM)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts.Gw.CertificateManager.FlushCache()
			out := ts.Gw.CertificateManager.List([]string{tc.id}, certs.CertificateAny)
			require.Len(t, out, 1)
			require.NotNil(t, out[0], "cert lookup for %s returned nil", tc.name)
			assert.NotEmpty(t, out[0].Certificate, "expected cert chain to be populated")
		})
	}
}
