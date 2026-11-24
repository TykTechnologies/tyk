package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	tykcrypto "github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/test"
)

// unknownPinID looks like a certificate ID but is not in the certificate store.
var unknownPinID = strings.Repeat("a", 64)

func pinningSpec(pins map[string]string) *APISpec {
	return &APISpec{APIDefinition: &apidef.APIDefinition{PinnedPublicKeys: pins}}
}

func TestGetPinnedPublicKeys(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	_, _, _, apiCert := certs.GenServerCertificate()
	apiKeyID, err := ts.Gw.uploadCertPublicKey(apiCert)
	require.NoError(t, err)

	_, _, _, globalCert := certs.GenServerCertificate()
	globalKeyID, err := ts.Gw.uploadCertPublicKey(globalCert)
	require.NoError(t, err)

	testCases := []struct {
		name           string
		host           string
		globalPins     map[string]string
		apiPins        map[string]string
		apiDisabled    bool
		wantKeys       []string
		wantConfigured bool
	}{
		{
			name:     "no pins",
			host:     "api.example.com",
			wantKeys: nil,
		},
		{
			name:     "pin for another host",
			host:     "api.example.com",
			apiPins:  map[string]string{"other.example.com": apiKeyID},
			wantKeys: nil,
		},
		{
			name:           "exact host",
			host:           "api.example.com",
			apiPins:        map[string]string{"api.example.com": apiKeyID},
			wantKeys:       []string{apiKeyID},
			wantConfigured: true,
		},
		{
			name:           "parent domain wildcard",
			host:           "api.example.com",
			apiPins:        map[string]string{"*.example.com": apiKeyID},
			wantKeys:       []string{apiKeyID},
			wantConfigured: true,
		},
		{
			name:           "catch-all",
			host:           "api.example.com",
			apiPins:        map[string]string{"*": apiKeyID},
			wantKeys:       []string{apiKeyID},
			wantConfigured: true,
		},
		{
			name:           "exact host wins over wildcard and catch-all",
			host:           "api.example.com",
			apiPins:        map[string]string{"*": globalKeyID, "*.example.com": globalKeyID, "api.example.com": apiKeyID},
			wantKeys:       []string{apiKeyID},
			wantConfigured: true,
		},
		{
			name:           "API pin wins over gateway-wide pin",
			host:           "api.example.com",
			globalPins:     map[string]string{"api.example.com": globalKeyID},
			apiPins:        map[string]string{"api.example.com": apiKeyID},
			wantKeys:       []string{apiKeyID},
			wantConfigured: true,
		},
		{
			name:           "gateway-wide pin applies when the API has none",
			host:           "api.example.com",
			globalPins:     map[string]string{"api.example.com": globalKeyID},
			wantKeys:       []string{globalKeyID},
			wantConfigured: true,
		},
		{
			name:           "API pins ignored when pinning is disabled for the API",
			host:           "api.example.com",
			globalPins:     map[string]string{"api.example.com": globalKeyID},
			apiPins:        map[string]string{"api.example.com": apiKeyID},
			apiDisabled:    true,
			wantKeys:       []string{globalKeyID},
			wantConfigured: true,
		},
		{
			name:           "several key IDs",
			host:           "api.example.com",
			apiPins:        map[string]string{"api.example.com": apiKeyID + "," + globalKeyID},
			wantKeys:       []string{apiKeyID, globalKeyID},
			wantConfigured: true,
		},
		{
			name:           "pinned with an empty value",
			host:           "api.example.com",
			apiPins:        map[string]string{"api.example.com": ""},
			wantKeys:       nil,
			wantConfigured: true,
		},
		{
			name:           "pinned to an unknown key ID",
			host:           "api.example.com",
			apiPins:        map[string]string{"api.example.com": unknownPinID},
			wantKeys:       []string{""},
			wantConfigured: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := config.Config{}
			conf.Security.PinnedPublicKeys = tc.globalPins

			spec := pinningSpec(tc.apiPins)
			spec.CertificatePinningDisabled = tc.apiDisabled

			keys, configured := ts.Gw.getPinnedPublicKeys(tc.host, spec, conf)

			assert.Equal(t, tc.wantKeys, keys)
			assert.Equal(t, tc.wantConfigured, configured)
		})
	}

	t.Run("nil spec uses gateway-wide pins only", func(t *testing.T) {
		conf := config.Config{}
		conf.Security.PinnedPublicKeys = map[string]string{"*": globalKeyID}

		keys, configured := ts.Gw.getPinnedPublicKeys("api.example.com", nil, conf)

		assert.Equal(t, []string{globalKeyID}, keys)
		assert.True(t, configured)
	})
}

// storePublicKey stores cert's public key in the certificate store and returns
// its ID. Every httptest server shares one built-in certificate, so another
// test may already have stored it.
func storePublicKey(t *testing.T, gw *Gateway, cert *x509.Certificate) string {
	t.Helper()

	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)

	if _, err := gw.CertificateManager.Add(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), ""); err != nil {
		require.Contains(t, err.Error(), "already exists")
	}

	keyID := tykcrypto.HexSHA256(pubDER)
	require.Equal(t, []string{keyID}, gw.CertificateManager.ListPublicKeys([]string{keyID}))

	return keyID
}

// assertConnResult closes conn when the connection succeeded and checks err
// against wantErr.
func assertConnResult(t *testing.T, conn io.Closer, err error, wantErr bool) {
	t.Helper()

	if err == nil {
		_ = conn.Close()
	}

	if wantErr {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}

// TestUpstreamCertificatePinning covers TT-18123: configuring certificate
// pinning must never weaken TLS verification for an upstream host that the
// pins do not cover, and a pin entry with an empty value must reject.
func TestUpstreamCertificatePinning(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	defer ts.ResetTestConfig()

	// The httptest certificate is valid for 127.0.0.1, so adding it to
	// RootCAs makes the upstream fully trusted, including the hostname check.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()

	upstreamAddr := upstream.Listener.Addr().String()

	trusted := x509.NewCertPool()
	trusted.AddCert(upstream.Certificate())

	upstreamKeyID := storePublicKey(t, ts.Gw, upstream.Certificate())

	_, _, _, otherCert := certs.GenServerCertificate()
	otherKeyID, err := ts.Gw.uploadCertPublicKey(otherCert)
	require.NoError(t, err)

	setGlobalPins := func(t *testing.T, pins map[string]string) {
		t.Helper()
		conf := ts.Gw.GetConfig()
		conf.Security.PinnedPublicKeys = pins
		ts.Gw.SetConfig(conf)
		t.Cleanup(func() {
			conf := ts.Gw.GetConfig()
			conf.Security.PinnedPublicKeys = nil
			ts.Gw.SetConfig(conf)
		})
	}

	t.Run("direct dial", func(t *testing.T) {
		testCases := []struct {
			name       string
			globalPins map[string]string
			apiPins    map[string]string
			tlsConfig  *tls.Config
			wantErr    bool
		}{
			{
				name:      "pinned key matches, untrusted certificate",
				apiPins:   map[string]string{"127.0.0.1": upstreamKeyID},
				tlsConfig: &tls.Config{RootCAs: x509.NewCertPool()},
			},
			{
				name:      "pinned key does not match",
				apiPins:   map[string]string{"127.0.0.1": otherKeyID},
				tlsConfig: &tls.Config{RootCAs: trusted},
				wantErr:   true,
			},
			{
				name:      "pin for another host, untrusted certificate",
				apiPins:   map[string]string{"other.example.com": otherKeyID},
				tlsConfig: &tls.Config{RootCAs: x509.NewCertPool()},
				wantErr:   true,
			},
			{
				name:      "pin for another host, trusted certificate",
				apiPins:   map[string]string{"other.example.com": otherKeyID},
				tlsConfig: &tls.Config{RootCAs: trusted},
			},
			{
				name:      "pin for another host, verification skipped by the operator",
				apiPins:   map[string]string{"other.example.com": otherKeyID},
				tlsConfig: &tls.Config{RootCAs: x509.NewCertPool(), InsecureSkipVerify: true},
			},
			{
				name:       "gateway-wide pin for another host, untrusted certificate",
				globalPins: map[string]string{"other.example.com": otherKeyID},
				tlsConfig:  &tls.Config{RootCAs: x509.NewCertPool()},
				wantErr:    true,
			},
			{
				name:      "pinned to an unknown key ID",
				apiPins:   map[string]string{"127.0.0.1": unknownPinID},
				tlsConfig: &tls.Config{RootCAs: trusted},
				wantErr:   true,
			},
			{
				name:      "pinned with an empty value",
				apiPins:   map[string]string{"127.0.0.1": ""},
				tlsConfig: &tls.Config{RootCAs: x509.NewCertPool()},
				wantErr:   true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				setGlobalPins(t, tc.globalPins)

				dial := ts.Gw.customDialTLSCheck(pinningSpec(tc.apiPins), tc.tlsConfig)
				require.NotNil(t, dial, "pinning is configured, so a custom dialer is expected")

				conn, err := dial("tcp", upstreamAddr)
				assertConnResult(t, conn, err, tc.wantErr)
			})
		}

		t.Run("pinning disabled for the API", func(t *testing.T) {
			spec := pinningSpec(map[string]string{"127.0.0.1": otherKeyID})
			spec.CertificatePinningDisabled = true

			assert.Nil(t, ts.Gw.customDialTLSCheck(spec, &tls.Config{}))
		})
	})

	// verifyPeerCertificatePinnedCheck is used when upstream traffic goes
	// through an HTTP proxy. These cases run a real handshake with the
	// tls.Config it prepares, so they check the outcome, not the wiring.
	t.Run("through an upstream proxy", func(t *testing.T) {
		testCases := []struct {
			name      string
			apiPins   map[string]string
			tlsConfig *tls.Config
			wantErr   bool
		}{
			{
				name:      "catch-all pin matches, untrusted certificate",
				apiPins:   map[string]string{"*": upstreamKeyID},
				tlsConfig: &tls.Config{RootCAs: x509.NewCertPool()},
			},
			{
				name:      "catch-all pin does not match",
				apiPins:   map[string]string{"*": otherKeyID},
				tlsConfig: &tls.Config{RootCAs: trusted},
				wantErr:   true,
			},
			{
				name:      "per-host pin only, untrusted certificate",
				apiPins:   map[string]string{"127.0.0.1": upstreamKeyID},
				tlsConfig: &tls.Config{RootCAs: x509.NewCertPool()},
				wantErr:   true,
			},
			{
				name:      "per-host pin only, trusted certificate",
				apiPins:   map[string]string{"127.0.0.1": otherKeyID},
				tlsConfig: &tls.Config{RootCAs: trusted},
			},
			{
				name:      "catch-all pinned to an unknown key ID",
				apiPins:   map[string]string{"*": unknownPinID},
				tlsConfig: &tls.Config{RootCAs: trusted},
				wantErr:   true,
			},
			{
				name:      "catch-all pinned with an empty value",
				apiPins:   map[string]string{"*": ""},
				tlsConfig: &tls.Config{RootCAs: x509.NewCertPool()},
				wantErr:   true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cfg := tc.tlsConfig
				cfg.VerifyPeerCertificate = ts.Gw.verifyPeerCertificatePinnedCheck(pinningSpec(tc.apiPins), cfg)

				conn, err := tls.Dial("tcp", upstreamAddr, cfg)
				assertConnResult(t, conn, err, tc.wantErr)
			})
		}
	})
}

// TestUpstreamCertificatePinning_Proxy runs the TT-18123 cases end to end
// through the Gateway. The Gateway uses the system roots for upstreams, so
// only cases that reject an untrusted certificate, or that the operator
// explicitly allows, can be checked here; the unit cases above cover a
// trusted upstream.
func TestUpstreamCertificatePinning_Proxy(t *testing.T) {
	_, _, _, serverCert := certs.GenServerCertificate()

	t.Run("API pin for another host", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ProxySSLInsecureSkipVerify = false
		})
		defer ts.Close()

		upstream, _, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.PinnedPublicKeys = map[string]string{"other.example.com": unknownPinID}
		})

		_, _ = ts.Run(t, test.TestCase{Code: http.StatusInternalServerError})
	})

	t.Run("API pin for another host, verification skipped by the operator", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ProxySSLInsecureSkipVerify = true
		})
		defer ts.Close()

		upstream, _, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.PinnedPublicKeys = map[string]string{"other.example.com": unknownPinID}
		})

		_, _ = ts.Run(t, test.TestCase{Code: http.StatusOK})
	})

	t.Run("gateway-wide pin for another host", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ProxySSLInsecureSkipVerify = false
			globalConf.Security.PinnedPublicKeys = map[string]string{"other.example.com": unknownPinID}
		})
		defer ts.Close()

		upstream, _, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
		})

		_, _ = ts.Run(t, test.TestCase{Code: http.StatusInternalServerError})
	})

	t.Run("API pin with an empty value", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ProxySSLInsecureSkipVerify = false
		})
		defer ts.Close()

		upstream, _, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.PinnedPublicKeys = map[string]string{"127.0.0.1": ""}
		})

		_, _ = ts.Run(t, test.TestCase{Code: http.StatusInternalServerError})
	})

	t.Run("per-host pin through an upstream proxy", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ProxySSLInsecureSkipVerify = false
		})
		defer ts.Close()

		upstream, upstreamKeyID, finish := newUpstreamSSL(t, ts.Gw, serverCert, handlerEmpty)
		defer finish()

		proxy := initProxy("http", nil)
		defer func() {
			assert.NoError(t, proxy.Stop(ts))
		}()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
			spec.Proxy.Transport.ProxyURL = proxy.URL
			spec.PinnedPublicKeys = map[string]string{"127.0.0.1": upstreamKeyID}
		})

		_, _ = ts.Run(t, test.TestCase{Code: http.StatusInternalServerError})
	})
}

func TestHasHostPins(t *testing.T) {
	testCases := []struct {
		name        string
		globalPins  map[string]string
		apiPins     map[string]string
		apiDisabled bool
		want        bool
	}{
		{name: "no pins"},
		{name: "catch-all only", apiPins: map[string]string{"*": "id"}},
		{name: "API host pin", apiPins: map[string]string{"api.example.com": "id"}, want: true},
		{name: "API wildcard pin", apiPins: map[string]string{"*.example.com": "id"}, want: true},
		{name: "gateway-wide host pin", globalPins: map[string]string{"api.example.com": "id"}, want: true},
		{name: "API host pin with pinning disabled", apiPins: map[string]string{"api.example.com": "id"}, apiDisabled: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := config.Config{}
			conf.Security.PinnedPublicKeys = tc.globalPins

			spec := pinningSpec(tc.apiPins)
			spec.CertificatePinningDisabled = tc.apiDisabled

			assert.Equal(t, tc.want, hasHostPins(spec, conf))
		})
	}

	assert.False(t, hasHostPins(nil, config.Config{}))
}
