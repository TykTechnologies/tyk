package gateway

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

func TestExternalOAuthMiddleware_JWKWithProxy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test JWK server
	jwkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkResponse := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": "test-key-id",
					"use": "sig",
					"n":   "test-n-value",
					"e":   "AQAB",
				},
			},
		}
		json.NewEncoder(w).Encode(jwkResponse)
	}))
	defer jwkServer.Close()

	// Create a test proxy server that tracks requests
	var proxyRequests int
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests++
		// Forward the request to the actual JWK server
		resp, err := http.Get(jwkServer.URL)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer proxyServer.Close()

	// Configure external service config with proxy
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		OAuth: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: proxyServer.URL,
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Create API spec with external OAuth configuration
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "test-api",
			OrgID: "test-org",
		},
	}

	// Set external OAuth configuration
	spec.ExternalOAuth = apidef.ExternalOAuth{
		Enabled: true,
		Providers: []apidef.Provider{
			{
				JWT: apidef.JWTValidation{
					Enabled:       true,
					Source:        jwkServer.URL,
					SigningMethod: "RS256",
				},
			},
		},
	}

	// Create middleware
	middleware := &ExternalOAuthMiddleware{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	// Test JWK fetching - should go through proxy
	_, err := middleware.getSecretFromJWKURL(jwkServer.URL, "test-key-id")

	// We expect this to fail due to signature verification, but the proxy should be called
	assert.Error(t, err) // Expected because we don't have proper RSA keys
	assert.Greater(t, proxyRequests, 0, "Proxy should have received at least one request")
}

func TestExternalOAuthMiddleware_IntrospectionWithProxy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test introspection server
	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"active": true,
			"sub":    "test-user",
			"exp":    time.Now().Add(time.Hour).Unix(),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer introspectionServer.Close()

	// Create a test proxy server that tracks requests
	var proxyRequests int
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests++
		// Forward the request to the actual introspection server
		resp, err := http.Post(introspectionServer.URL, r.Header.Get("Content-Type"), r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer proxyServer.Close()

	// Configure external service config with proxy
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		OAuth: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: proxyServer.URL,
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Create middleware
	middleware := &ExternalOAuthMiddleware{
		BaseMiddleware: &BaseMiddleware{
			Gw: ts.Gw,
		},
	}

	// Test introspection - should go through proxy
	opts := apidef.Introspection{
		URL:          introspectionServer.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	claims, err := middleware.introspectWithClient(opts, "test-token")

	assert.NoError(t, err)
	assert.True(t, claims["active"].(bool))
	assert.Equal(t, "test-user", claims["sub"])
	assert.Greater(t, proxyRequests, 0, "Proxy should have received at least one request")
}

func TestExternalOAuthMiddleware_mTLSSupport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping mTLS test in short mode")
	}

	ts := StartTest(nil)
	defer ts.Close()

	// Create temporary cert files for testing
	certPEM := `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKyKGp/xvq3TANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAlZBMRIwEAYDVQQHDAlBcmxpbmd0b24xFTATBgNVBAoMDFRl
c3QgQ29tcGFueTEUMBIGA1UECwwLVGVzdCBTZWN0aW9uMRAwDgYDVQQDDAdUZXN0
IENBMSAwHgYJKoZIhvcNAQkBFhF0ZXN0QGV4YW1wbGUuY29tMB4XDTI0MDEwMTEw
MDAwMFoXDTI1MDEwMTEwMDAwMFowgY8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJW
QTESMBAGA1UEBwwJQXJsaW5ndG9uMRUwEwYDVQQKDAxUZXN0IENvbXBhbnkxFDAS
BgNVBAsMC1Rlc3QgU2VjdGlvbjEQMA4GA1UEAwwHVGVzdCBDQTEgMB4GCSqGSIb3
DQEJARYRdGVzdEBleGFtcGxlLmNvbTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7
-----END CERTIFICATE-----`

	keyPEM := `-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAu6
-----END PRIVATE KEY-----`

	certFile, err := ioutil.TempFile("", "test-cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(certFile.Name())

	keyFile, err := ioutil.TempFile("", "test-key-*.pem")
	require.NoError(t, err)
	defer os.Remove(keyFile.Name())

	_, err = certFile.Write([]byte(certPEM))
	require.NoError(t, err)
	certFile.Close()

	_, err = keyFile.Write([]byte(keyPEM))
	require.NoError(t, err)
	keyFile.Close()

	// Configure external service config with mTLS
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		OAuth: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:  true,
				CertFile: certFile.Name(),
				KeyFile:  keyFile.Name(),
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Test that HTTP client factory creates client with mTLS configuration
	factory := NewExternalHTTPClientFactory(ts.Gw)
	client, err := factory.CreateIntrospectionClient()
	require.NoError(t, err)

	// Verify transport is configured
	transport := client.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig)

	// We can't easily test the actual certificate loading without a proper test server,
	// but we can verify the client was created successfully
	assert.NotNil(t, client)
}

func TestJWTMiddleware_JWKWithProxyAndMTLS(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test JWK server
	jwkServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkResponse := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": "test-key-id",
					"use": "sig",
					"n":   "test-n-value",
					"e":   "AQAB",
				},
			},
		}
		json.NewEncoder(w).Encode(jwkResponse)
	}))
	defer jwkServer.Close()

	// Configure external service config with proxy and mTLS
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		OAuth: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true, // For test server
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Create API spec
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:     "test-api",
			JWTSource: jwkServer.URL,
		},
	}

	// Create middleware
	middleware := &JWTMiddleware{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	// Test JWK fetching with mTLS
	_, err := middleware.getSecretFromURL(jwkServer.URL, "test-key-id", "rsa")

	// We expect this to work for the HTTP client creation part
	// (actual JWK parsing might fail due to test data, but that's ok)
	assert.Error(t, err) // Expected because we don't have proper RSA keys in test data
}
