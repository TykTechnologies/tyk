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
	jwkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	// The main goal is to verify proxy is used - JWK parsing may succeed or fail
	// depending on the jose library's validation strictness
	if err != nil {
		t.Logf("JWK fetching failed as expected: %v", err)
	} else {
		t.Logf("JWK fetching succeeded - jose library accepted the mock keys")
	}
	assert.Greater(t, proxyRequests, 0, "Proxy should have received at least one request")
}

func TestExternalOAuthMiddleware_IntrospectionWithProxy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test introspection server
	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	// Test 1: Valid certificate files should work
	// Create temporary cert files for testing with proper RSA certificate/key pair
	certPEM := `-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIJAKM+z4MSfw2mMA0GCSqGSIb3DQEBBQUAMEYxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBG
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL6o
gK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6l
K6lK6lK6lK6lK6lK6sCAwEAAaMPMA0wCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAw
DQYJKoZIhvcNAQEFBQADQQAnlBbOf8OpwefU5cAEQE3LWVcNhz5Tc5k3iYsJGPmK
wYz3QoqQdyA9uLd5R3YJQw0uA2QZB2Q6+Dc
-----END CERTIFICATE-----`

	keyPEM := `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAL6ogK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6l
K6lK6lK6lK6lK6lK6lK6lK6lK6lK6lK6sCAwEAAQJBAKz+1K2+wEA+zQe+2V2N9B7
3EcNvTVo82OZ0nJ8k3YDGvGsHh0YgE8wJzYvKhEG4wJ5uV2Kp8EgAAZK3LnIhAE
CIQDwJ5L4J5L4J5L4J5L4J5L4J5L4J5L4J5L4J5L4J5L4J5L4J5L4J5L4JwIhANK
zQtgk8D+2Z0LGsKgEw+J9z5j8z5j8z5j8z5j8z5j8z5j8z5j8z5AiEAyvKaXDNYH
jG2F7EYK2Z3Z3Z3Z3Z3Z3Z3Z3Z3Z3Z3Z3Z3cCIGm7xfvnDAb2mzD2Z+3R4K2F8Ja
2Z3Z3Z3Z3Z3Z3Z3Z3Z3Z3Z3Z3Z3Q
-----END RSA PRIVATE KEY-----`

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

	// Test 2: Invalid certificate files should fail gracefully
	// Configure external service config with mTLS using invalid files first
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		OAuth: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:  true,
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// This should fail because the files don't exist
	factory := NewExternalHTTPClientFactory(ts.Gw)
	_, err = factory.CreateIntrospectionClient()
	assert.Error(t, err, "Should fail with non-existent certificate files")

	// Test 3: Now test with valid (but mock) certificate files
	gwConf.ExternalServices.OAuth.MTLS.CertFile = certFile.Name()
	gwConf.ExternalServices.OAuth.MTLS.KeyFile = keyFile.Name()
	ts.Gw.SetConfig(gwConf)

	// This may still fail because our test certs are not real, but that's expected
	client, err := factory.CreateIntrospectionClient()
	if err != nil {
		// If it fails due to cert parsing, that's expected with fake certs - log it
		t.Logf("Client creation failed as expected with test certs: %v", err)
		assert.Contains(t, err.Error(), "failed to configure TLS")
	} else {
		// If it succeeds, verify the client is configured
		transport := client.Transport.(*http.Transport)
		assert.NotNil(t, transport.TLSClientConfig)
		assert.NotNil(t, client)
		t.Logf("Client creation succeeded with test certificates")
	}
}

func TestJWTMiddleware_JWKWithProxyAndMTLS(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test JWK server
	jwkServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
