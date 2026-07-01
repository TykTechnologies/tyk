package httpclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

// Verifies: STK-REQ-094, SYS-REQ-182, SW-REQ-169
// SW-REQ-169:nominal:nominal
// SW-REQ-169:boundary:nominal
// SW-REQ-169:error_handling:nominal
// SW-REQ-169:encoding_safety:nominal
// SW-REQ-169:determinism:nominal
// SYS-REQ-182:determinism:nominal
// MCDC SYS-REQ-182: external_http_client_jwk_fetch_determined=T, external_http_client_mtls_error_classification_determined=T, external_http_client_mtls_loading_determined=T, external_http_client_proxy_selection_determined=T, external_http_client_service_client_determined=T, external_http_client_service_config_determined=T => TRUE
// MCDC SW-REQ-169: external_http_client_jwk_fetch_determined=T, external_http_client_mtls_error_classification_determined=T, external_http_client_mtls_loading_determined=T, external_http_client_proxy_selection_determined=T, external_http_client_service_client_determined=T, external_http_client_service_config_determined=T => TRUE
func TestExternalHTTPClientFactoryReqProof(t *testing.T) {
	factory := NewExternalHTTPClientFactory(&config.ExternalServiceConfig{
		Global: config.GlobalProxyConfig{
			Enabled:   true,
			HTTPProxy: "http://global-proxy:8080",
		},
		OAuth: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				Enabled:     true,
				HTTPProxy:   "http://oauth-proxy:8080",
				HTTPSProxy:  "https://oauth-secure-proxy:8443",
				BypassProxy: "localhost, internal.example.com",
			},
			MTLS: config.MTLSConfig{
				Enabled:            true,
				CertID:             "cert123",
				CACertIDs:          []string{"ca123"},
				InsecureSkipVerify: true,
			},
		},
		Webhooks: config.ServiceConfig{
			Proxy: config.ProxyConfig{Enabled: true},
		},
	}, &mockCertificateManager{
		certificates: map[string]*tls.Certificate{
			"cert123": createMockCertificate(),
		},
		caCertificates: []string{"ca123"},
	})

	require.True(t, factory.isServiceConfigured(config.ServiceTypeOAuth))
	require.True(t, factory.isServiceConfigured(config.ServiceTypeStorage))
	require.False(t, NewExternalHTTPClientFactory(&config.ExternalServiceConfig{}, nil).isServiceConfigured("unknown-without-global"))

	oauthConfig := factory.getServiceConfig(config.ServiceTypeOAuth)
	assert.Equal(t, "http://oauth-proxy:8080", oauthConfig.Proxy.HTTPProxy)

	storageConfig := factory.getServiceConfig(config.ServiceTypeStorage)
	assert.Equal(t, "http://global-proxy:8080", storageConfig.Proxy.HTTPProxy)

	client, err := factory.CreateOAuthClient()
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Equal(t, 15*time.Second, client.Timeout)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	require.Len(t, transport.TLSClientConfig.Certificates, 1)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
	assert.Equal(t, 50, transport.MaxIdleConns)
	assert.Equal(t, 10, transport.MaxIdleConnsPerHost)

	webhookClient, err := factory.CreateWebhookClient()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, webhookClient.Timeout)

	proxyFunc, err := factory.getProxyFunction(oauthConfig)
	require.NoError(t, err)
	require.NotNil(t, proxyFunc)

	req, err := http.NewRequest(http.MethodGet, "https://example.com/resource", nil)
	require.NoError(t, err)
	proxyURL, err := proxyFunc(req)
	require.NoError(t, err)
	require.NotNil(t, proxyURL)
	assert.Equal(t, "oauth-secure-proxy:8443", proxyURL.Host)

	bypassReq, err := http.NewRequest(http.MethodGet, "http://localhost/resource", nil)
	require.NoError(t, err)
	proxyURL, err = proxyFunc(bypassReq)
	require.NoError(t, err)
	assert.Nil(t, proxyURL)

	badFactory := NewExternalHTTPClientFactory(&config.ExternalServiceConfig{
		OAuth: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:  true,
				CertFile: "/missing/client.crt",
				KeyFile:  "/missing/client.key",
			},
		},
	}, nil)
	badClient, err := badFactory.CreateOAuthClient()
	require.Error(t, err)
	require.Nil(t, badClient)
	assert.True(t, IsMTLSError(err))
	assert.False(t, IsMTLSError(fmt.Errorf("not an mTLS error")))

	jwkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwkServer.Close()

	parsedBody := ""
	jwkSet, err := GetJWKWithClient(jwkServer.URL, jwkServer.Client(), func(body []byte) (*jose.JSONWebKeySet, error) {
		parsedBody = string(body)
		return &jose.JSONWebKeySet{}, nil
	})
	require.NoError(t, err)
	require.NotNil(t, jwkSet)
	assert.JSONEq(t, `{"keys":[]}`, parsedBody)
}
