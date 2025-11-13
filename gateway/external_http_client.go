package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpclient"
	"github.com/go-jose/go-jose/v3"
)

// ExternalHTTPClientFactory creates HTTP clients for external service interactions
// with support for proxy configuration and mTLS client certificates.
type ExternalHTTPClientFactory struct {
	factory *httpclient.ExternalHTTPClientFactory
}

// NewExternalHTTPClientFactory creates a new HTTP client factory.
func NewExternalHTTPClientFactory(gw *Gateway) *ExternalHTTPClientFactory {
	gwConfig := gw.GetConfig()
	factory := httpclient.NewExternalHTTPClientFactory(&gwConfig.ExternalServices, gw.CertificateManager)
	return &ExternalHTTPClientFactory{
		factory: factory,
	}
}

// CreateClient creates an HTTP client configured for the specified service type.
// It applies proxy settings and mTLS configuration based on the service configuration hierarchy:
// 1. Service-specific configuration
// 2. Global configuration
// 3. Environment variables (for proxy)
// 4. Default settings
func (f *ExternalHTTPClientFactory) CreateClient(serviceType string) (*http.Client, error) {
	log.Debugf("[ExternalServices] Creating HTTP client for service type: %s", serviceType)

	client, err := f.factory.CreateClient(serviceType)
	if err != nil {
		return nil, err
	}

	log.Debugf("[ExternalServices] HTTP client for %s created with timeout: %v", serviceType, client.Timeout)
	return client, nil
}

// CreateJWKClient creates an HTTP client specifically configured for JWK endpoint requests.
// This method requires external services OAuth configuration to be set up and will fail if not configured.
// Callers should fall back to getJWK() function if this method returns an error.
func (f *ExternalHTTPClientFactory) CreateJWKClient() (*http.Client, error) {
	log.Debug("[ExternalServices] Creating JWK HTTP client")
	return f.factory.CreateJWKClient()
}

// CreateIntrospectionClient creates an HTTP client for OAuth introspection requests.
func (f *ExternalHTTPClientFactory) CreateIntrospectionClient() (*http.Client, error) {
	log.Debug("[ExternalServices] Creating OAuth introspection HTTP client")
	return f.factory.CreateIntrospectionClient()
}

// CreateWebhookClient creates an HTTP client for webhook requests.
func (f *ExternalHTTPClientFactory) CreateWebhookClient() (*http.Client, error) {
	log.Debug("[ExternalServices] Creating webhook HTTP client")
	return f.factory.CreateWebhookClient()
}

// CreateHealthCheckClient creates an HTTP client for health check requests.
func (f *ExternalHTTPClientFactory) CreateHealthCheckClient() (*http.Client, error) {
	log.Debug("[ExternalServices] Creating health check HTTP client")
	return f.factory.CreateHealthCheckClient()
}

// getJWKWithClient fetches JWK using the provided HTTP client for proxy and mTLS support
func getJWKWithClient(jwlUrl string, client *http.Client) (*jose.JSONWebKeySet, error) {
	log.Debug("Pulling JWK with configured client")
	return httpclient.GetJWKWithClient(jwlUrl, client, parseJWK)
}
