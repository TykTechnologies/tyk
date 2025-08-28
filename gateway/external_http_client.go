package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/go-jose/go-jose/v3"
)

// ExternalHTTPClientFactory creates HTTP clients for external service interactions
// with support for proxy configuration and mTLS client certificates.
type ExternalHTTPClientFactory struct {
	config *config.ExternalServiceConfig
	gw     *Gateway
}

// NewExternalHTTPClientFactory creates a new HTTP client factory.
func NewExternalHTTPClientFactory(gw *Gateway) *ExternalHTTPClientFactory {
	gwConfig := gw.GetConfig()
	return &ExternalHTTPClientFactory{
		config: &gwConfig.ExternalServices,
		gw:     gw,
	}
}

// CreateClient creates an HTTP client configured for the specified service type.
// It applies proxy settings and mTLS configuration based on the service configuration hierarchy:
// 1. Service-specific configuration
// 2. Global configuration
// 3. Environment variables (for proxy)
// 4. Default settings
func (f *ExternalHTTPClientFactory) CreateClient(serviceType string) (*http.Client, error) {
	serviceConfig := f.getServiceConfig(serviceType)

	transport := f.getServiceTransport(serviceType)

	// Configure proxy
	proxyFunc, err := f.getProxyFunction(serviceConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to configure proxy: %w", err)
	}
	transport.Proxy = proxyFunc

	// Configure TLS
	tlsConfig, err := f.getTLSConfig(serviceConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}
	transport.TLSClientConfig = tlsConfig

	// Apply service-specific timeout configuration
	timeout := f.getServiceTimeout(serviceType)

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// getServiceConfig returns the merged configuration for a specific service type.
func (f *ExternalHTTPClientFactory) getServiceConfig(serviceType string) config.ServiceConfig {
	var serviceConfig config.ServiceConfig

	// Get service-specific configuration
	switch serviceType {
	case config.ServiceTypeOAuth:
		serviceConfig = f.config.OAuth
	case config.ServiceTypeStorage:
		serviceConfig = f.config.Storage
	case config.ServiceTypeWebhook:
		serviceConfig = f.config.Webhooks
	case config.ServiceTypeHealth:
		serviceConfig = f.config.Health
	case config.ServiceTypeDiscovery:
		serviceConfig = f.config.Discovery
	default:
		// Use empty service config, will fall back to global settings
		serviceConfig = config.ServiceConfig{}
	}

	// Merge with global proxy configuration if service-specific is not set
	if serviceConfig.Proxy.HTTPProxy == "" && serviceConfig.Proxy.HTTPSProxy == "" && !serviceConfig.Proxy.UseEnvironment {
		if f.config.Proxy.HTTPProxy != "" || f.config.Proxy.HTTPSProxy != "" || f.config.Proxy.UseEnvironment {
			serviceConfig.Proxy = f.config.Proxy
		}
	}

	return serviceConfig
}

// getProxyFunction returns the appropriate proxy function based on configuration.
func (f *ExternalHTTPClientFactory) getProxyFunction(serviceConfig config.ServiceConfig) (func(*http.Request) (*url.URL, error), error) {
	// Priority: Service-specific → Global → Environment → Direct connection

	// Check service-specific proxy configuration
	if serviceConfig.Proxy.HTTPProxy != "" || serviceConfig.Proxy.HTTPSProxy != "" {
		// Validate proxy URLs during client creation to fail fast
		if serviceConfig.Proxy.HTTPProxy != "" {
			if _, err := url.Parse(serviceConfig.Proxy.HTTPProxy); err != nil {
				return nil, fmt.Errorf("invalid HTTP proxy URL: %w", err)
			}
		}
		if serviceConfig.Proxy.HTTPSProxy != "" {
			if _, err := url.Parse(serviceConfig.Proxy.HTTPSProxy); err != nil {
				return nil, fmt.Errorf("invalid HTTPS proxy URL: %w", err)
			}
		}
		return f.createCustomProxyFunc(serviceConfig.Proxy), nil
	}

	// Check if environment variables should be used
	if serviceConfig.Proxy.UseEnvironment {
		return http.ProxyFromEnvironment, nil
	}

	// No proxy configuration
	return nil, nil
}

// createCustomProxyFunc creates a custom proxy function based on the proxy configuration.
func (f *ExternalHTTPClientFactory) createCustomProxyFunc(proxyConfig config.ProxyConfig) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		var proxyURL string

		// Choose proxy based on scheme
		if req.URL.Scheme == "https" && proxyConfig.HTTPSProxy != "" {
			proxyURL = proxyConfig.HTTPSProxy
		} else if req.URL.Scheme == "http" && proxyConfig.HTTPProxy != "" {
			proxyURL = proxyConfig.HTTPProxy
		} else if proxyConfig.HTTPProxy != "" {
			// Fallback to HTTP proxy
			proxyURL = proxyConfig.HTTPProxy
		}

		if proxyURL == "" {
			return nil, nil // No proxy
		}

		// Check NO_PROXY list
		if f.shouldBypassProxy(req.URL.Host, proxyConfig.NoProxy) {
			return nil, nil
		}

		return url.Parse(proxyURL)
	}
}

// shouldBypassProxy checks if a host should bypass the proxy based on NO_PROXY configuration.
func (f *ExternalHTTPClientFactory) shouldBypassProxy(host, noProxy string) bool {
	if noProxy == "" {
		return false
	}

	// Parse comma-separated list of hosts to bypass
	for _, noProxyHost := range splitNoProxy(noProxy) {
		if host == noProxyHost || (noProxyHost == "localhost" && (host == "localhost" || host == "127.0.0.1")) {
			return true
		}
	}

	return false
}

// splitNoProxy splits a NO_PROXY string into individual hosts.
func splitNoProxy(noProxy string) []string {
	if noProxy == "" {
		return nil
	}

	var hosts []string
	for _, host := range strings.Split(noProxy, ",") {
		host = strings.TrimSpace(host)
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// getTLSConfig creates TLS configuration based on mTLS settings.
func (f *ExternalHTTPClientFactory) getTLSConfig(serviceConfig config.ServiceConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: serviceConfig.MTLS.InsecureSkipVerify,
	}

	// Configure mTLS if enabled
	if serviceConfig.MTLS.Enabled {
		// Load client certificate
		if serviceConfig.MTLS.CertFile != "" && serviceConfig.MTLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(serviceConfig.MTLS.CertFile, serviceConfig.MTLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		// Load CA certificate
		if serviceConfig.MTLS.CAFile != "" {
			caCert, err := ioutil.ReadFile(serviceConfig.MTLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}
	}

	return tlsConfig, nil
}

// CreateJWKClient creates an HTTP client specifically configured for JWK endpoint requests.
// This method preserves existing SSL skip verify behavior while adding proxy support.
func (f *ExternalHTTPClientFactory) CreateJWKClient(insecureSkipVerify bool) (*http.Client, error) {
	client, err := f.CreateClient(config.ServiceTypeOAuth)
	if err != nil {
		return nil, err
	}

	// Override TLS configuration to preserve existing JWK behavior
	if transport, ok := client.Transport.(*http.Transport); ok {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = insecureSkipVerify
	}

	return client, nil
}

// CreateIntrospectionClient creates an HTTP client for OAuth introspection requests.
func (f *ExternalHTTPClientFactory) CreateIntrospectionClient() (*http.Client, error) {
	return f.CreateClient(config.ServiceTypeOAuth)
}

// CreateWebhookClient creates an HTTP client for webhook requests.
func (f *ExternalHTTPClientFactory) CreateWebhookClient() (*http.Client, error) {
	return f.CreateClient(config.ServiceTypeWebhook)
}

// CreateHealthCheckClient creates an HTTP client for health check requests.
func (f *ExternalHTTPClientFactory) CreateHealthCheckClient() (*http.Client, error) {
	return f.CreateClient(config.ServiceTypeHealth)
}

// getJWKWithClient fetches JWK using the provided HTTP client for proxy and mTLS support
func getJWKWithClient(jwlUrl string, client *http.Client) (*jose.JSONWebKeySet, error) {
	log.Debug("Pulling JWK with configured client")
	resp, err := client.Get(jwlUrl)
	if err != nil {
		log.WithError(err).Error("Failed to get resource URL")
		return nil, err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("Failed to get read response body")
		return nil, err
	}

	jwkSet, err := parseJWK(buf)
	if err != nil {
		return nil, err
	}

	return jwkSet, nil
}

// getServiceTimeout returns the appropriate timeout for different service types
func (f *ExternalHTTPClientFactory) getServiceTimeout(serviceType string) time.Duration {
	switch serviceType {
	case config.ServiceTypeOAuth:
		// OAuth/JWT flows should have reasonable timeouts for authentication
		return 15 * time.Second
	case config.ServiceTypeWebhook:
		// Webhooks need reliable delivery with reasonable timeout
		return 30 * time.Second
	case config.ServiceTypeHealth:
		// Health checks need quick responses
		return 10 * time.Second
	case config.ServiceTypeDiscovery:
		// Service discovery needs quick responses for load balancing
		return 10 * time.Second
	case config.ServiceTypeStorage:
		// Storage operations might need more time
		return 20 * time.Second
	default:
		// Default conservative timeout
		return 30 * time.Second
	}
}

// getServiceTransport returns service-specific HTTP transport configuration
func (f *ExternalHTTPClientFactory) getServiceTransport(serviceType string) *http.Transport {
	switch serviceType {
	case config.ServiceTypeOAuth:
		// OAuth/JWT needs reliable connections for authentication
		return &http.Transport{
			MaxIdleConns:          50,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	case config.ServiceTypeWebhook:
		// Webhooks need reliable delivery
		return &http.Transport{
			MaxIdleConns:          50,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	case config.ServiceTypeHealth:
		// Health checks need quick, frequent connections
		return &http.Transport{
			MaxIdleConns:          20,
			MaxIdleConnsPerHost:   5,
			IdleConnTimeout:       15 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	case config.ServiceTypeDiscovery:
		// Service discovery needs quick responses
		return &http.Transport{
			MaxIdleConns:          30,
			MaxIdleConnsPerHost:   5,
			IdleConnTimeout:       20 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	case config.ServiceTypeStorage:
		// Storage may need longer-lived connections
		return &http.Transport{
			MaxIdleConns:          50,
			MaxIdleConnsPerHost:   15,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	default:
		// Default transport configuration
		return &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
}
