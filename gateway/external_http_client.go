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

	"github.com/TykTechnologies/tyk/certs"
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
	log.Debugf("[ExternalServices] Creating HTTP client for service type: %s", serviceType)

	serviceConfig := f.getServiceConfig(serviceType)

	transport := f.getServiceTransport(serviceType)

	// Configure proxy
	proxyFunc, err := f.getProxyFunction(serviceConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to configure proxy: %w", err)
	}
	transport.Proxy = proxyFunc

	if proxyFunc != nil {
		log.Debugf("[ExternalServices] HTTP client for %s configured with proxy support", serviceType)
	}

	// Configure TLS
	tlsConfig, err := f.getTLSConfig(serviceConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}
	transport.TLSClientConfig = tlsConfig

	if tlsConfig != nil && len(tlsConfig.Certificates) > 0 {
		log.Debugf("[ExternalServices] HTTP client for %s configured with mTLS certificates", serviceType)
	}

	// Apply service-specific timeout configuration
	timeout := f.getServiceTimeout(serviceType)

	log.Debugf("[ExternalServices] HTTP client for %s created with timeout: %v", serviceType, timeout)

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

	// Merge with global proxy configuration if service-specific is not set and global is enabled
	if serviceConfig.Proxy.HTTPProxy == "" && serviceConfig.Proxy.HTTPSProxy == "" && !serviceConfig.Proxy.Enabled {
		if f.config.Global.Enabled {
			// Map global config to service config structure
			serviceConfig.Proxy.Enabled = f.config.Global.Enabled
			serviceConfig.Proxy.HTTPProxy = f.config.Global.HTTPProxy
			serviceConfig.Proxy.HTTPSProxy = f.config.Global.HTTPSProxy
			serviceConfig.Proxy.BypassProxy = f.config.Global.BypassProxy
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

	// Check if proxy is enabled and should use environment variables
	if serviceConfig.Proxy.Enabled {
		// If no specific proxy URLs are set but proxy is enabled, use environment variables
		if serviceConfig.Proxy.HTTPProxy == "" && serviceConfig.Proxy.HTTPSProxy == "" {
			return http.ProxyFromEnvironment, nil
		}
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

		// Check bypass proxy list
		if f.shouldBypassProxy(req.URL.Host, proxyConfig.BypassProxy) {
			return nil, nil
		}

		return url.Parse(proxyURL)
	}
}

// shouldBypassProxy checks if a host should bypass the proxy based on bypass proxy configuration.
func (f *ExternalHTTPClientFactory) shouldBypassProxy(host, bypassProxy string) bool {
	if bypassProxy == "" {
		return false
	}

	// Parse comma-separated list of hosts to bypass
	for _, bypassHost := range splitBypassProxy(bypassProxy) {
		if host == bypassHost || (bypassHost == "localhost" && (host == "localhost" || host == "127.0.0.1")) {
			return true
		}
	}

	return false
}

// splitBypassProxy splits a bypass proxy string into individual hosts.
func splitBypassProxy(bypassProxy string) []string {
	if bypassProxy == "" {
		return nil
	}

	var hosts []string
	for _, host := range strings.Split(bypassProxy, ",") {
		host = strings.TrimSpace(host)
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// getTLSConfig creates TLS configuration based on mTLS settings.
// It supports both file-based and certificate store configurations.
func (f *ExternalHTTPClientFactory) getTLSConfig(serviceConfig config.ServiceConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: serviceConfig.MTLS.InsecureSkipVerify,
	}

	// Validate mTLS configuration
	if err := serviceConfig.MTLS.Validate(); err != nil {
		return nil, fmt.Errorf("invalid mTLS configuration: %w", err)
	}

	// Configure mTLS if enabled
	if serviceConfig.MTLS.Enabled {
		// Priority 1: Certificate store (if CertID is provided)
		if serviceConfig.MTLS.IsCertificateStoreConfig() {
			cert, err := f.loadCertificateFromStore(serviceConfig.MTLS.CertID)
			if err != nil {
				return nil, fmt.Errorf("failed to load certificate from store: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{*cert}
		} else if serviceConfig.MTLS.IsFileBasedConfig() {
			// Priority 2: File-based certificates (existing behavior)
			cert, err := tls.LoadX509KeyPair(serviceConfig.MTLS.CertFile, serviceConfig.MTLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		// Load CA certificates from store or file
		if len(serviceConfig.MTLS.CACertIDs) > 0 {
			caCertPool := f.loadCACertPoolFromStore(serviceConfig.MTLS.CACertIDs)
			if caCertPool != nil {
				tlsConfig.RootCAs = caCertPool
			}
		} else if serviceConfig.MTLS.CAFile != "" {
			// Existing file-based CA loading logic
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
	log.Debugf("[ExternalServices] Creating JWK HTTP client with insecureSkipVerify: %t", insecureSkipVerify)

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
		log.Debugf("[ExternalServices] JWK client configured with insecureSkipVerify: %t", insecureSkipVerify)
	}

	return client, nil
}

// CreateIntrospectionClient creates an HTTP client for OAuth introspection requests.
func (f *ExternalHTTPClientFactory) CreateIntrospectionClient() (*http.Client, error) {
	log.Debug("[ExternalServices] Creating OAuth introspection HTTP client")
	return f.CreateClient(config.ServiceTypeOAuth)
}

// CreateWebhookClient creates an HTTP client for webhook requests.
func (f *ExternalHTTPClientFactory) CreateWebhookClient() (*http.Client, error) {
	log.Debug("[ExternalServices] Creating webhook HTTP client")
	return f.CreateClient(config.ServiceTypeWebhook)
}

// CreateHealthCheckClient creates an HTTP client for health check requests.
func (f *ExternalHTTPClientFactory) CreateHealthCheckClient() (*http.Client, error) {
	log.Debug("[ExternalServices] Creating health check HTTP client")
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

// loadCertificateFromStore retrieves a certificate from the Tyk certificate store.
func (f *ExternalHTTPClientFactory) loadCertificateFromStore(certID string) (*tls.Certificate, error) {
	if f.gw.CertificateManager == nil {
		return nil, fmt.Errorf("certificate manager not available")
	}

	log.Debugf("[ExternalServices] Loading certificate from store: %s", certID)

	certsList := f.gw.CertificateManager.List([]string{certID}, certs.CertificatePrivate)
	if len(certsList) == 0 || certsList[0] == nil {
		return nil, fmt.Errorf("certificate not found in store: %s", certID)
	}

	log.Debugf("[ExternalServices] Successfully loaded certificate from store: %s", certID)
	return certsList[0], nil
}

// loadCACertPoolFromStore creates a CA certificate pool from store certificate IDs.
func (f *ExternalHTTPClientFactory) loadCACertPoolFromStore(certIDs []string) *x509.CertPool {
	if f.gw.CertificateManager == nil {
		log.Error("[ExternalServices] Certificate manager not available for CA certificate loading")
		return nil
	}

	log.Debugf("[ExternalServices] Loading CA certificates from store: %v", certIDs)

	certPool := f.gw.CertificateManager.CertPool(certIDs)
	if certPool != nil {
		log.Debugf("[ExternalServices] Successfully loaded %d CA certificates from store", len(certIDs))
	} else {
		log.Warn("[ExternalServices] Failed to create CA certificate pool from store")
	}

	return certPool
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
