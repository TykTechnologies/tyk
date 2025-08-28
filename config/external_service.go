package config

// ExternalServiceConfig defines configuration for external service interactions
// including proxy settings and mTLS client certificate support.
type ExternalServiceConfig struct {
	// Global proxy configuration that applies to all external services
	Proxy ProxyConfig `json:"proxy"`
	// Service-specific configurations that can override global settings
	OAuth     ServiceConfig `json:"oauth"`
	Storage   ServiceConfig `json:"storage"`
	Webhooks  ServiceConfig `json:"webhooks"`
	Health    ServiceConfig `json:"health"`
	Discovery ServiceConfig `json:"discovery"`
}

// ProxyConfig defines HTTP proxy configuration for external service connections.
type ProxyConfig struct {
	// UseEnvironment enables reading proxy configuration from environment variables
	// (HTTP_PROXY, HTTPS_PROXY, NO_PROXY)
	UseEnvironment bool `json:"use_environment"`
	// HTTPProxy sets the HTTP proxy URL (e.g., http://proxy:8080)
	HTTPProxy string `json:"http_proxy"`
	// HTTPSProxy sets the HTTPS proxy URL (e.g., https://proxy:8080)
	HTTPSProxy string `json:"https_proxy"`
	// NoProxy defines addresses that should bypass the proxy (comma-separated)
	NoProxy string `json:"no_proxy"`
}

// ServiceConfig defines service-specific configuration that can override global settings.
type ServiceConfig struct {
	// Proxy configuration for this specific service type
	Proxy ProxyConfig `json:"proxy"`
	// MTLS configuration for secure external communications
	MTLS MTLSConfig `json:"mtls"`
}

// MTLSConfig defines mTLS client certificate configuration.
type MTLSConfig struct {
	// Enabled controls whether mTLS is enabled for this service
	Enabled bool `json:"enabled"`
	// CertFile path to the client certificate file
	CertFile string `json:"cert_file"`
	// KeyFile path to the client private key file
	KeyFile string `json:"key_file"`
	// CAFile path to the CA certificate file for server verification
	CAFile string `json:"ca_file"`
	// InsecureSkipVerify disables server certificate verification (not recommended for production)
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
	// TLSMinVersion sets the minimum TLS version (e.g., "1.2", "1.3")
	TLSMinVersion string `json:"tls_min_version"`
	// TLSMaxVersion sets the maximum TLS version (e.g., "1.2", "1.3")
	TLSMaxVersion string `json:"tls_max_version"`
}

// Service type constants for identifying different external service types
const (
	ServiceTypeOAuth     = "oauth"
	ServiceTypeStorage   = "storage"
	ServiceTypeWebhook   = "webhook"
	ServiceTypeHealth    = "health"
	ServiceTypeDiscovery = "discovery"
)
