package config

import "fmt"

// ExternalServiceConfig provides centralized HTTP client management for Tyk Gateway's external service interactions.
// This enterprise-grade feature supports proxy configuration, mTLS client certificates, and service-specific settings
// for OAuth, Storage, Webhooks, Health Checks, and Service Discovery.
type ExternalServiceConfig struct {
	// Global proxy configuration that applies to all external services unless overridden at the service level
	Global GlobalProxyConfig `json:"global"`
	// OAuth service-specific configuration for external OAuth providers, JWT validation, and token introspection
	OAuth ServiceConfig `json:"oauth"`
	// Storage service-specific configuration for external storage operations including Redis connections and database interactions
	Storage ServiceConfig `json:"storage"`
	// Webhook service-specific configuration for webhook event notifications and delivery
	Webhooks ServiceConfig `json:"webhooks"`
	// Health check service-specific configuration for health check requests and uptime monitoring
	Health ServiceConfig `json:"health"`
	// Service discovery-specific configuration for service registry interactions and load balancer operations
	Discovery ServiceConfig `json:"discovery"`
}

// GlobalProxyConfig defines global HTTP proxy configuration that applies to all external services.
type GlobalProxyConfig struct {
	// Enabled determines whether to apply the global proxy settings for all services.
	// If enabled is true, the other three global settings will be applied for all services,
	// except where there is a service-level override.
	// If enabled is false, the global settings are not applied, only service-level settings (if declared).
	Enabled bool `json:"enabled"`
	// HTTPProxy is the HTTP proxy URL for HTTP requests to external services (e.g., http://localhost:3128).
	// This setting applies globally unless overridden by service-specific configuration.
	HTTPProxy string `json:"http_proxy"`
	// HTTPSProxy is the HTTPS proxy URL for HTTPS requests to external services (e.g., https://localhost:3128).
	// This setting applies globally unless overridden by service-specific configuration.
	HTTPSProxy string `json:"https_proxy"`
	// BypassProxy is a comma-separated list of hosts to bypass proxy. Supports exact hostnames, IP addresses,
	// CIDR blocks, and wildcard patterns (e.g., localhost,127.0.0.1,.internal,*.local).
	BypassProxy string `json:"bypass_proxy"`
}

// ProxyConfig defines service-specific HTTP proxy configuration.
type ProxyConfig struct {
	// Enabled determines whether to apply proxy settings for this specific service.
	Enabled bool `json:"enabled"`
	// HTTPProxy is the HTTP proxy URL for HTTP requests (e.g., http://localhost:3128).
	HTTPProxy string `json:"http_proxy"`
	// HTTPSProxy is the HTTPS proxy URL for HTTPS requests (e.g., https://localhost:3128).
	HTTPSProxy string `json:"https_proxy"`
	// BypassProxy is a comma-separated list of hosts to bypass proxy.
	BypassProxy string `json:"bypass_proxy"`
}

// ServiceConfig defines service-specific configuration that can override global settings.
type ServiceConfig struct {
	// Service-specific proxy configuration. When enabled, overrides global proxy settings for this service.
	Proxy ProxyConfig `json:"proxy"`
	// Mutual TLS configuration for service communications. Supports certificates stored in Tyk Certificate Store
	// (cert_id, ca_cert_ids) or in the file system (cert_file, key_file, ca_file).
	// Tyk Certificate Store configuration takes priority if provided.
	MTLS MTLSConfig `json:"mtls"`
}

// MTLSConfig defines mutual TLS client certificate configuration.
type MTLSConfig struct {
	// Enabled controls whether mTLS is enabled for service requests. When enabled, either file-based configuration (cert_file, key_file) or certificate store configuration (cert_id) must be provided.
	Enabled bool `json:"enabled"`

	// File-based certificate configuration
	// CertFile is the path to the client certificate file for mTLS authentication. Required when using file-based configuration.
	CertFile string `json:"cert_file"`
	// KeyFile is the path to the client private key file for mTLS authentication. Required when using file-based configuration.
	KeyFile string `json:"key_file"`
	// CAFile is the path to the CA certificate file for server verification. Optional but recommended for production environments.
	CAFile string `json:"ca_file"`

	// Certificate store integration
	// CertID is the certificate ID from Tyk certificate store for mTLS authentication. When provided, certificate store
	// is used instead of file-based configuration. Cannot be used together with cert_file and key_file.
	CertID string `json:"cert_id"`
	// CACertIDs is an array of CA certificate IDs from Tyk certificate store for server verification.
	// Used with certificate store configuration when cert_id is provided.
	CACertIDs []string `json:"ca_cert_ids"`

	// TLS configuration
	// InsecureSkipVerify skips server certificate verification. Not recommended for production use. Default: false.
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
	// TLSMinVersion is the minimum TLS version for service connections. Supported values: "1.2", "1.3". Default: "1.2".
	TLSMinVersion string `json:"tls_min_version"`
	// TLSMaxVersion is the maximum TLS version for service connections. Supported values: "1.2", "1.3". Default: "1.3".
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

// Validate validates the MTLSConfig for consistency and completeness.
func (cfg *MTLSConfig) Validate() error {
	if !cfg.Enabled {
		return nil
	}

	isFileConfig := cfg.CertFile != "" || cfg.KeyFile != ""
	hasStoreConfig := cfg.CertID != ""
	hasCAConfig := cfg.CAFile != "" || len(cfg.CACertIDs) > 0

	if isFileConfig && hasStoreConfig {
		return fmt.Errorf("cannot specify both file-based and certificate store configuration")
	}

	// Allow CA-only configurations (for server certificate verification)
	if !isFileConfig && !hasStoreConfig && !hasCAConfig {
		return fmt.Errorf("mTLS enabled but no certificate configuration provided")
	}

	if isFileConfig && (cfg.CertFile == "" || cfg.KeyFile == "") {
		return fmt.Errorf("both cert_file and key_file must be specified for file-based configuration")
	}

	return nil
}

// IsFileBasedConfig returns true if the configuration uses file-based certificates.
func (cfg *MTLSConfig) IsFileBasedConfig() bool {
	return cfg.CertFile != "" || cfg.KeyFile != ""
}

// IsCertificateStoreConfig returns true if the configuration uses certificate store.
func (cfg *MTLSConfig) IsCertificateStoreConfig() bool {
	return cfg.CertID != ""
}
