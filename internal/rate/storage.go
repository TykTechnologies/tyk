package rate

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/sirupsen/logrus"
)

// NewStorage provides a redis v9 client for rate limiter use.
func NewStorage(cfg *config.StorageOptionsConf, externalServicesConfig *config.ExternalServiceConfig) redis.UniversalClient {
	logrus.Debugf("[ExternalServices] Creating Redis client for rate limiter")
	// poolSize applies per cluster node and not for the whole cluster.
	poolSize := 500
	if cfg.MaxActive > 0 {
		poolSize = cfg.MaxActive
	}

	timeout := 5 * time.Second

	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}

	var tlsConfig *tls.Config

	if cfg.UseSSL {
		logrus.Debug("[ExternalServices] Configuring TLS for Redis connection")
		tlsConfig = createTLSConfig(cfg, externalServicesConfig)
	}

	opts := &redis.UniversalOptions{
		Addrs:            cfg.HostAddrs(),
		MasterName:       cfg.MasterName,
		SentinelPassword: cfg.SentinelPassword,
		Username:         cfg.Username,
		Password:         cfg.Password,
		DB:               cfg.Database,
		DialTimeout:      timeout,
		ReadTimeout:      timeout,
		WriteTimeout:     timeout,
		//		IdleTimeout:      240 * timeout,
		PoolSize:  poolSize,
		TLSConfig: tlsConfig,
	}

	if opts.MasterName != "" {
		return redis.NewFailoverClient(opts.Failover())
	}

	if cfg.EnableCluster {
		return redis.NewClusterClient(opts.Cluster())
	}

	return redis.NewClient(opts.Simple())
}

// createTLSConfig creates a TLS configuration with proper mTLS support
// It prioritizes external services storage configuration over legacy storage config
func createTLSConfig(cfg *config.StorageOptionsConf, externalServicesConfig *config.ExternalServiceConfig) *tls.Config {
	// Start with legacy configuration as base
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SSLInsecureSkipVerify,
	}

	// Override with external services storage configuration if available and enabled
	if externalServicesConfig != nil && externalServicesConfig.Storage.MTLS.Enabled {
		logrus.Debug("[ExternalServices] Using external services storage configuration for Redis TLS")
		storageConfig := externalServicesConfig.Storage.MTLS
		tlsConfig.InsecureSkipVerify = storageConfig.InsecureSkipVerify

		// Load client certificate from external services config
		if storageConfig.CertFile != "" && storageConfig.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(storageConfig.CertFile, storageConfig.KeyFile)
			if err != nil {
				logrus.WithError(err).Error("Failed to load external services storage client certificate for Redis")
			} else {
				tlsConfig.Certificates = []tls.Certificate{cert}
				logrus.Debug("Loaded Redis client certificate from external services storage configuration")
			}
		}

		// Load CA certificate from external services config
		if storageConfig.CAFile != "" {
			caCert, err := os.ReadFile(storageConfig.CAFile)
			if err != nil {
				logrus.WithError(err).Error("Failed to load external services storage CA certificate for Redis")
			} else {
				caCertPool := x509.NewCertPool()
				if !caCertPool.AppendCertsFromPEM(caCert) {
					logrus.Error("Failed to parse external services storage CA certificate for Redis")
				} else {
					tlsConfig.RootCAs = caCertPool
					logrus.Debug("Loaded Redis CA certificate from external services storage configuration")
				}
			}
		}

		// Set TLS versions from external services config if configured
		if storageConfig.TLSMinVersion != "" {
			if version, ok := getTLSVersion(storageConfig.TLSMinVersion); ok {
				tlsConfig.MinVersion = version
				logrus.Debugf("[ExternalServices] Redis TLS MinVersion set to: %s", storageConfig.TLSMinVersion)
			}
		}
		if storageConfig.TLSMaxVersion != "" {
			if version, ok := getTLSVersion(storageConfig.TLSMaxVersion); ok {
				tlsConfig.MaxVersion = version
				logrus.Debugf("[ExternalServices] Redis TLS MaxVersion set to: %s", storageConfig.TLSMaxVersion)
			}
		}

		// External services config takes priority, skip legacy configuration
		logrus.Debug("[ExternalServices] Redis TLS configuration completed using external services config")
		return tlsConfig
	}

	// Legacy certificate loading (only if external services config not used)
	logrus.Debug("[ExternalServices] Using legacy storage configuration for Redis TLS")

	// Load CA certificate if provided
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			logrus.WithError(err).Error("Failed to load legacy CA certificate for rate limiter Redis")
		} else {
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				logrus.Error("Failed to parse legacy CA certificate for rate limiter Redis")
			} else {
				tlsConfig.RootCAs = caCertPool
				logrus.Debug("Loaded Redis CA certificate from legacy storage configuration")
			}
		}
	}

	// Load client certificate and key for mutual TLS
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			logrus.WithError(err).Error("Failed to load legacy client certificate and key for rate limiter Redis")
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
			logrus.Debug("Loaded Redis client certificate from legacy storage configuration")
		}
	}

	// Set TLS versions from legacy config if configured
	if cfg.TLSMinVersion != "" {
		if version, ok := getTLSVersion(cfg.TLSMinVersion); ok {
			tlsConfig.MinVersion = version
			logrus.Debugf("[ExternalServices] Redis legacy TLS MinVersion set to: %s", cfg.TLSMinVersion)
		}
	}
	if cfg.TLSMaxVersion != "" {
		if version, ok := getTLSVersion(cfg.TLSMaxVersion); ok {
			tlsConfig.MaxVersion = version
			logrus.Debugf("[ExternalServices] Redis legacy TLS MaxVersion set to: %s", cfg.TLSMaxVersion)
		}
	}

	logrus.Debug("[ExternalServices] Redis TLS configuration completed using legacy config")
	return tlsConfig
}

// getTLSVersion converts a string TLS version to the corresponding tls constant
func getTLSVersion(version string) (uint16, bool) {
	switch version {
	case "1.0":
		return tls.VersionTLS10, true
	case "1.1":
		return tls.VersionTLS11, true
	case "1.2":
		return tls.VersionTLS12, true
	case "1.3":
		return tls.VersionTLS13, true
	default:
		logrus.Warnf("Unknown TLS version: %s", version)
		return 0, false
	}
}
