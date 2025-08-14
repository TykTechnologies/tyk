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
func NewStorage(cfg *config.StorageOptionsConf) redis.UniversalClient {
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
		tlsConfig = createTLSConfig(cfg)
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
func createTLSConfig(cfg *config.StorageOptionsConf) *tls.Config {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SSLInsecureSkipVerify,
	}

	// Set TLS versions if configured
	if cfg.TLSMinVersion != "" {
		if version, ok := getTLSVersion(cfg.TLSMinVersion); ok {
			tlsConfig.MinVersion = version
		}
	}
	if cfg.TLSMaxVersion != "" {
		if version, ok := getTLSVersion(cfg.TLSMaxVersion); ok {
			tlsConfig.MaxVersion = version
		}
	}

	// Load CA certificate if provided
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			logrus.WithError(err).Error("Failed to load CA certificate for rate limiter Redis")
		} else {
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				logrus.Error("Failed to parse CA certificate for rate limiter Redis")
			} else {
				tlsConfig.RootCAs = caCertPool
			}
		}
	}

	// Load client certificate and key for mutual TLS
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			logrus.WithError(err).Error("Failed to load client certificate and key for rate limiter Redis")
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

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
