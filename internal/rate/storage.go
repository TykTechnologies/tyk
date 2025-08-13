package rate

import (
	"crypto/tls"
	"crypto/x509"
	temporalStorageErr "github.com/TykTechnologies/storage/temporal/temperr"
	"os"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/redis"
)

// use temporalStorageErr for consistency in errors returned
var (
	InvalidTLSVersion    = temporalStorageErr.InvalidTLSVersion
	InvalidTLSMinVersion = temporalStorageErr.InvalidTLSMinVersion
	InvalidTLSMaxVersion = temporalStorageErr.InvalidTLSMaxVersion
	AppendCertsFromPEM   = temporalStorageErr.AppendCertsFromPEM
)

// NewStorage provides a redis v9 client for rate limiter use.
func NewStorage(cfg *config.StorageOptionsConf) (redis.UniversalClient, error) {
	// poolSize applies per cluster node and not for the whole cluster.
	poolSize := 500
	if cfg.MaxActive > 0 {
		poolSize = cfg.MaxActive
	}

	timeout := 5 * time.Second

	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}

	tlsConfig, err := loadTLSConfig(cfg)
	if err != nil {
		return nil, err
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
		return redis.NewFailoverClient(opts.Failover()), nil
	}

	if cfg.EnableCluster {
		return redis.NewClusterClient(opts.Cluster()), nil
	}

	return redis.NewClient(opts.Simple()), nil
}

func loadTLSConfig(cfg *config.StorageOptionsConf) (*tls.Config, error) {
	if !cfg.UseSSL {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SSLInsecureSkipVerify,
	}

	// add certs and key files
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
		} else {
			return nil, err
		}
	}

	// Add CA file if provided
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, AppendCertsFromPEM
		}
		tlsConfig.RootCAs = caCertPool
	}

	minVersion, maxVersion, err := handleTLSVersion(cfg)
	if err != nil {
		return nil, err
	}

	tlsConfig.MinVersion = uint16(minVersion)
	tlsConfig.MaxVersion = uint16(maxVersion)

	return tlsConfig, nil
}

func handleTLSVersion(cfg *config.StorageOptionsConf) (minVersion, maxVersion int, err error) {
	validVersions := map[string]int{
		"1.0": tls.VersionTLS10,
		"1.1": tls.VersionTLS11,
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	}

	if cfg.TLSMaxVersion == "" {
		cfg.TLSMaxVersion = "1.3"
	}

	if _, ok := validVersions[cfg.TLSMaxVersion]; ok {
		maxVersion = validVersions[cfg.TLSMaxVersion]
	} else {
		err = InvalidTLSMaxVersion
		return
	}

	if cfg.TLSMinVersion == "" {
		cfg.TLSMinVersion = "1.2"
	}

	if _, ok := validVersions[cfg.TLSMinVersion]; ok {
		minVersion = validVersions[cfg.TLSMinVersion]
	} else {
		err = InvalidTLSMinVersion
		return
	}

	if minVersion > maxVersion {
		err = InvalidTLSVersion
		return
	}

	return
}
