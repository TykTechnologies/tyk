package rate

import (
	"crypto/tls"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/redis"
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
		tlsConfig = &tls.Config{
			InsecureSkipVerify: cfg.SSLInsecureSkipVerify,
		}
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
