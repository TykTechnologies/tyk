package redis

import (
	"crypto/tls"
	"time"

	"github.com/TykTechnologies/tyk/config"
)

// getClientConfig returns a redis version specific *UniversalOptions.
var getClientConfig = func(cfg config.StorageOptionsConf) *UniversalOptions {
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

	return &UniversalOptions{
		Addrs:            getRedisAddrs(cfg),
		MasterName:       cfg.MasterName,
		SentinelPassword: cfg.SentinelPassword,
		Username:         cfg.Username,
		Password:         cfg.Password,
		DB:               cfg.Database,
		DialTimeout:      timeout,
		ReadTimeout:      timeout,
		WriteTimeout:     timeout,
		PoolSize:         poolSize,
		TLSConfig:        tlsConfig,
	}
}
