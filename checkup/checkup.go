package checkup

import (
	"runtime"
	"syscall"

	"github.com/TykTechnologies/tyk/v3/config"
	logger "github.com/TykTechnologies/tyk/v3/log"
)

var (
	log            = logger.Get().WithField("prefix", "checkup")
	defaultConfigs = config.Config{
		Secret:     "352d20ee67be67f6340b4c0605b044b7",
		NodeSecret: "352d20ee67be67f6340b4c0605b044b7",
		AnalyticsConfig: config.AnalyticsConfigConfig{
			PoolSize: runtime.NumCPU(),
		},
	}
)

const (
	minCPU               = 2
	minFileDescriptors   = 80000
	minRecordsBufferSize = 1000
)

func Run(c config.Config) {
	legacyRateLimiters(c)
	allowInsecureConfigs(c)
	healthCheck(c)
	fileDescriptors()
	cpus()
	defaultSecrets(c)
	defaultAnalytics(c)
}

func legacyRateLimiters(c config.Config) {
	if c.ManagementNode {
		return
	}

	if c.EnableSentinelRateLimiter || c.EnableRedisRollingLimiter {
		log.Warning("SentinelRateLimiter & RedisRollingLimiter are deprecated")
	}
}

func allowInsecureConfigs(c config.Config) {
	if c.AllowInsecureConfigs {
		log.WithField("config.allow_insecure_configs", true).
			Warning("Insecure configuration allowed")
	}
}

func healthCheck(c config.Config) {
	if c.HealthCheck.EnableHealthChecks {
		log.Warn("Health Checker is deprecated and not recommended")
	}
}

func fileDescriptors() {
	rlimit := &syscall.Rlimit{}

	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, rlimit)
	if err == nil && rlimit.Cur < minFileDescriptors {
		log.Warningf("File descriptor limit %d is too low for production use. A minimum of %d is recommended.\n"+
			"\tThis could have a significant negative impact on performance.\n"+
			"\tPlease refer to the following link for further guidance:\n"+
			"\t\thttps://tyk.io/docs/deploy-tyk-premise-production/#file-handles--file-descriptors",
			rlimit.Cur, minFileDescriptors)
	}
}

func cpus() {
	cpus := runtime.NumCPU()
	if cpus < minCPU {
		log.Warningf("Number of CPUs %d is too low for production use. A minimum of %d is recommended.\n"+
			"\tThis could have a significant negative impact on performance.\n"+
			"\tPlease refer to the following link for further guidance:\n"+
			"\t\thttps://tyk.io/docs/deploy-tyk-premise-production/#use-the-right-hardware",
			cpus, minCPU)
	}
}

func defaultSecrets(c config.Config) {
	if c.Secret == defaultConfigs.Secret {
		log.WithField("config.secret", defaultConfigs.Secret).
			Warning("Default secret should be changed for production.")
	}

	if c.NodeSecret == defaultConfigs.NodeSecret {
		log.WithField("config.node_secret", defaultConfigs.NodeSecret).
			Warning("Default node_secret should be changed for production.")
	}
}

func defaultAnalytics(c config.Config) {
	if !c.EnableAnalytics {
		return
	}

	if c.AnalyticsConfig.PoolSize == 0 {
		log.WithField("runtime.NumCPU", runtime.NumCPU()).
			Warning("AnalyticsConfig.PoolSize unset. Defaulting to number of available CPUs")

		c.AnalyticsConfig.PoolSize = runtime.NumCPU()
	}

	if c.AnalyticsConfig.RecordsBufferSize < minRecordsBufferSize {
		log.WithField("minRecordsBufferSize", minRecordsBufferSize).
			Warning("AnalyticsConfig.RecordsBufferSize < minimum - Overriding")

		c.AnalyticsConfig.RecordsBufferSize = minRecordsBufferSize
	}

	if c.AnalyticsConfig.StorageExpirationTime == 0 {
		log.WithField("storageExpirationTime", c.AnalyticsConfig.StorageExpirationTime).
			Warning("AnalyticsConfig.StorageExpirationTime is 0, defaulting to 60s")
		c.AnalyticsConfig.StorageExpirationTime = 60
	}

	config.SetGlobal(c)
}
