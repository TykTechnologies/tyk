package checkup

import (
	"runtime"
	"syscall"

	"github.com/TykTechnologies/tyk/config"
	logger "github.com/TykTechnologies/tyk/log"
)

var (
	log            = logger.Get().WithField("prefix", "checkup")
	defaultConfigs = config.Config{
		Secret:     "352d20ee67be67f6340b4c0605b044b7",
		NodeSecret: "352d20ee67be67f6340b4c0605b044b7",
	}
)

const (
	minCPU             = 2
	minFileDescriptors = 80000
)

func LegacyRateLimiters(c config.Config) {
	if c.ManagementNode {
		return
	}
	if c.EnableSentinelRateLimiter || c.EnableRedisRollingLimiter {
		log.Warning("SentinelRateLimiter & RedisRollingLimiter are deprecated")
	}
}

func AllowInsecureConfigs(c config.Config) {
	if c.AllowInsecureConfigs {
		log.Warning("Insecure configuration allowed: allow_insecure_configs: true")
	}
}

func HealthCheck(c config.Config) {
	if c.HealthCheck.EnableHealthChecks {
		log.Warn("Health Checker is deprecated and not recommended")
	}
}

func FileDescriptors() {
	rlimit := &syscall.Rlimit{}
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, rlimit)
	if err == nil && rlimit.Cur < minFileDescriptors {
		log.Warningf("File descriptor limit %d too low for production use. Min %d recommended.\n"+
			"\tThis could have a significant negative impact on performance.\n"+
			"\tPlease refer to https://tyk.io/docs/deploy-tyk-premise-production/#file-handles for further guidance.", rlimit.Cur, minFileDescriptors)
	}
}

func Cpus() {
	cpus := runtime.NumCPU()
	if cpus < minCPU {
		log.Warningf("Num CPUs %d too low for production use. Min %d recommended.\n"+
			"\tThis could have a significant negative impact on performance.\n"+
			"\tPlease refer to https://tyk.io/docs/deploy-tyk-premise-production/#use-the-right-hardware for further guidance.", cpus, minCPU)
	}
}

func DefaultSecrets(c config.Config) {
	if c.Secret == defaultConfigs.Secret {
		log.Warningf("Default secret `%s` should be changed for production.", defaultConfigs.Secret)
	}

	if c.NodeSecret == defaultConfigs.NodeSecret {
		log.Warningf("Default node_secret `%s` should be changed for production.", defaultConfigs.NodeSecret)
	}
}
