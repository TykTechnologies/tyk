//go:build !dev
// +build !dev

package config

// DevelopmentConfig should contain no flags for official release builds.
type DevelopmentConfig struct{}

// GetRateLimiterStorage will return the storage configuration to use for rate limiters.
func (c *Config) GetRateLimiterStorage() *StorageOptionsConf {
	if c.EnableSeparateRLStore {
		return &c.RateLimitStorage
	}

	return &c.Storage
}
