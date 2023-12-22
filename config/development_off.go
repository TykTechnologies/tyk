//go:build !dev
// +build !dev

package config

// DevelopmentConfig should contain no flags for official release builds.
type DevelopmentConfig struct{}
