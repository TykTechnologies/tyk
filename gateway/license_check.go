//go:build !ee && !dev

package gateway

import "github.com/TykTechnologies/tyk/config"

func checkLicense(config.Config) error {
	return nil
}
