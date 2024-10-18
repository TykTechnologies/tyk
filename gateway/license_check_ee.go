//go:build ee || dev

package gateway

import (
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ee/license"
)

func checkLicense(conf config.Config) error {
	log.Info("Tyk Gateway Enterprise Edition is starting")
	err := license.Load(conf.LicenseKey)
	if err != nil {
		log.Error("License validation failed: ", err)
		return err
	}
	return nil
}
