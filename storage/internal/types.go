package internal

import (
	"fmt"
	"strings"

	"github.com/TykTechnologies/tyk/config"

	model "github.com/TykTechnologies/tyk/storage/internal/model"
	redis6 "github.com/TykTechnologies/tyk/storage/internal/redis6"
	redis7 "github.com/TykTechnologies/tyk/storage/internal/redis7"
)

type StorageDriver = model.StorageDriver

// Assert that drivers implement the interface
var _ StorageDriver = &redis6.Driver{}
var _ StorageDriver = &redis7.Driver{}

// New returns an appropriate driver instance
func New(conf config.StorageOptionsConf) StorageDriver {
	if conf.Type == "redis7" {
		return redis7.New(conf)
	}
	return redis6.New(conf)
}

// Contains list of valid storage drivers
var validStorageDrivers = []string{"redis", "redis7"}

// IsValidDriver validates driver type against valid drivers
func IsValidDriver(driverType string) error {
	if !contains(validStorageDrivers, driverType) {
		return fmt.Errorf("Invalid storage type %q. Supported types are: %s", driverType, strings.Join(validStorageDrivers, ", "))
	}
	return nil
}

// contains checks whether the given slice contains the given item.
func contains(s []string, i string) bool {
	for _, a := range s {
		if a == i {
			return true
		}
	}
	return false
}
