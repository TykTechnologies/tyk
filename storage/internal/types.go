package internal

import (
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
