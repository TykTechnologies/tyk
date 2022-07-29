package internal

import (
	model "github.com/TykTechnologies/tyk/storage/internal/model"
	redis6 "github.com/TykTechnologies/tyk/storage/internal/redis6"
	redis7 "github.com/TykTechnologies/tyk/storage/internal/redis7"
)

type RedisDriver = model.RedisDriver

// Assert that drivers implement the interface
var _ RedisDriver = &redis6.Driver{}
var _ RedisDriver = &redis7.Driver{}
