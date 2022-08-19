package storage

import (
	"context"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage/internal"
)

// Controller interface for storage controllers
type Controller interface {
	Connect(ctx context.Context, onReconnect func(), conf *config.Config)
	Context() context.Context
	Connected() bool
	Disable(setRedisDown bool)
	WaitConnect(ctx context.Context) bool

	ControllerDeprecated
}

// ControllerDeprecated are old API endpoints for backwards compatibility
type ControllerDeprecated interface {
	// ConnectToRedis is deprecated in favor of Connect;
	ConnectToRedis(ctx context.Context, onReconnect func(), conf *config.Config)
	// DisableRedis is deprecated in favor of Disable;
	DisableRedis(setRedisDown bool)
}

// RedisController must implement Controller
var _ Controller = &RedisController{}

// RedisDriver represents the API surface of the redis client library that we use
type RedisDriver = internal.RedisDriver

func fromStringToInterfaceSlice(values []string) []interface{} {
	result := make([]interface{}, len(values))
	for i, v := range values {
		result[i] = v
	}
	return result
}
