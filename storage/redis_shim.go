package storage

import (
	"context"

	"github.com/TykTechnologies/tyk/config"
)

// RedisController acts as a shim to provide backward compatibility for Go plugins users.
// It facilitates connecting to Redis using Tyk's storage package in a way that doesn't break existing implementations.
// changes here are sensible
type RedisController struct {
	connection *ConnectionHandler
}

// NewRedisController initializes a new RedisController. This method ensures Go plugins can connect to Redis
// leveraging Tyk's internal storage mechanisms with minimal changes to their code.
func NewRedisController(ctx context.Context) *RedisController {
	return &RedisController{
		connection: NewConnectionHandler(ctx),
	}
}

// ConnectToRedis sets up the connection to Redis using specified configuration.
// It abstracts the connection logic, allowing Go plugins to seamlessly integrate without direct interaction with the underlying storage logic.
func (rc *RedisController) ConnectToRedis(ctx context.Context, onReconnect func(), conf *config.Config) {
	rc.connection.Connect(ctx, onReconnect, conf)
}

// DisableRedis toggles the Redis connection's active status, providing a mechanism to dynamically
// manage the connection state in response to runtime conditions or configurations.
func (rc *RedisController) DisableRedis(setRedisDown bool) {
	rc.connection.DisableStorage(setRedisDown)
}

// Connected checks the current state of the Redis connection, offering a simple interface
// for Go plugins to verify connectivity without delving into the specifics of the storage layer.
func (rc *RedisController) Connected() bool {
	return rc.connection.Connected()
}

// WaitConnect blocks until a Redis connection is established, enabling Go plugins to wait
// for connectivity before proceeding with operations that require Redis access.
func (rc *RedisController) WaitConnect(ctx context.Context) bool {
	return rc.connection.WaitConnect(ctx)
}
