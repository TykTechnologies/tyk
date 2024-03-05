package storage

import (
	"context"
	"github.com/TykTechnologies/tyk/config"
)

type RedisController struct {
	connection *ConnectionHandler
}

func NewRedisController(ctx context.Context) *RedisController {
	return &RedisController{
		connection: NewConnectionHandler(ctx),
	}
}

func (rc *RedisController) ConnectToRedis(ctx context.Context, onReconnect func(), conf *config.Config) {
	rc.connection.Connect(ctx, onReconnect, conf)
}

func (rc *RedisController) DisableRedis(setRedisDown bool) {
	rc.connection.DisableStorage(setRedisDown)
}

func (rc *RedisController) Connected() bool {
	return rc.connection.Connected()
}

func (rc *RedisController) WaitConnect(ctx context.Context) bool {
	return rc.connection.WaitConnect(ctx)
}
