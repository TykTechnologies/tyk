package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	tempmocks "github.com/TykTechnologies/storage/temporal/tempmocks"

	"github.com/TykTechnologies/tyk/config"
)

// Verifies: STK-REQ-095, SYS-REQ-183, SW-REQ-170
// SW-REQ-170:nominal:nominal
// SW-REQ-170:boundary:nominal
// SW-REQ-170:error_handling:nominal
// SW-REQ-170:encoding_safety:nominal
// SW-REQ-170:determinism:nominal
// SYS-REQ-183:determinism:nominal
// MCDC SYS-REQ-183: storage_connection_handler_backoff_determined=T, storage_connection_handler_connector_slots_determined=T, storage_connection_handler_redis_options_determined=T, storage_connection_handler_shim_delegation_determined=T, storage_connection_handler_state_determined=T, storage_connection_handler_status_disconnect_determined=T, storage_connection_handler_wait_reconnect_determined=T => TRUE
// MCDC SW-REQ-170: storage_connection_handler_backoff_determined=T, storage_connection_handler_connector_slots_determined=T, storage_connection_handler_redis_options_determined=T, storage_connection_handler_shim_delegation_determined=T, storage_connection_handler_state_determined=T, storage_connection_handler_status_disconnect_determined=T, storage_connection_handler_wait_reconnect_determined=T => TRUE
func TestStorageConnectionHandlerReqProof(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler := NewConnectionHandler(ctx)
	require.NotNil(t, handler.connections)
	require.NotNil(t, handler.connectionsMu)
	require.NotNil(t, handler.reconnect)
	assert.False(t, handler.Connected())
	assert.True(t, handler.enabled())

	handler.DisableStorage(true)
	assert.False(t, handler.enabled())
	assert.False(t, handler.Connected())

	handler.storageUp.Store(true)
	waitCtx, waitCancel := context.WithTimeout(ctx, time.Second)
	defer waitCancel()
	assert.True(t, handler.WaitConnect(waitCtx))

	cancelledCtx, cancelled := context.WithCancel(ctx)
	cancelled()
	assert.False(t, handler.WaitConnect(cancelledCtx))

	reconnectCtx, reconnectCancel := context.WithCancel(ctx)
	defer reconnectCancel()
	reconnected := make(chan struct{}, 1)
	go handler.recoverLoop(reconnectCtx, func() {
		reconnected <- struct{}{}
	})
	handler.reconnect <- struct{}{}
	select {
	case <-reconnected:
	case <-time.After(time.Second):
		t.Fatal("expected reconnect callback")
	}

	defaultConn := tempmocks.NewConnector(t)
	cacheConn := tempmocks.NewConnector(t)
	analyticsConn := tempmocks.NewConnector(t)
	handler.connections[DefaultConn] = defaultConn
	handler.connections[CacheConn] = cacheConn
	handler.connections[AnalyticsConn] = analyticsConn
	assert.Same(t, defaultConn, handler.getConnection(false, false))
	assert.Same(t, cacheConn, handler.getConnection(true, false))
	assert.Same(t, analyticsConn, handler.getConnection(false, true))

	statusHandler := NewConnectionHandler(ctx)
	var pingWG sync.WaitGroup
	pingWG.Add(3)
	statusConn := tempmocks.NewConnector(t)
	statusConn.On("Ping", mock.Anything).Return(nil).Run(func(mock.Arguments) {
		pingWG.Done()
	})
	statusHandler.connections[DefaultConn] = statusConn
	statusHandler.connections[CacheConn] = statusConn
	statusHandler.connections[AnalyticsConn] = statusConn
	statusHandler.storageUp.Store(false)
	statusHandler.disableStorage.Store(false)

	statusCtx, statusCancel := context.WithCancel(ctx)
	go statusHandler.statusCheck(statusCtx)
	pingWG.Wait()
	statusCancel()
	assert.True(t, statusHandler.Connected())

	disconnectErr := errors.New("disconnect failed")
	disconnectConn := tempmocks.NewConnector(t)
	disconnectConn.On("Disconnect", context.Background()).Return(disconnectErr)
	disconnectHandler := NewConnectionHandler(ctx)
	disconnectHandler.connections[DefaultConn] = disconnectConn
	assert.ErrorIs(t, disconnectHandler.Disconnect(), disconnectErr)

	conf, err := config.New()
	require.NoError(t, err)
	conf.Storage.MaxActive = 7
	conf.Storage.Timeout = 3
	conf.Storage.UseSSL = true
	conf.EnableSeperateCacheStore = true
	conf.EnableAnalytics = true
	conf.EnableSeperateAnalyticsStore = true
	require.NoError(t, handler.initConnection(*conf))
	assert.NotNil(t, handler.connections[DefaultConn])
	assert.NotNil(t, handler.connections[CacheConn])
	assert.NotNil(t, handler.connections[AnalyticsConn])

	for _, connType := range []string{DefaultConn, CacheConn, AnalyticsConn} {
		conn, err := NewConnector(connType, *conf)
		require.NoError(t, err)
		assert.NotNil(t, conn)
	}

	backoff := getExponentialBackoff()
	assert.Equal(t, float64(2), backoff.Multiplier)
	assert.Equal(t, 10*time.Second, backoff.MaxInterval)
	assert.Equal(t, time.Duration(0), backoff.MaxElapsedTime)

	shimCtx, shimCancel := context.WithCancel(context.Background())
	defer shimCancel()
	redisController := NewRedisController(shimCtx)
	require.NotNil(t, redisController.connection)
	redisController.DisableRedis(true)
	assert.False(t, redisController.Connected())

	redisController.connection.storageUp.Store(true)
	assert.True(t, redisController.WaitConnect(shimCtx))

}
