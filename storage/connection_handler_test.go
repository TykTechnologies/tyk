package storage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/assert"

	tempmocks "github.com/TykTechnologies/storage/temporal/tempmocks"

	"github.com/TykTechnologies/tyk/config"
)

func TestRecoverLoop(t *testing.T) {
	t.Parallel()

	var onReconnectCounter int
	var wg sync.WaitGroup
	wg.Add(1)
	onRecover := func() {
		onReconnectCounter++
		wg.Done()
	}
	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(t, err)

	rc := NewConnectionHandler(ctx)
	go rc.Connect(ctx, onRecover, conf)

	rc.DisableStorage(false)

	wg.Wait()
	assert.Equal(t, 1, onReconnectCounter)
}

func TestNewConnectionHandler(t *testing.T) {
	ctx := context.Background()
	handler := NewConnectionHandler(ctx)
	RunNewConnectionHandlerTest(t, handler)
}

func RunNewConnectionHandlerTest(t *testing.T, handler *ConnectionHandler) {
	t.Helper()

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.connections)
	assert.NotNil(t, handler.connectionsMu)
	assert.NotNil(t, handler.reconnect)
	assert.Equal(t, false, handler.Connected())
}

func TestConnectionHandler_statusCheckTriggersRecoverLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	onConnectCalled := make(chan bool, 1)
	onConnect := func() {
		onConnectCalled <- true
	}

	rc := NewConnectionHandler(ctx)
	rc.storageUp.Store(false)
	rc.disableStorage.Store(false)

	mockConn := tempmocks.NewConnector(t)
	mockConn.On("Ping", ctx).Return(nil)
	rc.connections[DefaultConn] = mockConn
	rc.connections[CacheConn] = mockConn
	rc.connections[AnalyticsConn] = mockConn

	go rc.recoverLoop(ctx, onConnect)
	go rc.statusCheckWithInterval(ctx, 10*time.Millisecond)

	select {
	case <-onConnectCalled:
	case <-time.After(time.Second):
		t.Fatal("ConnectionHandler.statusCheckWithInterval() did not trigger recoverLoop before timeout")
	}
	if !rc.Connected() {
		t.Error("ConnectionHandler.statusCheckWithInterval() Connected() = false, want true")
	}
}

// TestNewConnectorDefaultConn tests the creation of a new default connection.
func TestNewConnectorDefaultConn(t *testing.T) {
	conf, err := config.New()
	assert.NoError(t, err)

	conn, err := NewConnector(DefaultConn, *conf)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

// TestNewConnectorCacheConn tests the creation of a new cache connection.
func TestNewConnectorCacheConn(t *testing.T) {
	conf, err := config.New()
	assert.NoError(t, err)

	conf.EnableSeperateCacheStore = true

	conn, err := NewConnector(CacheConn, *conf)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

// TestNewConnectorAnalyticsConn tests the creation of a new analytics connection.
func TestNewConnectorAnalyticsConn(t *testing.T) {
	conf, err := config.New()
	assert.NoError(t, err)

	conf.EnableAnalytics = true
	conf.EnableSeperateAnalyticsStore = true

	conn, err := NewConnector(AnalyticsConn, *conf)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

// TestConnectionHandler_DisableStorage tests disabling the storage.
func TestConnectionHandler_DisableStorage(t *testing.T) {
	ctx := context.Background()
	rc := NewConnectionHandler(ctx)

	// Initially storage should not be disabled.
	assert.True(t, rc.enabled(), "Expected storage to be disabled initially")

	// Disable storage and test.
	rc.DisableStorage(true)
	assert.True(t, rc.disableStorage.Load().(bool), "Expected storage to be disabled")
	assert.False(t, rc.Connected(), "Expected storage to not be connected after disabling")
}

// TestConnectionHandler_Disconnect tests the disconnection of all connections.
func TestConnectionHandler_Disconnect(t *testing.T) {
	ctx := context.Background()
	rc := NewConnectionHandler(ctx)

	// Add a mock connection to the handler
	mockConn := tempmocks.NewConnector(t)
	mockConn.On("Disconnect", context.Background()).Return(nil)
	rc.connections[DefaultConn] = mockConn

	// Disconnect and test
	err := rc.Disconnect()
	assert.NoError(t, err)
	mockConn.AssertExpectations(t)
}

// TestConnectionHandler_statusCheck tests the status check routine of the connection handler.
func TestConnectionHandler_statusCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rc := NewConnectionHandler(ctx)

	numberOfCalls := 0
	wg := sync.WaitGroup{}
	wg.Add(1)
	// Add a mock connection to the handler
	mockConn := tempmocks.NewConnector(t)
	mockConn.On("Ping", ctx).Return(nil).Run(func(args mock.Arguments) {
		numberOfCalls++
		if numberOfCalls == 3 {
			wg.Done()
		}
	})

	rc.storageUp.Store(false)
	rc.disableStorage.Store(false)

	rc.connections[DefaultConn] = mockConn
	rc.connections[CacheConn] = mockConn
	rc.connections[AnalyticsConn] = mockConn

	// Run statusCheck in a goroutine with a short interval to keep the unit
	// test fast while production uses the default dampened interval.
	go rc.statusCheckWithInterval(ctx, 10*time.Millisecond)

	// Allow some time for the goroutine to run
	wg.Wait()

	// Check if storage is up
	assert.True(t, rc.Connected(), "Expected storage to be connected after status check")
	mockConn.AssertNumberOfCalls(t, "Ping", 3)
}

func TestStatusCheckInitialDelay(t *testing.T) {
	if got := statusCheckInitialDelay(time.Millisecond); got != 0 {
		t.Fatalf("statusCheckInitialDelay(time.Millisecond) = %s, want 0", got)
	}

	interval := 50 * time.Millisecond
	got := statusCheckInitialDelay(interval)
	if got < 0 || got >= interval {
		t.Fatalf("statusCheckInitialDelay(%s) = %s, want [0,%s)", interval, got, interval)
	}
}
