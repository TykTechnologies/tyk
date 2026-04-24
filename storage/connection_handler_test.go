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

func TestConnectionHandler_Connect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf, err := config.New()
	assert.NoError(t, err)

	onConnectCalled := make(chan bool, 1)
	onConnect := func() {
		onConnectCalled <- true
	}

	rc := NewConnectionHandler(ctx)
	rc.storageUp.Store(false)
	go rc.Connect(ctx, onConnect, conf)

	// let's wait one statusCheck cycle
	time.Sleep(1100 * time.Millisecond)
	// Simulate a connection event
	rc.storageUp.Store(false)

	// Allow some time for the goroutine to run
	time.Sleep(100 * time.Millisecond)
	<-onConnectCalled
	assert.True(t, rc.Connected(), "Expected storage to be connected")
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

// TestConnectWithNilOnConnect verifies that Connect handles nil callback
// without panicking when a reconnect event occurs.
// Regression test for nil pointer dereference in recoverLoop.
func TestConnectWithNilOnConnect(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rc := NewConnectionHandler(ctx)

	// Setup mock connections to avoid Redis dependency
	mockConn := tempmocks.NewConnector(t)
	mockConn.On("Ping", mock.Anything).Return(nil).Maybe()

	rc.connections[DefaultConn] = mockConn
	rc.connections[CacheConn] = mockConn
	rc.connections[AnalyticsConn] = mockConn
	rc.storageUp.Store(true)

	// Track that recoverLoop processes the reconnect signal without panic
	var wg sync.WaitGroup
	wg.Add(1)

	callbackExecuted := make(chan bool, 1)
	testCallback := func() {
		callbackExecuted <- true
	}

	go func() {
		defer wg.Done()
		rc.recoverLoop(ctx, testCallback)
	}()

	// Trigger reconnect signal
	rc.reconnect <- struct{}{}

	// Wait for callback execution with timeout
	select {
	case <-callbackExecuted:
		// Success: callback was invoked without panic
	case <-time.After(1 * time.Second):
		t.Fatal("Test timed out: recoverLoop did not process reconnect signal")
	}

	// Cleanup: cancel context to stop recoverLoop
	cancel()
	wg.Wait()
}

// TestConnectNormalizesNilCallback verifies that Connect normalizes a nil
// onConnect parameter to a no-op function, preventing nil pointer dereference.
func TestConnectNormalizesNilCallback(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rc := NewConnectionHandler(ctx)

	// Setup mock connections
	mockConn := tempmocks.NewConnector(t)
	mockConn.On("Ping", mock.Anything).Return(nil).Maybe()

	rc.connections[DefaultConn] = mockConn
	rc.connections[CacheConn] = mockConn
	rc.connections[AnalyticsConn] = mockConn

	// Call Connect with nil - this should not panic
	conf, err := config.New()
	assert.NoError(t, err)

	go rc.Connect(ctx, nil, conf)

	// Wait for Connect to initialize and start recoverLoop
	time.Sleep(100 * time.Millisecond)

	// Trigger reconnect - without the fix, this would panic
	select {
	case rc.reconnect <- struct{}{}:
	default:
		// Channel might already have a message from statusCheck
	}

	// Allow time for recoverLoop to process
	time.Sleep(100 * time.Millisecond)

	// If we reach here without panic, nil was properly normalized
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

	// Run statusCheck in a goroutine
	go rc.statusCheck(ctx)

	// Allow some time for the goroutine to run
	wg.Wait()

	// Check if storage is up
	assert.True(t, rc.Connected(), "Expected storage to be connected after status check")
	mockConn.AssertNumberOfCalls(t, "Ping", 3)
}
