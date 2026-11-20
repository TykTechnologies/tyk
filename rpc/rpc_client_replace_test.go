package rpc

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func countGoroutines(frame string) int {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]

	n := 0
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(stack, frame) {
			n++
		}
	}
	return n
}

// Connect racing a DNS reconnect must not leave a started client without a reference.
func TestConnectAndReconnect_NoOrphanedClient(t *testing.T) {
	const (
		handlerFrame = "gorpc.clientHandler("
		loginFrame   = "rpc.loginBase("
		iterations   = 300
	)

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	require.Zero(t, countGoroutines(handlerFrame))

	cfg := Config{ConnectionString: addr, APIKey: "test", RPCPoolSize: 1}
	funcs := map[string]interface{}{
		"Login": func(_, _ string) bool { return false },
	}

	values.Reset()
	require.True(t, Connect(cfg, true, funcs, nil, nil, nil) || IsEmergencyMode())

	for range iterations {
		var wg sync.WaitGroup
		start := make(chan struct{})

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			defaultSafeReconnectRPCClient(true)
		}()
		go func() {
			defer wg.Done()
			<-start
			Connect(cfg, true, funcs, nil, nil, nil)
		}()

		close(start)
		wg.Wait()
	}

	require.Eventually(t, func() bool {
		return countGoroutines(loginFrame) == 0
	}, 30*time.Second, 50*time.Millisecond)

	Reset()

	assert.Zero(t, countGoroutines(handlerFrame), "clients left running after the only referenced one was stopped")
}
