package httputil

import (
	"net"
	"net/http"
	"sync/atomic"
)

// ConnectionWatcher counts http server connections.
type ConnectionWatcher struct {
	n int64
}

// NewConnectionWatcher returns a new *ConnectionWatcher.
// SW-REQ-160
func NewConnectionWatcher() *ConnectionWatcher {
	return &ConnectionWatcher{}
}

// OnStateChange records open connections in response to connection
// state changes. Set net/http Server.ConnState to this method
// as value.
// SW-REQ-160
func (cw *ConnectionWatcher) OnStateChange(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		cw.Add(1)
	case http.StateHijacked, http.StateClosed:
		cw.Add(-1)
	}
}

// Count returns the number of connections at the time the call.
// SW-REQ-160
func (cw *ConnectionWatcher) Count() int {
	return int(atomic.LoadInt64(&cw.n))
}

// Add adds c to the number of active connections.
// SW-REQ-160
func (cw *ConnectionWatcher) Add(c int64) {
	atomic.AddInt64(&cw.n, c)
}
