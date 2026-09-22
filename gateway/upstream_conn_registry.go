package gateway

import (
	"net"
	"sync"
	"time"
)

// upstreamConnRegistry tracks connections per upstream address, in the
// dialler, because neither transport can evict a single destination.
type upstreamConnRegistry struct {
	mu     sync.Mutex
	conns  map[string]map[*trackedConn]struct{}
	drains map[string]*pendingDrain
	closed bool
}

// Stop cannot take back a fired timer, so the callback re-checks cancelled.
type pendingDrain struct {
	timer     *time.Timer
	cancelled bool
}

func newUpstreamConnRegistry() *upstreamConnRegistry {
	return &upstreamConnRegistry{
		conns:  map[string]map[*trackedConn]struct{}{},
		drains: map[string]*pendingDrain{},
	}
}

// track wraps a connection so it deregisters on close.
func (r *upstreamConnRegistry) track(addr string, conn net.Conn) net.Conn {
	if r == nil || conn == nil {
		return conn
	}

	tracked := &trackedConn{Conn: conn, registry: r, addr: addr}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return conn
	}

	r.cancelDrainLocked(addr)

	if r.conns[addr] == nil {
		r.conns[addr] = map[*trackedConn]struct{}{}
	}
	r.conns[addr][tracked] = struct{}{}

	return tracked
}

// drain closes every connection to addr after the deadline, which lets a
// backend that is shutting down finish its requests.
func (r *upstreamConnRegistry) drain(addr string, after time.Duration) {
	if r == nil {
		return
	}

	if after <= 0 {
		r.closeAddr(addr)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}

	r.cancelDrainLocked(addr)

	pending := &pendingDrain{}
	pending.timer = time.AfterFunc(after, func() {
		r.mu.Lock()

		// Re-dialled, re-drained or retired since the timer fired.
		if pending.cancelled {
			r.mu.Unlock()
			return
		}

		// One critical section, or a re-dial slips a connection into the set
		// this callback has committed to closing.
		delete(r.drains, addr)
		tracked := r.takeAddrLocked(addr)
		r.mu.Unlock()

		closeTracked(tracked)
	})
	r.drains[addr] = pending
}

func (r *upstreamConnRegistry) cancelDrain(addr string) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.cancelDrainLocked(addr)
}

// The flag is what stops a callback already fired and waiting on the mutex.
func (r *upstreamConnRegistry) cancelDrainLocked(addr string) {
	pending, ok := r.drains[addr]
	if !ok {
		return
	}

	pending.cancelled = true
	pending.timer.Stop()
	delete(r.drains, addr)
}

func (r *upstreamConnRegistry) closeAddr(addr string) {
	if r == nil {
		return
	}

	r.mu.Lock()
	tracked := r.takeAddrLocked(addr)
	r.mu.Unlock()

	closeTracked(tracked)
}

func (r *upstreamConnRegistry) takeAddrLocked(addr string) map[*trackedConn]struct{} {
	tracked := r.conns[addr]
	delete(r.conns, addr)
	return tracked
}

func closeTracked(tracked map[*trackedConn]struct{}) {
	for conn := range tracked {
		conn.closeUnderlying()
	}
}

// close retires the registry. Unload has already closed the idle connections,
// so what remains has requests on it and is left alone.
func (r *upstreamConnRegistry) close() {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}
	r.closed = true

	for _, pending := range r.drains {
		pending.cancelled = true
		pending.timer.Stop()
	}
	r.drains = map[string]*pendingDrain{}
	r.conns = map[string]map[*trackedConn]struct{}{}
}

// countFor is used by tests.
func (r *upstreamConnRegistry) countFor(addr string) int {
	if r == nil {
		return 0
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.conns[addr])
}

func (r *upstreamConnRegistry) forget(conn *trackedConn) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if tracked, ok := r.conns[conn.addr]; ok {
		delete(tracked, conn)
		if len(tracked) == 0 {
			delete(r.conns, conn.addr)
		}
	}
}

type trackedConn struct {
	net.Conn

	registry *upstreamConnRegistry
	addr     string
	once     sync.Once
}

// Close deregisters first, so a connection the transport retires leaves the
// books.
func (c *trackedConn) Close() error {
	c.registry.forget(c)

	var err error
	c.once.Do(func() { err = c.Conn.Close() })
	return err
}

// closeUnderlying assumes the caller has already deregistered.
func (c *trackedConn) closeUnderlying() {
	c.once.Do(func() { _ = c.Conn.Close() })
}
