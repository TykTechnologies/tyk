package gateway

import (
	"net"
	"sync"
	"time"
)

// upstreamConnRegistry tracks the connections an API holds per upstream
// address, so connections to a departed address can be closed rather than
// waited out.
//
// It goes through the dialler because neither pool can evict one destination:
// both expose only CloseIdleConnections, which closes everything.
type upstreamConnRegistry struct {
	mu     sync.Mutex
	conns  map[string]map[*trackedConn]struct{}
	drains map[string]*pendingDrain
	closed bool
}

// pendingDrain is one scheduled close for an address. Stop cannot take back a
// timer that has already fired, so a callback waiting on the mutex checks
// cancelled before closing anything — otherwise it closes the connection its
// replacement was protecting.
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

// track records a dialled connection and returns it wrapped so it deregisters
// itself on close. Dialling also cancels any drain pending for that address.
func (r *upstreamConnRegistry) track(addr string, conn net.Conn) net.Conn {
	if r == nil || conn == nil {
		return conn
	}

	tracked := &trackedConn{Conn: conn, registry: r, addr: addr}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		// The API is gone; hand it back untracked.
		return conn
	}

	r.cancelDrainLocked(addr)

	if r.conns[addr] == nil {
		r.conns[addr] = map[*trackedConn]struct{}{}
	}
	r.conns[addr][tracked] = struct{}{}

	return tracked
}

// drain closes the connections to addr once after has elapsed, replacing any
// pending drain. Zero or less closes at once.
//
// The delay is the point: a backend removed from a Service keeps serving until
// its shutdown completes, so closing now would cut requests that would finish.
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

		// Re-dialled, re-drained, or retired between this timer firing and it
		// reaching the mutex.
		if pending.cancelled {
			r.mu.Unlock()
			return
		}

		// Deciding to close and taking the connections must be one critical
		// section: a gap lets a re-dial register a connection this callback
		// has already committed to closing.
		delete(r.drains, addr)
		tracked := r.takeAddrLocked(addr)
		r.mu.Unlock()

		closeTracked(tracked)
	})
	r.drains[addr] = pending
}

// cancelDrain stops a pending drain, for an address that returned to the set
// before its deadline arrived.
func (r *upstreamConnRegistry) cancelDrain(addr string) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.cancelDrainLocked(addr)
}

// cancelDrainLocked retires addr's pending drain. The flag is what stops a
// callback that has already fired.
func (r *upstreamConnRegistry) cancelDrainLocked(addr string) {
	pending, ok := r.drains[addr]
	if !ok {
		return
	}

	pending.cancelled = true
	pending.timer.Stop()
	delete(r.drains, addr)
}

// closeAddr closes every connection held to addr.
func (r *upstreamConnRegistry) closeAddr(addr string) {
	if r == nil {
		return
	}

	r.mu.Lock()
	tracked := r.takeAddrLocked(addr)
	r.mu.Unlock()

	closeTracked(tracked)
}

// takeAddrLocked removes addr's connections so the caller can close them off
// the lock.
func (r *upstreamConnRegistry) takeAddrLocked(addr string) map[*trackedConn]struct{} {
	tracked := r.conns[addr]
	delete(r.conns, addr)
	return tracked
}

// closeTracked closes connections the registry has already let go of.
func closeTracked(tracked map[*trackedConn]struct{}) {
	for conn := range tracked {
		conn.closeUnderlying()
	}
}

// close retires the registry on API unload: drains cancelled, nothing further
// tracked.
//
// The connections are left alone. Unload has already called Retire, which
// closes the idle ones, so what remains has requests on it. Severing those
// would cut streams mid-flight; they close themselves once their last stream
// ends, via the pool's idle timeout.
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

// countFor reports how many connections are held to addr. Used by tests.
func (r *upstreamConnRegistry) countFor(addr string) int {
	if r == nil {
		return 0
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.conns[addr])
}

// forget removes conn, however it came to be closed.
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

// trackedConn is a connection the registry can close on its own initiative.
type trackedConn struct {
	net.Conn

	registry *upstreamConnRegistry
	addr     string
	once     sync.Once
}

// Close deregisters first, so a connection the pool retires does not stay on
// the books.
func (c *trackedConn) Close() error {
	c.registry.forget(c)

	var err error
	c.once.Do(func() { err = c.Conn.Close() })
	return err
}

// closeUnderlying closes a connection the caller has already deregistered.
func (c *trackedConn) closeUnderlying() {
	c.once.Do(func() { _ = c.Conn.Close() })
}
