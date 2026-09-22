package gateway

import (
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// upstreamConnRegistry tracks connections per address, because neither transport evicts one destination.
type upstreamConnRegistry struct {
	mu     sync.Mutex
	conns  map[string]map[*trackedConn]struct{}
	drains map[string]*pendingDrain
	closed bool
	logger *logrus.Entry
}

// pendingDrain carries cancelled because Stop cannot take back a fired timer.
type pendingDrain struct {
	timer     *time.Timer
	cancelled bool
}

func newUpstreamConnRegistry(logger *logrus.Entry) *upstreamConnRegistry {
	return &upstreamConnRegistry{
		conns:  map[string]map[*trackedConn]struct{}{},
		drains: map[string]*pendingDrain{},
		logger: logger,
	}
}

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

// drain closes every connection to addr after the deadline, so a departing backend can finish.
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

		// One critical section, or a re-dial joins the set already committed to closing.
		delete(r.drains, addr)
		tracked := r.takeAddrLocked(addr)
		r.mu.Unlock()

		if len(tracked) > 0 && r.logger != nil {
			r.logger.WithFields(logrus.Fields{
				"address":     addr,
				"connections": len(tracked),
				"deadline":    after.String(),
			}).Info("[PROXY] [DNS DISCOVERY] Drain deadline reached, closing connections to a departed upstream")
		}

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

// cancelDrainLocked flags as well as stops, to turn back an already fired callback.
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

// close retires the registry. Unload has already closed the idle connections.
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

// Close deregisters first, so a connection the transport retires leaves the books.
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
