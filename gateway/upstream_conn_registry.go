package gateway

import (
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const departedRetention = 5 * time.Minute

// upstreamConnRegistry tracks connections per address, because neither transport evicts one destination.
// track and retire tolerate a nil receiver: an API with draining disabled has no registry.
type upstreamConnRegistry struct {
	mu       sync.Mutex
	conns    map[string]map[*trackedConn]struct{}
	drains   map[string]*pendingDrain
	departed map[string]departure
	closed   bool
	logger   *logrus.Entry

	members     map[string]struct{}
	memberDrain time.Duration
}

type departure struct {
	after time.Duration
	at    time.Time
}

// pendingDrain carries cancelled because Stop cannot take back a fired timer.
type pendingDrain struct {
	timer     *time.Timer
	cancelled bool
}

func newUpstreamConnRegistry(logger *logrus.Entry) *upstreamConnRegistry {
	return &upstreamConnRegistry{
		conns:    map[string]map[*trackedConn]struct{}{},
		drains:   map[string]*pendingDrain{},
		departed: map[string]departure{},
		logger:   logger,
	}
}

func (r *upstreamConnRegistry) track(addr string, conn net.Conn) net.Conn {
	if r == nil || conn == nil {
		return conn
	}

	tracked := &trackedConn{Conn: conn, registry: r, addr: addr}

	r.mu.Lock()

	if r.closed {
		r.mu.Unlock()
		return conn
	}

	if r.conns[addr] == nil {
		r.conns[addr] = map[*trackedConn]struct{}{}
	}
	r.conns[addr][tracked] = struct{}{}

	_, departed := r.departed[addr]
	if !departed {
		if _, member := r.members[addr]; r.members == nil || member {
			r.mu.Unlock()
			return tracked
		}
		stale := r.drainLocked(addr, r.memberDrain)
		r.mu.Unlock()
		closeTracked(stale)
		return tracked
	}

	if _, pending := r.drains[addr]; pending {
		r.mu.Unlock()
		return tracked
	}

	stale := r.takeAddrLocked(addr)
	r.mu.Unlock()
	closeTracked(stale)

	return tracked
}

// drain closes every connection to addr after the deadline, so a departing backend can finish.
func (r *upstreamConnRegistry) drain(addr string, after time.Duration) {
	if r == nil {
		return
	}

	r.mu.Lock()

	if r.closed {
		r.mu.Unlock()
		return
	}

	tracked := r.drainLocked(addr, after)
	r.mu.Unlock()
	closeTracked(tracked)
}

func (r *upstreamConnRegistry) drainLocked(addr string, after time.Duration) map[*trackedConn]struct{} {
	r.pruneDepartedLocked()

	if _, pending := r.drains[addr]; pending {
		return nil
	}

	r.departed[addr] = departure{after: after, at: time.Now()}

	if after > 0 {
		r.armDrainLocked(addr, after)
		return nil
	}

	return r.takeAddrLocked(addr)
}

func (r *upstreamConnRegistry) reconcile(members map[string]struct{}, after time.Duration) {
	if r == nil {
		return
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.members = members
	r.memberDrain = after
	if members == nil {
		r.mu.Unlock()
		return
	}

	var absent []string
	for addr := range r.conns {
		if _, ok := members[addr]; ok {
			continue
		}
		if _, pending := r.drains[addr]; pending {
			continue
		}
		absent = append(absent, addr)
	}
	r.mu.Unlock()

	for _, addr := range absent {
		r.drain(addr, after)
	}
}

func (r *upstreamConnRegistry) armDrainLocked(addr string, after time.Duration) {
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
				"timeout":     after.String(),
			}).Info("[PROXY] [DNS DISCOVERY] Drain timeout reached, closing connections to a departed upstream")
		}

		closeTracked(tracked)
	})
	r.drains[addr] = pending
}

func (r *upstreamConnRegistry) pruneDepartedLocked() {
	now := time.Now()
	for addr, gone := range r.departed {
		if _, pending := r.drains[addr]; pending {
			continue
		}
		if now.Sub(gone.at) > gone.after+departedRetention {
			delete(r.departed, addr)
		}
	}
}

func (r *upstreamConnRegistry) cancelDrain(addr string) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.cancelDrainLocked(addr)
	delete(r.departed, addr)
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

func (r *upstreamConnRegistry) retire(after time.Duration) {
	if r == nil {
		return
	}

	r.mu.Lock()

	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true

	var immediate []map[*trackedConn]struct{}
	for addr := range r.conns {
		if _, pending := r.drains[addr]; pending {
			continue
		}
		if after > 0 {
			r.armDrainLocked(addr, after)
			continue
		}
		immediate = append(immediate, r.takeAddrLocked(addr))
	}
	r.departed = map[string]departure{}
	r.mu.Unlock()

	for _, tracked := range immediate {
		closeTracked(tracked)
	}
}

func (r *upstreamConnRegistry) abandon() {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}
	r.closed = true

	for addr := range r.conns {
		if _, pending := r.drains[addr]; !pending {
			delete(r.conns, addr)
		}
	}
	r.departed = map[string]departure{}
	r.members = nil
}

func (r *upstreamConnRegistry) countFor(addr string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.conns[addr])
}

func (r *upstreamConnRegistry) forget(conn *trackedConn) {
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

type upstreamConnRegistries struct {
	mu    sync.Mutex
	byAPI map[string]*registryClaim
}

type registryClaim struct {
	registry *upstreamConnRegistry
	owner    any
}

func (rs *upstreamConnRegistries) claim(apiID string, owner any, fresh *upstreamConnRegistry) *upstreamConnRegistry {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.byAPI == nil {
		rs.byAPI = map[string]*registryClaim{}
	}

	if current, ok := rs.byAPI[apiID]; ok {
		current.owner = owner
		return current.registry
	}

	rs.byAPI[apiID] = &registryClaim{registry: fresh, owner: owner}
	return fresh
}

func (rs *upstreamConnRegistries) release(apiID string, owner any, after time.Duration) {
	rs.mu.Lock()
	current, ok := rs.byAPI[apiID]
	if !ok || current.owner != owner {
		rs.mu.Unlock()
		return
	}
	delete(rs.byAPI, apiID)
	rs.mu.Unlock()

	current.registry.retire(after)
}

func (rs *upstreamConnRegistries) abandon(apiID string) {
	rs.mu.Lock()
	current, ok := rs.byAPI[apiID]
	delete(rs.byAPI, apiID)
	rs.mu.Unlock()

	if ok {
		current.registry.abandon()
	}
}
