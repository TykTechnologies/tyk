package gateway

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var errUpstreamDeparted = errors.New("upstream address departed and its drain deadline has passed")

type upstreamSelection struct {
	generation uint64
	version    uint64
}

type upstreamConnRegistry struct {
	mu     sync.Mutex
	conns  map[string]map[*trackedConn]struct{}
	drains map[string]*time.Timer

	members    map[string]struct{}
	generation uint64
	version    uint64

	generations uint64

	released  bool
	abandoned bool
	deadline  time.Time

	logger *logrus.Entry
}

func newUpstreamConnRegistry(logger *logrus.Entry) *upstreamConnRegistry {
	return &upstreamConnRegistry{
		conns:  map[string]map[*trackedConn]struct{}{},
		drains: map[string]*time.Timer{},
		logger: logger,
	}
}

func (r *upstreamConnRegistry) newGeneration() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.generations++
	return r.generations
}

func (r *upstreamConnRegistry) track(addr string, conn net.Conn, sel upstreamSelection) (net.Conn, error) {
	if r == nil || conn == nil {
		return conn, nil
	}

	r.mu.Lock()

	if r.abandoned {
		r.mu.Unlock()
		return conn, nil
	}

	if !r.admitLocked(addr, sel) {
		r.mu.Unlock()
		_ = conn.Close()
		return nil, errUpstreamDeparted
	}

	tracked := &trackedConn{Conn: conn, registry: r, addr: addr}
	if r.conns[addr] == nil {
		r.conns[addr] = map[*trackedConn]struct{}{}
	}
	r.conns[addr][tracked] = struct{}{}

	if r.released {
		r.armLocked(addr, time.Until(r.deadline))
	}

	r.mu.Unlock()
	return tracked, nil
}

func (r *upstreamConnRegistry) admitLocked(addr string, sel upstreamSelection) bool {
	if r.released {
		return time.Now().Before(r.deadline)
	}

	if _, member := r.members[addr]; member {
		return true
	}

	if _, pending := r.drains[addr]; pending {
		return true
	}

	if sel.generation < r.generation {
		return false
	}
	if sel.generation == r.generation && sel.version < r.version {
		return false
	}

	return true
}

func (r *upstreamConnRegistry) update(gen, version uint64, addrs []string, after time.Duration) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.released || r.abandoned || gen < r.generation {
		return
	}
	if gen == r.generation && version < r.version {
		return
	}

	next := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		next[addr] = struct{}{}
	}

	for addr := range r.members {
		if _, ok := next[addr]; !ok {
			r.armLocked(addr, after)
		}
	}
	for addr := range r.conns {
		if _, ok := next[addr]; !ok {
			r.armLocked(addr, after)
		}
	}
	for addr := range next {
		r.cancelLocked(addr)
	}

	r.members = next
	r.generation = gen
	r.version = version
}

func (r *upstreamConnRegistry) armLocked(addr string, after time.Duration) {
	if _, pending := r.drains[addr]; pending {
		return
	}
	if after < 0 {
		after = 0
	}

	var timer *time.Timer
	timer = time.AfterFunc(after, func() {
		r.mu.Lock()

		if r.drains[addr] != timer {
			r.mu.Unlock()
			return
		}
		delete(r.drains, addr)
		tracked := r.conns[addr]
		delete(r.conns, addr)
		r.mu.Unlock()

		if len(tracked) > 0 && r.logger != nil {
			r.logger.WithFields(logrus.Fields{
				"address":     addr,
				"connections": len(tracked),
			}).Info("[PROXY] [DNS DISCOVERY] Drain deadline reached, closing connections to a departed upstream")
		}

		closeTracked(tracked)
	})
	r.drains[addr] = timer
}

func (r *upstreamConnRegistry) cancelLocked(addr string) {
	timer, ok := r.drains[addr]
	if !ok {
		return
	}
	timer.Stop()
	delete(r.drains, addr)
}

func (r *upstreamConnRegistry) release(after time.Duration) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.released || r.abandoned {
		return
	}
	r.released = true
	r.deadline = time.Now().Add(after)
	r.members = nil

	for addr := range r.conns {
		r.armLocked(addr, after)
	}
}

func (r *upstreamConnRegistry) abandon() {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.released || r.abandoned {
		return
	}
	r.abandoned = true
	r.members = nil

	for addr := range r.conns {
		if _, pending := r.drains[addr]; !pending {
			delete(r.conns, addr)
		}
	}
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

func closeTracked(tracked map[*trackedConn]struct{}) {
	for conn := range tracked {
		conn.closeUnderlying()
	}
}

type trackedConn struct {
	net.Conn

	registry *upstreamConnRegistry
	addr     string
	once     sync.Once
}

func (c *trackedConn) Close() error {
	c.registry.forget(c)

	var err error
	c.once.Do(func() { err = c.Conn.Close() })
	return err
}

func (c *trackedConn) closeUnderlying() {
	c.once.Do(func() { _ = c.Conn.Close() })
}

type upstreamConnRegistries struct {
	mu    sync.Mutex
	byAPI map[string]*upstreamConnRegistry
}

func (rs *upstreamConnRegistries) get(apiID string, logger *logrus.Entry) *upstreamConnRegistry {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.byAPI == nil {
		rs.byAPI = map[string]*upstreamConnRegistry{}
	}

	if current, ok := rs.byAPI[apiID]; ok {
		return current
	}

	fresh := newUpstreamConnRegistry(logger)
	rs.byAPI[apiID] = fresh
	return fresh
}

func (rs *upstreamConnRegistries) take(apiID string) *upstreamConnRegistry {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	current, ok := rs.byAPI[apiID]
	if ok {
		delete(rs.byAPI, apiID)
	}
	return current
}

func (rs *upstreamConnRegistries) release(apiID string, after time.Duration) {
	rs.take(apiID).release(after)
}

func (rs *upstreamConnRegistries) abandon(apiID string) {
	rs.take(apiID).abandon()
}
