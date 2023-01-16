package reloadmachinery

import (
	"errors"
	"sync"
	"time"
)

var (
	// ErrNotQueued occurs in EnsureQueued(), a timeout error
	ErrNotQueued = errors.New("can't ensure a queue happened")

	// ErrNotReloaded occurs in EnsureReloaded(), a timeout error
	ErrNotReloaded = errors.New("can't ensure a reload happened")
)

// ReloadMachinery is a helper struct to use when writing tests that do manual
// gateway reloads
type ReloadMachinery struct {
	mu sync.RWMutex

	enabled bool
	count   int
	cycles  int

	// to simulate time ticks for tests that do reloads
	reloadTick chan time.Time
	stop       chan struct{}
	started    bool
}

// New creates a new instance of *ReloadMachinery
func New() *ReloadMachinery {
	return &ReloadMachinery{
		enabled:    true,
		reloadTick: make(chan time.Time),
	}
}

func (r *ReloadMachinery) StartTicker() {
	r.stop = make(chan struct{})
	r.started = true

	go func() {
		for {
			select {
			case <-r.stop:
				return
			default:
				r.Tick()
			}
		}
	}()
}

func (r *ReloadMachinery) StopTicker() {
	if r.started {
		close(r.stop)
		r.started = false
	}
}

func (r *ReloadMachinery) ReloadTicker() <-chan time.Time {
	return r.reloadTick
}

// OnQueued is called when a reload has been queued. This increments the queue
// count
func (r *ReloadMachinery) OnQueued() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.enabled {
		r.count++
	}
}

// OnReload is called when a reload has been completed. This increments the
// reload cycles count.
func (r *ReloadMachinery) OnReload() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.enabled {
		r.cycles++
	}
}

// Reloaded returns true if a read has occurred since r was enabled
func (r *ReloadMachinery) Reloaded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.cycles > 0
}

// Enable when called it will allow r to keep track of reload cycles and queues
func (r *ReloadMachinery) Enable() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.enabled = true
}

// Disable turns off tracking of reload cycles and queues
func (r *ReloadMachinery) Disable() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.enabled = false
	r.count = 0
	r.cycles = 0
}

// Reset sets reloads counts and queues to 0
func (r *ReloadMachinery) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.count = 0
	r.cycles = 0
}

// Queued returns true if any queue happened
func (r *ReloadMachinery) Queued() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.count > 0
}

// Tick triggers reload
func (r *ReloadMachinery) Tick() {
	r.reloadTick <- time.Time{}
}

// EnsureQueued this will block until any queue happens.
// It will timeout after 100ms.
func (r *ReloadMachinery) EnsureQueued() error {
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()

	timeout := time.NewTicker(100 * time.Millisecond)
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			return ErrNotQueued
		case <-tick.C:
			if r.Queued() {
				return nil
			}
		}
	}
}

// EnsureReloaded this will block until any reload happens.
// It will timeout after 200ms.
func (r *ReloadMachinery) EnsureReloaded() error {
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()

	timeout := time.NewTicker(200 * time.Millisecond)
	defer timeout.Stop()

	for {
		select {
		case <-timeout.C:
			return ErrNotReloaded
		case <-tick.C:
			if r.Reloaded() {
				return nil
			}
		}
	}
}

// TickOk triggers a reload and ensures a queue happened and a reload cycle
// happened. This function will block until a result. The error result must
// be checked in tests.
func (r *ReloadMachinery) TickOk() error {
	r.Tick()
	return r.TickState()
}

// TickState waits that any queues or reload events are registered.
// Errors on queued or reloaded timeouts.
func (r *ReloadMachinery) TickState() error {
	if err := r.EnsureQueued(); err != nil {
		return err
	}
	if err := r.EnsureReloaded(); err != nil {
		return err
	}
	return nil
}
