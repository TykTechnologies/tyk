package gateway

import (
	"errors"
	"sync"
	"time"
)

var errReloadMachineryTimeout = errors.New("Timed out waiting for reload to be queued")

// ReloadMachinery is a helper struct to use when writing tests that do manual
// gateway reloads
type ReloadMachinery struct {
	run    bool
	count  int
	cycles int
	mu     sync.RWMutex

	// to simulate time ticks for tests that do reloads
	reloadTick chan time.Time
	stop       chan struct{}
	started    bool
}

func NewReloadMachinery() *ReloadMachinery {
	return &ReloadMachinery{
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
	if r.run {
		r.count++
	}
}

// OnReload is called when a reload has been completed. This increments the
// reload cycles count.
func (r *ReloadMachinery) OnReload() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run {
		r.cycles++
	}
}

// Reloaded returns true if a read has occured since r was enabled
func (r *ReloadMachinery) Reloaded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cycles > 0
}

// Enable  when callled it will allow r to keep track of reload cycles and queues
func (r *ReloadMachinery) Enable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.run = true
}

// Disable turns off tracking of reload cycles and queues
func (r *ReloadMachinery) Disable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.run = true
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

// EnsureQueued this will block until any queue happens. It will timeout after
// 100ms
func (r *ReloadMachinery) EnsureQueued() error {
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()

	for {
		timeout := time.NewTimer(100 * time.Millisecond)

		select {
		case <-timeout.C:
			return errReloadMachineryTimeout
		case <-tick.C:
			if !timeout.Stop() {
				<-timeout.C
			}
			if r.Queued() {
				return nil
			}
		}
	}
}

// EnsureReloaded this will block until any reload happens. It will timeout after
// 200ms
func (r *ReloadMachinery) EnsureReloaded() error {
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		timeout := time.NewTimer(200 * time.Millisecond)

		select {
		case <-timeout.C:
			return errReloadMachineryTimeout
		case <-tick.C:
			if !timeout.Stop() {
				<-timeout.C
			}
			if r.Reloaded() {
				return nil
			}
		}
	}
}

// Tick triggers reload
func (r *ReloadMachinery) Tick() {
	r.reloadTick <- time.Time{}
}

// TickOk triggers a reload and ensures a queue happend and a reload cycle
// happens. This will block until all the cases are met.
func (r *ReloadMachinery) TickOk() error {
	if err := r.EnsureQueued(); err != nil {
		return err
	}
	r.Tick()
	return r.EnsureReloaded()
}
