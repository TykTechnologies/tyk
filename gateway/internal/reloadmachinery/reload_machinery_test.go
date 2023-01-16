package reloadmachinery_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/gateway/internal/reloadmachinery"
)

var (
	ErrNotQueued   = reloadmachinery.ErrNotQueued
	ErrNotReloaded = reloadmachinery.ErrNotReloaded
)

func TestReloadMachinery(t *testing.T) {
	r := reloadmachinery.New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Read all ticker events as they come in until we stop the test.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.ReloadTicker():
				r.OnQueued()
				// real code does some reloading things here
				r.OnReload()
				continue
			}
		}
	}()

	r.Disable()
	r.Tick()

	assert.ErrorIs(t, r.EnsureQueued(), ErrNotQueued)
	assert.ErrorIs(t, r.EnsureReloaded(), ErrNotReloaded)
	assert.ErrorIs(t, r.TickState(), ErrNotQueued)

	r.Enable()

	assert.ErrorIs(t, r.EnsureQueued(), ErrNotQueued)
	assert.ErrorIs(t, r.EnsureReloaded(), ErrNotReloaded)
	assert.ErrorIs(t, r.TickState(), ErrNotQueued)

	r.OnQueued()

	assert.NoError(t, r.EnsureQueued())
	assert.ErrorIs(t, r.EnsureReloaded(), ErrNotReloaded)
	assert.ErrorIs(t, r.TickState(), ErrNotReloaded)

	r.OnReload()

	assert.NoError(t, r.EnsureQueued())
	assert.NoError(t, r.EnsureReloaded())
	assert.NoError(t, r.TickState())

	r.Reset()

	assert.ErrorIs(t, r.EnsureQueued(), ErrNotQueued)
	assert.ErrorIs(t, r.EnsureReloaded(), ErrNotReloaded)
	assert.ErrorIs(t, r.TickState(), ErrNotQueued)

	r.StartTicker()
	time.Sleep(2 * time.Millisecond)
	r.StopTicker()

	assert.NoError(t, r.EnsureQueued())
	assert.NoError(t, r.EnsureReloaded())
	assert.NoError(t, r.TickState())

	r.Reset()

	assert.NoError(t, r.TickOk())
}
