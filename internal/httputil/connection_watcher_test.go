package httputil_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

// Verifies: STK-REQ-085, SYS-REQ-173, SW-REQ-160
// STK-REQ-085:STK-REQ-085-AC-01:acceptance
// SW-REQ-160:nominal:nominal
// SW-REQ-160:boundary:nominal
// SW-REQ-160:determinism:nominal
func TestConnectionWatcher(t *testing.T) {
	t.Run("explicit count deltas", func(t *testing.T) {
		w := httputil.NewConnectionWatcher()
		assert.Equal(t, 0, w.Count())

		tests := []struct {
			name  string
			delta int64
			want  int
		}{
			{name: "increment one", delta: 1, want: 1},
			{name: "increment two", delta: 2, want: 3},
			{name: "decrement to zero", delta: -3, want: 0},
			{name: "decrement below zero follows delta", delta: -1, want: -1},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w.Add(tt.delta)
				assert.Equal(t, tt.want, w.Count())
			})
		}
	})

	t.Run("connection state deltas", func(t *testing.T) {
		w := httputil.NewConnectionWatcher()
		tests := []struct {
			name  string
			state http.ConnState
			want  int
		}{
			{name: "new increments", state: http.StateNew, want: 1},
			{name: "active leaves count unchanged", state: http.StateActive, want: 1},
			{name: "idle leaves count unchanged", state: http.StateIdle, want: 1},
			{name: "closed decrements", state: http.StateClosed, want: 0},
			{name: "hijacked decrements", state: http.StateHijacked, want: -1},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w.OnStateChange(nil, tt.state)
				assert.Equal(t, tt.want, w.Count())
			})
		}
	})
}
