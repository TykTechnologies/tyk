package gateway

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConfigureAutoMaxProcs_DisableShortCircuits confirms the early-return
// guard: when disable=true, GOMAXPROCS must remain at whatever the runtime
// already chose. Anything else would mean automaxprocs.Set ran despite the
// disable flag.
func TestConfigureAutoMaxProcs_DisableShortCircuits(t *testing.T) {
	before := runtime.GOMAXPROCS(0)
	configureAutoMaxProcs(true)
	after := runtime.GOMAXPROCS(0)
	assert.Equal(t, before, after, "disable=true must skip automaxprocs.Set")
}
