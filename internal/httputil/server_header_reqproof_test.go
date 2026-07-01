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
// SW-REQ-160:encoding_safety:nominal
// SW-REQ-160:determinism:nominal
// SYS-REQ-173:determinism:nominal
// MCDC SYS-REQ-173: http_basic_auth_header_determined=T, http_connection_watcher_determined=T => TRUE
// MCDC SW-REQ-160: http_basic_auth_header_determined=T, http_connection_watcher_determined=T => TRUE
func TestHTTPServerHeaderHelpers(t *testing.T) {
	watcher := httputil.NewConnectionWatcher()
	assert.Equal(t, 0, watcher.Count())

	watcher.Add(2)
	assert.Equal(t, 2, watcher.Count())

	watcher.OnStateChange(nil, http.StateIdle)
	assert.Equal(t, 2, watcher.Count())

	watcher.OnStateChange(nil, http.StateClosed)
	assert.Equal(t, 1, watcher.Count())

	assert.Equal(t, "Basic dXNlcjpwYXNzd29yZA==", httputil.AuthHeader("user", "password"))
	assert.Equal(t, "Basic dXNlcjpuYW1lOnBhc3M6d29yZA==", httputil.AuthHeader("user:name", "pass:word"))
}
