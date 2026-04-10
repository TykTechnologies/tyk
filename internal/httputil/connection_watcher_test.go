package httputil_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

func TestConnectionWatcher(t *testing.T) {
	w := httputil.NewConnectionWatcher()
	w.Add(1)
	assert.Equal(t, 1, w.Count())
	w.Add(2)
	assert.Equal(t, 3, w.Count())
	w.Add(-3)
	assert.Equal(t, 0, w.Count())

	w.OnStateChange(nil, http.StateNew)
	assert.Equal(t, 1, w.Count())

	w.OnStateChange(nil, http.StateClosed)
	w.OnStateChange(nil, http.StateHijacked)
	assert.Equal(t, -1, w.Count())

}
