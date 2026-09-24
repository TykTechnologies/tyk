package roundtrippers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTimeout(t *testing.T) {
	t.Run("timeout is applied", func(t *testing.T) {
		timeout := 10 * time.Millisecond
		mw := Timeout(timeout)

		var ctx context.Context
		next := RoundTripperFn(func(r *http.Request) (*http.Response, error) {
			ctx = r.Context()
			time.Sleep(20 * time.Millisecond)
			return nil, ctx.Err()
		})

		rt := mw(next)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)

		_, err := rt.RoundTrip(req)
		require.Error(t, err)
		assert.Equal(t, context.DeadlineExceeded, err)
	})

	t.Run("timeout is not applied when 0", func(t *testing.T) {
		mw := Timeout(0)

		next := RoundTripperFn(func(r *http.Request) (*http.Response, error) {
			_, ok := r.Context().Deadline()
			assert.False(t, ok)
			return &http.Response{StatusCode: http.StatusOK}, nil
		})

		rt := mw(next)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)

		res, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})
}
