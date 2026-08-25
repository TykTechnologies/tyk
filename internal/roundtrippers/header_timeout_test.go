package roundtrippers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeadersTimeout(t *testing.T) {
	t.Run("timeout is applied when headers take too long", func(t *testing.T) {
		timeout := 10 * time.Millisecond
		mw := HeadersTimeout(timeout)

		next := RoundTripperFn(func(r *http.Request) (*http.Response, error) {
			trace := httptrace.ContextClientTrace(r.Context())
			require.NotNil(t, trace)

			// Simulate writing request
			if trace.WroteRequest != nil {
				trace.WroteRequest(httptrace.WroteRequestInfo{})
			}

			// Wait longer than timeout
			time.Sleep(20 * time.Millisecond)

			return nil, r.Context().Err()
		})

		rt := mw(next)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)

		_, err := rt.RoundTrip(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("timeout is not applied when headers arrive in time", func(t *testing.T) {
		timeout := 50 * time.Millisecond
		mw := HeadersTimeout(timeout)

		next := RoundTripperFn(func(r *http.Request) (*http.Response, error) {
			trace := httptrace.ContextClientTrace(r.Context())
			require.NotNil(t, trace)

			// Simulate writing request
			if trace.WroteRequest != nil {
				trace.WroteRequest(httptrace.WroteRequestInfo{})
			}

			// Simulate getting first byte before timeout
			if trace.GotFirstResponseByte != nil {
				trace.GotFirstResponseByte()
			}

			// Wait longer than timeout to ensure it was cancelled
			time.Sleep(60 * time.Millisecond)

			return &http.Response{StatusCode: http.StatusOK}, r.Context().Err()
		})

		rt := mw(next)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)

		res, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})
}
