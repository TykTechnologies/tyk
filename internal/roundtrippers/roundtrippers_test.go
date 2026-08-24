package roundtrippers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCombine(t *testing.T) {
	t.Run("combines middlewares in correct order", func(t *testing.T) {
		var order []string

		mw1 := func(next RoundTripper) RoundTripper {
			return RoundTripperFn(func(r *http.Request) (*http.Response, error) {
				order = append(order, "mw1-before")
				res, err := next.RoundTrip(r)
				order = append(order, "mw1-after")
				return res, err
			})
		}

		mw2 := func(next RoundTripper) RoundTripper {
			return RoundTripperFn(func(r *http.Request) (*http.Response, error) {
				order = append(order, "mw2-before")
				res, err := next.RoundTrip(r)
				order = append(order, "mw2-after")
				return res, err
			})
		}

		init := RoundTripperFn(func(r *http.Request) (*http.Response, error) {
			order = append(order, "init")
			return &http.Response{StatusCode: http.StatusOK}, nil
		})

		rt := Combine(init, mw1, mw2)
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		
		res, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		expectedOrder := []string{"mw1-before", "mw2-before", "init", "mw2-after", "mw1-after"}
		assert.Equal(t, expectedOrder, order)
	})

	t.Run("ignores nil middlewares", func(t *testing.T) {
		var called bool
		mw1 := func(next RoundTripper) RoundTripper {
			return RoundTripperFn(func(r *http.Request) (*http.Response, error) {
				called = true
				return next.RoundTrip(r)
			})
		}

		init := RoundTripperFn(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK}, nil
		})

		rt := Combine(init, nil, mw1, nil)
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		
		res, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.True(t, called)
	})
}
