package roundtrippers

import (
	"context"
	"net/http"
	"time"
)

func Timeout(timeout time.Duration) Middleware {
	return func(next RoundTripper) RoundTripper {
		if timeout == 0 {
			return next
		}

		return RoundTripperFn(func(r *http.Request) (*http.Response, error) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			return invokeRtWithCancel(next, r.WithContext(ctx), cancel)
		})
	}
}
