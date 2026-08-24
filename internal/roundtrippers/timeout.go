package roundtrippers

import (
	"context"
	"net/http"
	"time"
)

type timeoutOpt struct {
	disabled   bool
	disabledFn func(*http.Request) bool
}

type TimeoutOpt func(*timeoutOpt)

func Timeout(timeout time.Duration, opts ...TimeoutOpt) Middleware {
	return func(next RoundTripper) RoundTripper {
		opt := timeoutOpt{disabled: false}
		for _, apply := range opts {
			apply(&opt)
		}

		if timeout == 0 || opt.disabled {
			return next
		}

		return RoundTripperFn(func(r *http.Request) (*http.Response, error) {
			if opt.disabledFn != nil && opt.disabledFn(r) {
				return next.RoundTrip(r)
			}

			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			return invokeRtWithCancel(next, r.WithContext(ctx), cancel)
		})
	}
}

func WithTimeoutDisable(disabled bool) TimeoutOpt {
	return func(opt *timeoutOpt) {
		opt.disabled = disabled
	}
}

func WithTimeoutDisableFn(disabledFn func(*http.Request) bool) TimeoutOpt {
	return func(opt *timeoutOpt) {
		opt.disabledFn = disabledFn
	}
}
