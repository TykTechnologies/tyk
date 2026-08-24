package roundtrippers

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"time"
)

type headersTimeoutOpts struct {
	disabled bool
}

type HeadersTimeoutOpt func(*headersTimeoutOpts)

func HeadersTimeout(timeout time.Duration, opts ...HeadersTimeoutOpt) Middleware {
	return func(next RoundTripper) RoundTripper {
		opt := headersTimeoutOpts{disabled: false}
		for _, apply := range opts {
			apply(&opt)
		}

		if timeout == 0 || opt.disabled {
			return next
		}

		return RoundTripperFn(func(r *http.Request) (*http.Response, error) {
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()

			timer := time.NewTimer(timeout)
			timer.Stop()

			trace := &httptrace.ClientTrace{
				WroteRequest: func(_ httptrace.WroteRequestInfo) {
					timer.Reset(timeout)

					go func() {
						select {
						case <-timer.C:
							cancel()
						case <-ctx.Done():
						}
					}()
				},
				GotFirstResponseByte: func() {
					timer.Stop()
				},
			}

			ctx = httptrace.WithClientTrace(ctx, trace)
			return next.RoundTrip(r.WithContext(ctx))
		})
	}
}

func WithHeadersTimeoutDisabled(disabled bool) HeadersTimeoutOpt {
	return func(opts *headersTimeoutOpts) {
		opts.disabled = disabled
	}
}
