package roundtrippers

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/internal/errors"
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

		return RoundTripperFn(func(r *http.Request) (response *http.Response, err error) {
			ctx, cancel := context.WithCancel(r.Context())

			timer := time.NewTimer(timeout)
			timer.Stop()

			var timedOut atomic.Bool

			trace := &httptrace.ClientTrace{
				WroteRequest: func(_ httptrace.WroteRequestInfo) {
					timer.Reset(timeout)

					go func() {
						select {
						case <-timer.C:
							timedOut.Store(true)
							cancel()
						case <-ctx.Done():
						}
					}()
				},
				GotFirstResponseByte: func() {
					timer.Stop()
				},
			}

			response, err = invokeRtWithCancel(
				next,
				r.WithContext(httptrace.WithClientTrace(ctx, trace)),
				cancel,
			)

			if err != nil && timedOut.Load() {
				err = errors.Join(err, ErrHeadersTimeout)
			}

			return
		})
	}
}

func WithHeadersTimeoutDisabled(disabled bool) HeadersTimeoutOpt {
	return func(opts *headersTimeoutOpts) {
		opts.disabled = disabled
	}
}
