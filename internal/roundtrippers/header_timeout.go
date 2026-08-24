package roundtrippers

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/internal/errors"
)

type headersTimeoutOpt struct {
	disabled   bool
	disabledFn func(*http.Request) bool
}

type HeadersTimeoutOpt func(*headersTimeoutOpt)

func HeadersTimeout(timeout time.Duration, opts ...HeadersTimeoutOpt) Middleware {
	return func(next RoundTripper) RoundTripper {
		opt := headersTimeoutOpt{disabled: false}
		for _, apply := range opts {
			apply(&opt)
		}

		if timeout == 0 || opt.disabled {
			return next
		}

		return RoundTripperFn(func(r *http.Request) (response *http.Response, err error) {
			if opt.disabledFn != nil && opt.disabledFn(r) {
				return next.RoundTrip(r)
			}

			ctx, cancel := context.WithCancel(r.Context())

			// The tracker takes full ownership of the state
			tracker := newHeadersTimeoutTracker(ctx, timeout, cancel)
			defer tracker.Stop()

			trace := &httptrace.ClientTrace{
				WroteRequest:         tracker.OnWroteRequest,
				GotFirstResponseByte: tracker.OnGotFirstByte,
			}

			response, err = invokeRtWithCancel(
				next,
				r.WithContext(httptrace.WithClientTrace(ctx, trace)),
				cancel,
			)

			if err != nil && tracker.HasTimedOut() {
				err = errors.Join(err, ErrHeadersTimeout)
			}

			return
		})
	}
}

func WithHeadersTimeoutDisabled(disabled bool) HeadersTimeoutOpt {
	return func(opts *headersTimeoutOpt) {
		opts.disabled = disabled
	}
}

func WithHeadersTimeoutDisableFn(disabledFn func(*http.Request) bool) HeadersTimeoutOpt {
	return func(opt *headersTimeoutOpt) {
		opt.disabledFn = disabledFn
	}
}

// headersTimeoutTracker encapsulates state and synchronization for the headers timeout.
type headersTimeoutTracker struct {
	mu       sync.Mutex
	timer    *time.Timer
	timedOut atomic.Bool

	ctx     context.Context
	timeout time.Duration
	cancel  context.CancelFunc
}

// newHeadersTimeoutTracker is a factory initializing the tracker's state.
func newHeadersTimeoutTracker(
	ctx context.Context,
	timeout time.Duration,
	cancel context.CancelFunc,
) *headersTimeoutTracker {

	return &headersTimeoutTracker{
		ctx:     ctx,
		timeout: timeout,
		cancel:  cancel,
	}
}

// OnWroteRequest matches the httptrace.WroteRequest signature.
func (t *headersTimeoutTracker) OnWroteRequest(_ httptrace.WroteRequestInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If the request was already canceled (e.g., lower-level error), ignore the timer.
	if t.ctx.Err() != nil {
		return
	}

	t.timer = time.AfterFunc(t.timeout, func() {
		t.timedOut.Store(true)
		t.cancel()
	})
}

// OnGotFirstByte matches the httptrace.GotFirstResponseByte signature.
func (t *headersTimeoutTracker) OnGotFirstByte() {
	t.Stop()
}

// Stop unconditionally stops the timer and prevents leaks.
func (t *headersTimeoutTracker) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.timer != nil {
		t.timer.Stop()
	}
}

// HasTimedOut returns whether the timeout actually triggered.
func (t *headersTimeoutTracker) HasTimedOut() bool {
	return t.timedOut.Load()
}
