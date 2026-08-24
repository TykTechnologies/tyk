package roundtrippers

import (
	"context"
	"io"
	"net/http"
	"slices"
)

type RoundTripper = http.RoundTripper
type Middleware func(next RoundTripper) RoundTripper

func Combine(init RoundTripper, middlewares ...Middleware) RoundTripper {
	for _, mw := range slices.Backward(middlewares) {
		if mw == nil {
			continue
		}
		init = mw(init)
	}

	return init
}

type RoundTripperFn func(*http.Request) (*http.Response, error)

func (rt RoundTripperFn) RoundTrip(request *http.Request) (*http.Response, error) {
	return rt(request)
}

type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelReadCloser) Close() error {
	c.cancel()
	if c.ReadCloser != nil {
		return c.ReadCloser.Close()
	}
	return nil
}

func invokeRtWithCancel(
	rt RoundTripper,
	req *http.Request,
	cancel context.CancelFunc,
) (response *http.Response, err error) {
	defer func() {
		if err := recover(); err != nil {
			cancel()
			panic(err)
		}
	}()

	response, err = rt.RoundTrip(req)

	if err != nil {
		cancel()
		return
	}

	if response == nil || response.Body == nil {
		cancel()
		return
	}

	response.Body = &cancelReadCloser{
		ReadCloser: response.Body,
		cancel:     cancel,
	}

	return
}
