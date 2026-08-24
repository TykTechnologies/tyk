package roundtrippers

import (
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
