package test

import (
	"context"
	"net"
	"net/http"
)

type (
	// Options for populating a http.Client
	ClientOption func(*http.Client)

	// Options for populating a http.Transport
	TransportOption func(*http.Transport)

	// DialContext function signature
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
)

// NewClient creates a http.Client with options
func NewClient(opts ...ClientOption) *http.Client {
	client := &http.Client{}
	applyClientOptions(client, opts...)
	return client
}

func applyClientOptions(c *http.Client, opts ...ClientOption) {
	for _, v := range opts {
		v(c)
	}
}

// NewClientLocal returns a http.Client that can connect
// only to localhost. See: `WithLocalDialer`.
func NewClientLocal(opts ...ClientOption) *http.Client {
	client := NewClient(
		WithTransport(
			NewTransport(WithLocalDialer()),
		),
	)
	applyClientOptions(client, opts...)
	return client
}

// WithTransport sets a http.RoundTripper to a http.Client
func WithTransport(transport http.RoundTripper) ClientOption {
	return ClientOption(func(c *http.Client) {
		c.Transport = transport
	})
}

// NewTransport creates a http.Transport with options
func NewTransport(opts ...TransportOption) *http.Transport {
	transport := &http.Transport{}
	for _, v := range opts {
		v(transport)
	}
	return transport
}

// WithDialer sets transport.DialContext
func WithDialer(dialer DialContext) TransportOption {
	return TransportOption(func(transport *http.Transport) {
		transport.DialContext = dialer
	})
}

// WithLocalDialer sets a http.Transport DialContext,
// which only connects to 127.0.0.1.
func WithLocalDialer() TransportOption {
	return TransportOption(func(transport *http.Transport) {
		transport.DialContext = LocalDialer()
	})
}

// LocalDialer provides a function to use to dial to localhost
func LocalDialer() func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		host := "127.0.0.1"

		dialer := net.Dialer{}
		return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	}
}
