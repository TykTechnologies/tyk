package httputil

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/TykTechnologies/tyk/config"
)

// DialContextFunc is the signature for a DialContext function.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// NewTransport creates a http transport based on gateway config and dial context function.
func NewTransport(config *config.Config, dialContext DialContextFunc) *http.Transport {
	transport := &http.Transport{
		DialContext:         dialContext,
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost, // default is 100
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return transport
}
