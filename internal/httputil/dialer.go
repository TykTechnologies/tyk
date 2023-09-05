package httputil

import (
	"net"
	"time"
)

// DefaultDialerTimeout holds the default dialer timeout value in seconds.
const DefaultDialerTimeout = 30 * time.Second

// NewDialer creates a net.Dialer with KeepAlive/Timeout set to `timeout` in seconds.
func NewDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		DualStack: true,
		KeepAlive: timeout,
		Timeout:   timeout,
	}
}
