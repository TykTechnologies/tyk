//go:build !ee && !dev

package streams

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// httpMultiplexer mirrors the bento service.HTTPMultiplexer interface
// so that CE builds compile without importing bento.
type httpMultiplexer interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// Stream is a wrapper around stream
type Stream struct {
	allowedUnsafe []string
	streamConfig  string
	logger        *logrus.Entry
}

// NewStream creates a new stream without initializing it
func NewStream(_ []string, logger *logrus.Entry) *Stream {
	return &Stream{
		logger: logger,
	}
}

// Start is a no-op in CE builds.
func (s *Stream) Start(_ map[string]interface{}, _ httpMultiplexer) error {
	return nil
}

// Stop is a no-op in CE builds.
func (s *Stream) Stop() error {
	return nil
}

// GetConfig returns the configuration of the stream
func (s *Stream) GetConfig() string {
	return s.streamConfig
}

// Reset stops the stream
func (s *Stream) Reset() error {
	return s.Stop()
}
