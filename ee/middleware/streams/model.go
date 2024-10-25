package streams

import (
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	// ExtensionTykStreaming is the OAS extension for Tyk streaming.
	ExtensionTykStreaming = "x-tyk-streaming"
	StreamGCInterval      = 1 * time.Minute
)

// BaseMiddleware is the subset of BaseMiddleware APIs that the middleware uses.
type BaseMiddleware interface {
	model.LoggerProvider
}

// Gateway is the subset of Gateway APIs that the middleware uses.
type Gateway interface {
	model.ConfigProvider
	model.ReplaceTykVariables
}

// StreamsConfig represents a stream configuration.
type StreamsConfig struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`

	Streams map[string]any `json:"streams"`
}

// GlobalStreamCounter is used for testing.
var GlobalStreamCounter atomic.Int64
