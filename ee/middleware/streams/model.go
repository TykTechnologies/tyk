package streams

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/redis"
)

type KafkaTelemetrySnapshot struct {
	APIID, StreamID, ComponentID string
	Deltas                       map[string]uint64
	State                        map[string]int64
}

type KafkaTelemetryRecorder interface {
	RecordKafkaStreams(context.Context, KafkaTelemetrySnapshot)
}

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
	StreamingRedisClient() (redis.UniversalClient, error)
}

// APISpec is a subset of gateway.APISpec for the values the middleware consumes.
type APISpec struct {
	APIID string
	Name  string
	IsOAS bool
	OAS   oas.OAS

	StripListenPath model.StripListenPathFunc
}

// NewAPISpec creates a new APISpec object based on the required inputs.
// The resulting object is a subset of `*gateway.APISpec`.
func NewAPISpec(id string, name string, isOasDef bool, oasDef oas.OAS, stripListenPath model.StripListenPathFunc) *APISpec {
	return &APISpec{
		APIID:           id,
		Name:            name,
		IsOAS:           isOasDef,
		OAS:             oasDef,
		StripListenPath: stripListenPath,
	}
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
