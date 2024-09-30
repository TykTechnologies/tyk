package streamv1

import (
	"sync/atomic"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	// ExtensionTykStreaming is the oas extension for tyk streaming
	ExtensionTykStreaming = "x-tyk-streaming"
)

type BaseMiddleware interface {
	model.LoggerProvider
}

type Gateway interface {
	model.ConfigProvider
	model.ReplaceTykVariables
}

// APISpec is a subset of gateway.APISpec for the values the middleware consumes.
type APISpec struct {
	APIID string
	Name  string
	IsOAS bool
	OAS   oas.OAS

	StripListenPath model.StripListenPathFunc
}

func NewAPISpec(id string, name string, isOasDef bool, oasDef oas.OAS, stripListenPath model.StripListenPathFunc) *APISpec {
	return &APISpec{
		APIID:           id,
		Name:            name,
		IsOAS:           isOasDef,
		OAS:             oasDef,
		StripListenPath: stripListenPath,
	}
}

// StreamsConfig represents a stream configuration
type StreamsConfig struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	Streams map[string]any `json:"streams"`
}

// Used for testing
var GlobalStreamCounter atomic.Int64
