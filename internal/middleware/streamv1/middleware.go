package streamv1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/streaming"
)

// Middleware implements a streaming middleware.
type Middleware struct {
	Spec *APISpec
	Gw   Gateway

	base BaseMiddleware

	streamManagers sync.Map // Map of consumer group IDs to Manager

	ctx            context.Context
	cancel         context.CancelFunc
	allowedUnsafe  []string
	defaultManager *Manager
}

// Middleware implements model.Middleware.
var _ model.Middleware = &Middleware{}

// NewMiddleware returns a new instance of Middleware.
func NewMiddleware(gw Gateway, mw BaseMiddleware, spec *APISpec) *Middleware {
	return &Middleware{
		base: mw,
		Gw:   gw,
		Spec: spec,
	}
}

// Logger returns a logger with middleware filled out.
func (s *Middleware) Logger() *logrus.Entry {
	return s.base.Logger().WithField("mw", s.Name())
}

// Name returns the name for the middleware.
func (s *Middleware) Name() string {
	return "Middleware"
}

// EnabledForSpec checks if streaming is enabled on the config.
func (s *Middleware) EnabledForSpec() bool {
	s.Logger().Debug("Checking if streaming is enabled")

	streamingConfig := s.Gw.GetConfig().Streaming
	s.Logger().Debugf("Streaming config: %+v", streamingConfig)

	if streamingConfig.Enabled {
		s.Logger().Debug("Streaming is enabled in the config")
		s.allowedUnsafe = streamingConfig.AllowUnsafe
		s.Logger().Debugf("Allowed unsafe components: %v", s.allowedUnsafe)

		config := s.getStreamsConfig(nil)
		GlobalStreamCounter.Add(int64(len(config.Streams)))

		s.Logger().Debug("Total streams count: ", len(config.Streams))

		return len(config.Streams) != 0
	}

	s.Logger().Debug("Streaming is not enabled in the config")
	return false
}

// Init initializes the middleware
func (s *Middleware) Init() {
	s.Logger().Debug("Initializing Middleware")
	s.ctx, s.cancel = context.WithCancel(context.Background())

	s.Logger().Debug("Initializing default stream manager")
	s.defaultManager = NewManager(s, nil)
}

func (s *Middleware) getStreamsConfig(r *http.Request) *StreamsConfig {
	config := &StreamsConfig{Streams: make(map[string]any)}
	if !s.Spec.IsOAS {
		return config
	}

	extension, ok := s.Spec.OAS.T.Extensions[ExtensionTykStreaming]
	if !ok {
		return config
	}

	if streamsMap, ok := extension.(map[string]any); ok {
		if streams, ok := streamsMap["streams"].(map[string]any); ok {
			s.processStreamsConfig(r, streams, config)
		}
	}

	return config
}

func (s *Middleware) processStreamsConfig(r *http.Request, streams map[string]any, config *StreamsConfig) {
	for streamID, stream := range streams {
		if r == nil {
			s.Logger().Debugf("No request available to replace variables in stream config for %s", streamID)
		} else {
			s.Logger().Debugf("Stream config for %s: %v", streamID, stream)
			marshaledStream, err := json.Marshal(stream)
			if err != nil {
				s.Logger().Errorf("Failed to marshal stream config: %v", err)
				continue
			}
			replacedStream := s.Gw.ReplaceTykVariables(r, string(marshaledStream), true)

			if replacedStream != string(marshaledStream) {
				s.Logger().Debugf("Stream config changed for %s: %s", streamID, replacedStream)
			} else {
				s.Logger().Debugf("Stream config has not changed for %s: %s", streamID, replacedStream)
			}

			var unmarshaledStream map[string]interface{}
			err = json.Unmarshal([]byte(replacedStream), &unmarshaledStream)
			if err != nil {
				s.Logger().Errorf("Failed to unmarshal replaced stream config: %v", err)
				continue
			}
			stream = unmarshaledStream
		}
		config.Streams[streamID] = stream
	}
}

// ProcessRequest will handle the streaming functionality.
func (s *Middleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	strippedPath := s.Spec.StripListenPath(r.URL.Path)
	if !s.defaultManager.hasPath(strippedPath) {
		return nil, http.StatusOK
	}

	s.Logger().Debugf("Processing request: %s, %s", r.URL.Path, strippedPath)

	newRequest := &http.Request{
		Method: r.Method,
		URL:    &url.URL{Scheme: r.URL.Scheme, Host: r.URL.Host, Path: strippedPath},
	}

	if !s.defaultManager.muxer.Match(newRequest, &mux.RouteMatch{}) {
		return nil, http.StatusOK
	}

	var match mux.RouteMatch
	streamManager := NewManager(s, r)
	streamManager.routeLock.Lock()
	streamManager.muxer.Match(newRequest, &match)
	streamManager.routeLock.Unlock()

	// direct Bento handler
	handler, ok := match.Handler.(http.HandlerFunc)
	if !ok {
		return errors.New("invalid route handler"), http.StatusInternalServerError
	}

	handler.ServeHTTP(w, r)

	return nil, middleware.StatusRespond
}

// Unload closes and remove active streams.
func (s *Middleware) Unload() {
	s.Logger().Debugf("Unloading streaming middleware %s", s.Spec.Name)

	totalStreams := 0
	s.streamManagers.Range(func(_, value interface{}) bool {
		manager, ok := value.(*Manager)
		if !ok {
			return true
		}
		manager.streams.Range(func(_, _ interface{}) bool {
			totalStreams++
			return true
		})
		return true
	})
	GlobalStreamCounter.Add(-int64(totalStreams))

	s.cancel()

	s.Logger().Debug("Closing active streams")
	s.streamManagers.Range(func(_, value interface{}) bool {
		manager, ok := value.(*Manager)
		if !ok {
			return true
		}
		manager.streams.Range(func(_, streamValue interface{}) bool {
			if stream, ok := streamValue.(*streaming.Stream); ok {
				if err := stream.Reset(); err != nil {
					return true
				}
			}
			return true
		})
		return true
	})

	s.streamManagers = sync.Map{}

	s.Logger().Info("All streams successfully removed")
}
