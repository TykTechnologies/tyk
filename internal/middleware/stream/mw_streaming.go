package stream

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/streaming"
)

const (
	// ExtensionTykStreaming is the oas extension for tyk streaming
	ExtensionTykStreaming = "x-tyk-streaming"
	StreamGCInterval      = 1 * time.Minute
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
var globalStreamCounter atomic.Int64

// StreamingMiddleware is a middleware that handles streaming functionality
type StreamingMiddleware struct {
<<<<<<< HEAD:gateway/mw_streaming.go
	*BaseMiddleware

	createStreamManagerLock sync.Mutex
	streamManagerCache      sync.Map // Map of payload hash to StreamManager
	ctx                     context.Context
	cancel                  context.CancelFunc
	allowedUnsafe           []string
	defaultStreamManager    *StreamManager
}

// StreamManager is responsible for creating a single stream
type StreamManager struct {
	streams     sync.Map
	routeLock   sync.Mutex
	muxer       *mux.Router
	mw          *StreamingMiddleware
	dryRun      bool
	listenPaths []string

	activityCounter atomic.Int32 // Counts active subscriptions, requests.
}
=======
	Spec *APISpec
	Gw   Gateway

	base BaseMiddleware

	streamManagers sync.Map // Map of consumer group IDs to Manager

	ctx            context.Context
	cancel         context.CancelFunc
	allowedUnsafe  []string
	defaultManager *Manager
}

var _ model.Middleware = &StreamingMiddleware{}
>>>>>>> fb9b35ec7 (Move streams middleware to internal/middleware/streams):internal/middleware/stream/mw_streaming.go

func NewStreamingMiddleware(gw Gateway, mw BaseMiddleware, spec *APISpec) *StreamingMiddleware {
	return &StreamingMiddleware{
		base: mw,
		Gw:   gw,
		Spec: spec,
	}
}

func (s *StreamingMiddleware) Logger() *logrus.Entry {
	return s.base.Logger().WithField("mw", s.Name())
}

func (s *StreamingMiddleware) garbageCollect() {
	s.Logger().Debug("Starting garbage collection for inactive stream managers")

	s.streamManagerCache.Range(func(key, value interface{}) bool {
		manager := value.(*StreamManager)
		if manager == s.defaultStreamManager {
			return true
		}

		if manager.activityCounter.Load() <= 0 {
			s.Logger().Infof("Removing inactive stream manager: %v", key)
			manager.streams.Range(func(streamKey, streamValue interface{}) bool {
				streamID := streamKey.(string)
				err := manager.removeStream(streamID)
				if err != nil {
					s.Logger().Errorf("Error removing stream %s: %v", streamID, err)
				}
				return true
			})
			s.streamManagerCache.Delete(key)
		}

		return true
	})
}

// Name is StreamingMiddleware
func (s *StreamingMiddleware) Name() string {
	return "StreamingMiddleware"
}

// EnabledForSpec checks if streaming is enabled on the config
func (s *StreamingMiddleware) EnabledForSpec() bool {
	s.Logger().Debug("Checking if streaming is enabled")

	streamingConfig := s.Gw.GetConfig().Streaming
	s.Logger().Debugf("Streaming config: %+v", streamingConfig)

	if streamingConfig.Enabled {
		s.Logger().Debug("Streaming is enabled in the config")
		s.allowedUnsafe = streamingConfig.AllowUnsafe
		s.Logger().Debugf("Allowed unsafe components: %v", s.allowedUnsafe)

		config := s.getStreamsConfig(nil)
		globalStreamCounter.Add(int64(len(config.Streams)))

		s.Logger().Debug("Total streams count: ", len(config.Streams))

		return len(config.Streams) != 0
	}

	s.Logger().Debug("Streaming is not enabled in the config")
	return false
}

// Init initializes the middleware
func (s *StreamingMiddleware) Init() {
	s.Logger().Debug("Initializing StreamingMiddleware")
	s.ctx, s.cancel = context.WithCancel(context.Background())

	s.Logger().Debug("Initializing default stream manager")
<<<<<<< HEAD:gateway/mw_streaming.go
	s.defaultStreamManager = s.createStreamManager(nil)

	// Start garbage collection routine
	go func() {
		ticker := time.NewTicker(StreamGCInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.garbageCollect()
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

func (s *StreamingMiddleware) createStreamManager(r *http.Request) *StreamManager {
	streamsConfig := s.getStreamsConfig(r)
	configJSON, _ := json.Marshal(streamsConfig)
	cacheKey := fmt.Sprintf("%x", sha256.Sum256(configJSON))

	// Critical section starts here
	// This section is called by ProcessRequest method of the middleware implementation
	// Concurrent requests can call this method at the same time and those requests
	// creates new StreamManagers and store them concurrently, as a result
	// the returned stream manager has overwritten by a different one by leaking
	// the previously stored StreamManager.
	s.createStreamManagerLock.Lock()
	defer s.createStreamManagerLock.Unlock()

	s.Logger().Debug("Attempting to load stream manager from cache")
	s.Logger().Debugf("Cache key: %s", cacheKey)
	if cachedManager, found := s.streamManagerCache.Load(cacheKey); found {
		s.Logger().Debug("Found cached stream manager")
		return cachedManager.(*StreamManager)
	}

	newStreamManager := &StreamManager{
		muxer:           mux.NewRouter(),
		mw:              s,
		dryRun:          r == nil,
		activityCounter: atomic.Int32{},
	}
	newStreamManager.initStreams(r, streamsConfig)

	if r != nil {
		s.streamManagerCache.Store(cacheKey, newStreamManager)
	}
	return newStreamManager
=======
	s.defaultManager = NewManager(s, nil)
>>>>>>> fb9b35ec7 (Move streams middleware to internal/middleware/streams):internal/middleware/stream/mw_streaming.go
}

// Helper function to extract paths from an http_server configuration
func extractPaths(httpConfig map[string]interface{}) []string {
	var paths []string
	defaultPaths := map[string]string{
		"path":        "/post",
		"ws_path":     "/post/ws",
		"stream_path": "/get/stream",
	}
	for key, defaultValue := range defaultPaths {
		if val, ok := httpConfig[key].(string); ok {
			paths = append(paths, val)
		} else {
			paths = append(paths, defaultValue)
		}
	}
	return paths
}

// Helper function to extract HTTP server paths from a given configuration
func extractHTTPServerPaths(config map[string]interface{}) []string {
	if httpServerConfig, ok := config["http_server"].(map[string]interface{}); ok {
		return extractPaths(httpServerConfig)
	}
	return nil
}

// Helper function to handle broker configurations
func handleBroker(brokerConfig map[string]interface{}) []string {
	var paths []string
	for _, ioKey := range []string{"inputs", "outputs"} {
		if ioList, ok := brokerConfig[ioKey].([]interface{}); ok {
			for _, ioItem := range ioList {
				if ioItemMap, ok := ioItem.(map[string]interface{}); ok {
					paths = append(paths, extractHTTPServerPaths(ioItemMap)...)
				}
			}
		}
	}
	return paths
}

// GetHTTPPaths is the ain function to get HTTP paths from the stream configuration
func GetHTTPPaths(streamConfig map[string]interface{}) []string {
	var paths []string
	for _, component := range []string{"input", "output"} {
		if componentMap, ok := streamConfig[component].(map[string]interface{}); ok {
			paths = append(paths, extractHTTPServerPaths(componentMap)...)
			if brokerConfig, ok := componentMap["broker"].(map[string]interface{}); ok {
				paths = append(paths, handleBroker(brokerConfig)...)
			}
		}
	}
	// remove duplicates
	var deduplicated []string
	exists := map[string]struct{}{}
	for _, item := range paths {
		if _, ok := exists[item]; !ok {
			deduplicated = append(deduplicated, item)
			exists[item] = struct{}{}
		}
	}
	return deduplicated
}

func (s *StreamingMiddleware) getStreamsConfig(r *http.Request) *StreamsConfig {
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

func (s *StreamingMiddleware) processStreamsConfig(r *http.Request, streams map[string]any, config *StreamsConfig) {
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

// ProcessRequest will handle the streaming functionality
func (s *StreamingMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
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

// Unload closes and remove active streams
func (s *StreamingMiddleware) Unload() {
	s.Logger().Debugf("Unloading streaming middleware %s", s.Spec.Name)

	totalStreams := 0
<<<<<<< HEAD:gateway/mw_streaming.go
	s.cancel()

	s.Logger().Debug("Closing active streams")
	s.streamManagerCache.Range(func(_, value interface{}) bool {
		manager := value.(*StreamManager)
=======
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
	globalStreamCounter.Add(-int64(totalStreams))

	s.cancel()

	s.Logger().Debug("Closing active streams")
	s.streamManagers.Range(func(_, value interface{}) bool {
		manager, ok := value.(*Manager)
		if !ok {
			return true
		}
>>>>>>> fb9b35ec7 (Move streams middleware to internal/middleware/streams):internal/middleware/stream/mw_streaming.go
		manager.streams.Range(func(_, streamValue interface{}) bool {
			totalStreams++
			if stream, ok := streamValue.(*streaming.Stream); ok {
				if err := stream.Reset(); err != nil {
					return true
				}
			}
			return true
		})
		return true
	})

	globalStreamCounter.Add(-int64(totalStreams))
	s.streamManagerCache = sync.Map{}

	s.Logger().Info("All streams successfully removed")
}

type handleFuncAdapter struct {
	streamID string
	sm       *Manager
	mw       *StreamingMiddleware
	muxer    *mux.Router
	logger   *logrus.Entry
}

func (h *handleFuncAdapter) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) {
	h.logger.Debugf("Registering streaming handleFunc for path: %s", path)

	if h.mw == nil || h.muxer == nil {
		h.logger.Error("StreamingMiddleware or muxer is nil")
		return
	}

	h.sm.routeLock.Lock()
	h.muxer.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		h.sm.activityCounter.Add(1)
		f(w, r)
		h.sm.activityCounter.Add(-1)
	})
	h.sm.routeLock.Unlock()
	h.logger.Debugf("Registered handler for path: %s", path)
}
