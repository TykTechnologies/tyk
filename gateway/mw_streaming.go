package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/internal/streaming"
)

const (
	// ExtensionTykStreaming is the oas extension for tyk streaming
	ExtensionTykStreaming = "x-tyk-streaming"
	StreamGCInterval      = 1 * time.Minute
)

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

func (sm *StreamManager) initStreams(r *http.Request, config *StreamsConfig) {
	// Clear existing routes for this consumer group
	sm.muxer = mux.NewRouter()

	for streamID, streamConfig := range config.Streams {
		sm.setUpOrDryRunStream(streamConfig, streamID)
	}

	// If it is default stream manager, init muxer
	if r == nil {
		for _, path := range sm.listenPaths {
			sm.muxer.HandleFunc(path, func(_ http.ResponseWriter, _ *http.Request) {
				// Dummy handler
			})
		}
	}
}

func (sm *StreamManager) setUpOrDryRunStream(streamConfig any, streamID string) {
	if streamMap, ok := streamConfig.(map[string]interface{}); ok {
		httpPaths := GetHTTPPaths(streamMap)

		if sm.dryRun {
			if len(httpPaths) == 0 {
				err := sm.createStream(streamID, streamMap)
				if err != nil {
					sm.mw.Logger().WithError(err).Errorf("Error creating stream %s", streamID)
				}
			}
		} else {
			err := sm.createStream(streamID, streamMap)
			if err != nil {
				sm.mw.Logger().WithError(err).Errorf("Error creating stream %s", streamID)
			}
		}
		sm.listenPaths = append(sm.listenPaths, httpPaths...)
	}
}

// removeStream removes a stream
func (sm *StreamManager) removeStream(streamID string) error {
	streamFullID := fmt.Sprintf("%s_%s", sm.mw.Spec.APIID, streamID)

	if streamValue, exists := sm.streams.Load(streamFullID); exists {
		stream, ok := streamValue.(*streaming.Stream)
		if !ok {
			return fmt.Errorf("stream %s is not a valid stream", streamID)
		}
		err := stream.Stop()
		if err != nil {
			return err
		}
		sm.streams.Delete(streamFullID)
	} else {
		return fmt.Errorf("stream %s does not exist", streamID)
	}
	return nil
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
			replacedStream := s.Gw.replaceTykVariables(r, string(marshaledStream), true)

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

// createStream creates a new stream
func (sm *StreamManager) createStream(streamID string, config map[string]interface{}) error {
	streamFullID := fmt.Sprintf("%s_%s", sm.mw.Spec.APIID, streamID)
	sm.mw.Logger().Debugf("Creating stream: %s", streamFullID)

	stream := streaming.NewStream(sm.mw.allowedUnsafe)
	err := stream.Start(config, &handleFuncAdapter{
		mw:       sm.mw,
		streamID: streamFullID,
		muxer:    sm.muxer,
		sm:       sm,
		// child logger is necessary to prevent race condition
		logger: sm.mw.Logger().WithField("stream", streamFullID),
	})
	if err != nil {
		sm.mw.Logger().Errorf("Failed to start stream %s: %v", streamFullID, err)
		return err
	}

	sm.streams.Store(streamFullID, stream)
	sm.mw.Logger().Infof("Successfully created stream: %s", streamFullID)

	return nil
}

func (sm *StreamManager) hasPath(path string) bool {
	for _, p := range sm.listenPaths {
		if strings.TrimPrefix(path, "/") == strings.TrimPrefix(p, "/") {
			return true
		}
	}
	return false
}

// ProcessRequest will handle the streaming functionality
func (s *StreamingMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	strippedPath := s.Spec.StripListenPath(r.URL.Path)
	if !s.defaultStreamManager.hasPath(strippedPath) {
		return nil, http.StatusOK
	}

	s.Logger().Debugf("Processing request: %s, %s", r.URL.Path, strippedPath)

	newRequest := &http.Request{
		Method: r.Method,
		URL:    &url.URL{Scheme: r.URL.Scheme, Host: r.URL.Host, Path: strippedPath},
	}

	if !s.defaultStreamManager.muxer.Match(newRequest, &mux.RouteMatch{}) {
		return nil, http.StatusOK
	}

	var match mux.RouteMatch
	streamManager := s.createStreamManager(r)
	streamManager.routeLock.Lock()
	streamManager.muxer.Match(newRequest, &match)
	streamManager.routeLock.Unlock()

	// direct Bento handler
	handler, ok := match.Handler.(http.HandlerFunc)
	if !ok {
		return errors.New("invalid route handler"), http.StatusInternalServerError
	}

	handler.ServeHTTP(w, r)

	return nil, mwStatusRespond
}

// Unload closes and remove active streams
func (s *StreamingMiddleware) Unload() {
	s.Logger().Debugf("Unloading streaming middleware %s", s.Spec.Name)

	totalStreams := 0
	s.cancel()

	s.Logger().Debug("Closing active streams")
	s.streamManagerCache.Range(func(_, value interface{}) bool {
		manager := value.(*StreamManager)
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
	sm       *StreamManager
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
