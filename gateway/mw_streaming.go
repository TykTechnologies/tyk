package gateway

import (
	"crypto/md5"
	"encoding/json"
	"time"

	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/internal/streaming"
)

const (
	ExtensionTykStreaming = "x-tyk-streaming"
	StreamGCInterval      = 1 * time.Minute
	StreamInactiveLimit   = 10 * time.Minute
)

// Used for testing
var globalStreamCounter atomic.Int64

// StreamingMiddleware is a middleware that handles streaming functionality
type StreamingMiddleware struct {
	*BaseMiddleware

	streamManagerCache sync.Map // Map of payload hash to StreamManager

	streamManagers       sync.Map // Map of consumer group IDs to StreamManager
	ctx                  context.Context
	cancel               context.CancelFunc
	allowedUnsafe        []string
	defaultStreamManager *StreamManager

	lastActivity sync.Map // Map of stream IDs to last activity time

}

type StreamManager struct {
	streams     sync.Map
	routeLock   sync.Mutex
	muxer       *mux.Router
	mw          *StreamingMiddleware
	dryRun      bool
	listenPaths []string

	lastActivity sync.Map // Map of stream IDs to last activity time

}

func (sm *StreamManager) initStreams(r *http.Request, specStreams map[string]interface{}) {
	// Clear existing routes for this consumer group
	sm.muxer = mux.NewRouter()

	for streamID, streamConfig := range specStreams {
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

	// If it is default stream manager, init muxer
	if r == nil {
		for _, path := range sm.listenPaths {
			sm.muxer.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
				// Dummy handler
			})
		}
	}
}

// removeStream removes a stream
func (sm *StreamManager) removeStream(streamID string) error {
	streamFullID := fmt.Sprintf("%s_%s", sm.mw.Spec.APIID, streamID)

	if streamValue, exists := sm.streams.Load(streamFullID); exists {
		stream := streamValue.(*streaming.Stream)
		err := stream.Stop()
		if err != nil {
			return err
		}
		sm.streams.Delete(streamFullID)
	} else {
		return fmt.Errorf("Stream %s does not exist", streamID)
	}
	return nil
}

type connection struct {
	id     string
	cancel context.CancelFunc
}

func (s *StreamingMiddleware) garbageCollect() {
	s.Logger().Debug("Starting garbage collection for inactive streams")
	now := time.Now()

	s.streamManagerCache.Range(func(_, value interface{}) bool {
		manager := value.(*StreamManager)
		manager.streams.Range(func(key, streamValue interface{}) bool {
			streamID := key.(string)

			lastActivityTime, ok := manager.lastActivity.Load(streamID)
			if !ok {
				// If no activity recorded, assume it's inactive
				lastActivityTime = time.Time{}
			}

			if now.Sub(lastActivityTime.(time.Time)) > StreamInactiveLimit {
				s.Logger().Infof("Removing inactive stream: %s", streamID)
				err := manager.removeStream(streamID)
				if err != nil {
					s.Logger().Errorf("Error removing stream %s: %v", streamID, err)
				}
			}

			return true
		})
		return true
	})
}

func (s *StreamingMiddleware) Name() string {
	return "StreamingMiddleware"
}

func (s *StreamingMiddleware) EnabledForSpec() bool {
	s.Logger().Debug("Checking if streaming is enabled")

	streamingConfig := s.Gw.GetConfig().Streaming
	s.Logger().Debugf("Streaming config: %+v", streamingConfig)

	if streamingConfig.Enabled {
		s.Logger().Debug("Streaming is enabled in the config")
		s.allowedUnsafe = streamingConfig.AllowUnsafe
		s.Logger().Debugf("Allowed unsafe components: %v", s.allowedUnsafe)

		specStreams := s.getStreamsConfig(nil)
		globalStreamCounter.Add(int64(len(specStreams)))

		s.Logger().Debug("Total streams count: ", len(specStreams))

		if len(specStreams) == 0 {
			return false
		}

		return true
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
	cacheKey := fmt.Sprintf("%x", md5.Sum(configJSON))

	s.Logger().Debug("Attempting to load stream manager from cache")
	s.Logger().Debugf("Cache key: %s", cacheKey)
	if cachedManager, found := s.streamManagerCache.Load(cacheKey); found {
		s.Logger().Debug("Found cached stream manager")
		return cachedManager.(*StreamManager)
	}

	newStreamManager := &StreamManager{
		muxer:  mux.NewRouter(),
		mw:     s,
		dryRun: r == nil,
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

// Main function to get HTTP paths from the stream configuration
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
	return paths
}

// getStreamsConfig extracts streaming configurations from an API spec if available.
func (s *StreamingMiddleware) getStreamsConfig(r *http.Request) map[string]interface{} {
	streamConfigs := make(map[string]interface{})
	if s.Spec.IsOAS {
		if ext, ok := s.Spec.OAS.T.Extensions[ExtensionTykStreaming]; ok {
			if streamsMap, ok := ext.(map[string]interface{}); ok {
				if streams, ok := streamsMap["streams"].(map[string]interface{}); ok {
					for streamID, stream := range streams {
						if r != nil {
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
						} else {
							s.Logger().Debugf("No request available to replace variables in stream config for %s", streamID)
						}
						streamConfigs[streamID] = stream
					}
				}
			}
		}
	}
	return streamConfigs
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
	handler, _ := match.Handler.(http.HandlerFunc)

	handler.ServeHTTP(w, r)

	return nil, mwStatusRespond
}

func (s *StreamingMiddleware) Unload() {
	s.Logger().Debugf("Unloading streaming middleware %s", s.Spec.Name)

	totalStreams := 0
	s.streamManagers.Range(func(_, value interface{}) bool {
		manager := value.(*StreamManager)
		manager.streams.Range(func(_, _ interface{}) bool {
			totalStreams++
			return true
		})
		return true
	})
	globalStreamCounter.Add(-int64(totalStreams))

	s.cancel()

	s.Logger().Debug("Closing active streams")
	s.streamManagerCache.Range(func(_, value interface{}) bool {
		manager := value.(*StreamManager)
		manager.streams.Range(func(_, streamValue interface{}) bool {
			if stream, ok := streamValue.(*streaming.Stream); ok {
				stream.Reset()
			}
			return true
		})
		return true
	})

	s.streamManagers = sync.Map{}
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
		h.sm.lastActivity.Store(h.streamID, time.Now())
		f(w, r)
		h.sm.lastActivity.Store(h.streamID, time.Now())
	})
	h.sm.routeLock.Unlock()
	h.logger.Debugf("Registered handler for path: %s", path)
}
