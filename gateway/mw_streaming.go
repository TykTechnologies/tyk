package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/internal/streaming"
)

const (
	ExtensionTykStreaming = "x-tyk-streaming"
	GCInterval            = 1 * time.Minute
	ConsumerGroupTimeout  = 30 * time.Second
)

// Used for testing
var globalStreamCounter atomic.Int64

// StreamingMiddleware is a middleware that handles streaming functionality
type StreamingMiddleware struct {
	*BaseMiddleware
	streamManagers       sync.Map // Map of consumer group IDs to StreamManager
	connections          sync.Map // Map of streamID to map of connectionID to connection
	ctx                  context.Context
	cancel               context.CancelFunc
	allowedUnsafe        []string
	gcTicker             *time.Ticker
	defaultStreamManager *StreamManager
}

type StreamManager struct {
	streamManager *streaming.StreamManager
	muxer         *mux.Router
	mw            *StreamingMiddleware
	consumerGroup string
	connections   int64
	lastAccess    time.Time
	sync.Mutex
}

func (sm *StreamManager) initStreams(specStreams map[string]interface{}) {
	// Clear existing routes for this consumer group
	sm.muxer = mux.NewRouter()

	for streamID, streamConfig := range specStreams {
		if streamMap, ok := streamConfig.(map[string]interface{}); ok {
			err := sm.addOrUpdateStream(streamID, streamMap)
			if err != nil {
				sm.mw.Logger().Errorf("Error adding stream %s for consumer group %s: %v", streamID, sm.consumerGroup, err)
			}
		}
	}
}

// removeStream removes a stream
func (sm *StreamManager) removeStream(streamID string) error {
	streamFullID := fmt.Sprintf("%s_%s_%s", sm.mw.Spec.APIID, sm.consumerGroup, streamID)
	return sm.streamManager.RemoveStream(streamFullID)
}

type connection struct {
	id     string
	cancel context.CancelFunc
}

func (s *StreamingMiddleware) Name() string {
	return "StreamingMiddleware"
}

func (s *StreamingMiddleware) EnabledForSpec() bool {
	s.Logger().Debug("Checking if streaming is enabled")

	labsConfig := s.Gw.GetConfig().Labs
	s.Logger().Debugf("Labs config: %+v", labsConfig)

	if streamingConfig, ok := labsConfig["streaming"].(map[string]interface{}); ok {
		s.Logger().Debugf("Streaming config: %+v", streamingConfig)
		if enabled, ok := streamingConfig["enabled"].(bool); ok && enabled {
			s.Logger().Debug("Streaming is enabled in the config")
			if allowUnsafe, ok := streamingConfig["allow_unsafe"].([]interface{}); ok {
				s.allowedUnsafe = make([]string, len(allowUnsafe))
				for i, v := range allowUnsafe {
					if str, ok := v.(string); ok {
						s.allowedUnsafe[i] = str
					}
				}
			}
			s.Logger().Debugf("Allowed unsafe components: %v", s.allowedUnsafe)

			specStreams := s.getStreams(nil)
			globalStreamCounter.Add(int64(len(specStreams)))

			s.Logger().Debug("Total streams count: ", len(specStreams))

			if len(specStreams) == 0 {
				return false
			}

			return true
		}
	}

	s.Logger().Debug("Streaming is not enabled in the config")
	return false
}

// Init initializes the middleware
func (s *StreamingMiddleware) Init() {
	s.Logger().Debug("Initializing StreamingMiddleware")
	s.ctx, s.cancel = context.WithCancel(context.Background())

	s.Logger().Debug("Initializing default stream manager")
	s.defaultStreamManager = s.createStreamManager("default", nil)

	s.gcTicker = time.NewTicker(GCInterval)
	go s.runGC()
}

func (s *StreamingMiddleware) runGC() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.gcTicker.C:
			// s.cleanupUnusedConsumerGroups()
		}
	}
}

// - mapping: >
//         root = if json().id.string() == "$tyk_context.request_data_report_id" {
//         deleted() }

func (s *StreamingMiddleware) cleanupUnusedConsumerGroups() {
	now := time.Now()
	s.streamManagers.Range(func(key, value interface{}) bool {
		consumerGroup := key.(string)
		if consumerGroup == "default" {
			return true
		}
		manager := value.(*StreamManager)
		manager.Lock()
		if manager.connections == 0 && now.Sub(manager.lastAccess) > ConsumerGroupTimeout {
			s.Logger().Infof("Cleaning up unused consumer group: %s", consumerGroup)
			manager.streamManager.Reset()
			s.streamManagers.Delete(consumerGroup)
		}
		manager.Unlock()
		return true
	})
}

func (s *StreamingMiddleware) createStreamManager(consumerGroup string, r *http.Request) *StreamManager {
	// if manager, exists := s.streamManagers.Load(consumerGroup); exists {
	// 	return manager.(*StreamManager)
	// }

	// s.Logger().Infof("StreamManager not found for consumer group %s. Creating a new one.", consumerGroup)
	streamManager := streaming.NewStreamManager(s.allowedUnsafe)
	muxer := mux.NewRouter()
	newStreamManager := &StreamManager{
		streamManager: streamManager,
		muxer:         muxer,
		mw:            s,
		consumerGroup: consumerGroup,
	}
	randomID := fmt.Sprintf("_%d", time.Now().UnixNano())
	consumerGroupWithID := consumerGroup + randomID
	s.streamManagers.Store(consumerGroupWithID, newStreamManager)

	// Call initStreams for the new StreamManager
	newStreamManager.initStreams(s.getStreams(r))

	return newStreamManager
}

// getStreams extracts streaming configurations from an API spec if available.
func (s *StreamingMiddleware) getStreams(r *http.Request) map[string]interface{} {
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

// addOrUpdateStream adds a new stream or updates an existing one
func (sm *StreamManager) addOrUpdateStream(streamID string, config map[string]interface{}) error {
	streamFullID := fmt.Sprintf("%s_%s_%s", sm.mw.Spec.APIID, sm.consumerGroup, streamID)
	sm.mw.Logger().Debugf("Adding/updating stream: %s for consumer group: %s", streamFullID, sm.consumerGroup)

	err := sm.streamManager.AddStream(streamFullID, config, &handleFuncAdapter{mw: sm.mw, streamID: streamFullID, consumerGroup: sm.consumerGroup, muxer: sm.muxer, sm: sm})
	if err != nil {
		sm.mw.Logger().Errorf("Failed to add stream %s: %v", streamFullID, err)
	} else {
		sm.mw.Logger().Infof("Successfully added/updated stream: %s", streamFullID)
	}

	sm.mw.Logger().Debugf("Current streams after add/update: %+v", sm.streamManager.Streams())

	return err
}

// ProcessRequest will handle the streaming functionality
func (s *StreamingMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	strippedPath := s.Spec.StripListenPath(r, r.URL.Path)

	s.Logger().Debugf("Processing request: %s, %s", r.URL.Path, strippedPath)

	newRequest := r.Clone(r.Context())
	newRequest.URL.Path = strippedPath

	var match mux.RouteMatch
	// First do the check if such route is defined by streaming API
	if s.defaultStreamManager.muxer.Match(newRequest, &match) {
		pathRegexp, _ := match.Route.GetPathRegexp()
		s.Logger().Debugf("Matched stream: %v", pathRegexp)
		handler, _ := match.Handler.(http.HandlerFunc)
		if handler != nil {
			// Now that we know that such streaming endpoint here,
			// we can actually initialize individual stream manager
			consumerGroup := s.getConsumerGroup(r)
			streamManager := s.createStreamManager(consumerGroup, r)
			streamManager.muxer.Match(newRequest, &match)
			handler, _ := match.Handler.(http.HandlerFunc)

			handler.ServeHTTP(w, r)
			return nil, mwStatusRespond
		}
	}

	// If no stream matches, continue with the next middleware
	return nil, http.StatusOK
}

func (s *StreamingMiddleware) getConsumerGroup(r *http.Request) string {
	consumerGroup := ctxGetAuthToken(r)

	session := ctxGetSession(r)
	if session != nil {
		if pattern, found := session.MetaData["consumer_group"]; found {
			if patternString, ok := pattern.(string); ok && patternString != "" {
				consumerGroup = patternString
			}
		}
	}

	if customKeyValue := s.Gw.replaceTykVariables(r, consumerGroup, false); customKeyValue != "" {
		consumerGroup = customKeyValue
	}

	if consumerGroup == "" {
		consumerGroup = "default"
	}

	return consumerGroup
}

func (s *StreamingMiddleware) Unload() {
	s.Logger().Debugf("Unloading streaming middleware %s", s.Spec.Name)

	totalStreams := 0
	s.streamManagers.Range(func(_, value interface{}) bool {
		manager := value.(*StreamManager)
		totalStreams += len(manager.streamManager.Streams())
		return true
	})
	globalStreamCounter.Add(-int64(totalStreams))

	s.cancel()
	s.gcTicker.Stop()

	s.Logger().Debug("Closing active connections")
	s.connections.Range(func(_, value interface{}) bool {
		if conns, ok := value.(*sync.Map); ok {
			conns.Range(func(_, connValue interface{}) bool {
				if conn, ok := connValue.(connection); ok {
					conn.cancel()
				}
				return true
			})
		}
		return true
	})

	time.Sleep(500 * time.Millisecond)

	s.streamManagers.Range(func(_, value interface{}) bool {
		manager := value.(*StreamManager)
		manager.Lock()
		s.Logger().Infof("Consumer Group %s: Closing %d connections, last access: %v", manager.consumerGroup, manager.connections, manager.lastAccess)
		manager.Unlock()
		manager.streamManager.Reset()
		return true
	})

	s.streamManagers = sync.Map{}
	s.connections = sync.Map{}

	s.Logger().Info("All streams successfully removed and connections closed")
}

type handleFuncAdapter struct {
	streamID      string
	sm            *StreamManager
	consumerGroup string
	mw            *StreamingMiddleware
	muxer         *mux.Router
}

func (h *handleFuncAdapter) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) {
	h.mw.Logger().Debugf("Registering streaming handleFunc for path: %s", path)

	if h.mw == nil || h.muxer == nil {
		h.mw.Logger().Error("StreamingMiddleware or muxer is nil")
		return
	}

	h.muxer.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		h.sm.Lock()
		h.sm.connections++
		h.sm.lastAccess = time.Now()
		h.sm.Unlock()

		f(w, r)

		h.sm.Lock()
		h.sm.connections--
		h.sm.Unlock()
	})
	h.mw.Logger().Debugf("Registered handler for path: %s", path)
}
