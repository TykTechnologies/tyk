package gateway

import (
	"context"
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
	consumerGroupManagers sync.Map // Map of consumer group IDs to ConsumerGroupManager
	connections           sync.Map // Map of streamID to map of connectionID to connection
	ctx                   context.Context
	cancel                context.CancelFunc
	allowedUnsafe         []string
	gcTicker              *time.Ticker
}

type ConsumerGroupManager struct {
	streamManager *streaming.StreamManager
	muxer         *mux.Router
	mw            *StreamingMiddleware
	consumerGroup string
	connections   int64
	lastAccess    time.Time
	sync.Mutex
}

func (cgm *ConsumerGroupManager) initStreams() {
	// Clear existing routes for this consumer group
	cgm.muxer = mux.NewRouter()

	specStreams := cgm.mw.getStreams()

	for streamID, streamConfig := range specStreams {
		if streamMap, ok := streamConfig.(map[string]interface{}); ok {
			err := cgm.addOrUpdateStream(streamID, streamMap)
			if err != nil {
				cgm.mw.Logger().Errorf("Error adding stream %s for consumer group %s: %v", streamID, cgm.consumerGroup, err)
			}
		}
	}
}

// removeStream removes a stream
func (cgm *ConsumerGroupManager) removeStream(streamID string) error {
	streamFullID := fmt.Sprintf("%s_%s_%s", cgm.mw.Spec.APIID, cgm.consumerGroup, streamID)
	return cgm.streamManager.RemoveStream(streamFullID)
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

			specStreams := s.getStreams()
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

	s.Logger().Debug("Initializing default consumer group")
	s.getConsumerGroupManager("default")

	s.gcTicker = time.NewTicker(GCInterval)
	go s.runGC()
}

func (s *StreamingMiddleware) runGC() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.gcTicker.C:
			s.cleanupUnusedConsumerGroups()
		}
	}
}

func (s *StreamingMiddleware) cleanupUnusedConsumerGroups() {
	now := time.Now()
	s.consumerGroupManagers.Range(func(key, value interface{}) bool {
		consumerGroup := key.(string)
		manager := value.(*ConsumerGroupManager)
		manager.Lock()
		if manager.connections == 0 && now.Sub(manager.lastAccess) > ConsumerGroupTimeout {
			s.Logger().Infof("Cleaning up unused consumer group: %s", consumerGroup)
			manager.streamManager.Reset()
			s.consumerGroupManagers.Delete(consumerGroup)
		}
		manager.Unlock()
		return true
	})
}

func (s *StreamingMiddleware) getConsumerGroupManager(consumerGroup string) *ConsumerGroupManager {
	if manager, exists := s.consumerGroupManagers.Load(consumerGroup); exists {
		return manager.(*ConsumerGroupManager)
	}

	s.Logger().Infof("ConsumerGroupManager not found for consumer group %s. Creating a new one.", consumerGroup)
	streamManager := streaming.NewStreamManager(s.allowedUnsafe)
	muxer := mux.NewRouter()
	consumerGroupManager := &ConsumerGroupManager{
		streamManager: streamManager,
		muxer:         muxer,
		mw:            s,
		consumerGroup: consumerGroup,
	}
	s.consumerGroupManagers.Store(consumerGroup, consumerGroupManager)

	// Call updateStreams for the new ConsumerGroupManager
	consumerGroupManager.initStreams()

	return consumerGroupManager
}

// getStreams extracts streaming configurations from an API spec if available.
func (s *StreamingMiddleware) getStreams() map[string]interface{} {
	streamConfigs := make(map[string]interface{})
	if s.Spec.IsOAS {
		if ext, ok := s.Spec.OAS.T.Extensions[ExtensionTykStreaming]; ok {
			if streamsMap, ok := ext.(map[string]interface{}); ok {
				if streams, ok := streamsMap["streams"].(map[string]interface{}); ok {
					for streamID, stream := range streams {
						streamConfigs[streamID] = stream
					}
				}
			}
		}
	}
	return streamConfigs
}

// addOrUpdateStream adds a new stream or updates an existing one
func (cgm *ConsumerGroupManager) addOrUpdateStream(streamID string, config map[string]interface{}) error {
	streamFullID := fmt.Sprintf("%s_%s_%s", cgm.mw.Spec.APIID, cgm.consumerGroup, streamID)
	cgm.mw.Logger().Debugf("Adding/updating stream: %s for consumer group: %s", streamFullID, cgm.consumerGroup)

	err := cgm.streamManager.AddStream(streamFullID, config, &handleFuncAdapter{mw: cgm.mw, streamID: streamFullID, consumerGroup: cgm.consumerGroup, muxer: cgm.muxer, cgm: cgm})
	if err != nil {
		cgm.mw.Logger().Errorf("Failed to add stream %s: %v", streamFullID, err)
	} else {
		cgm.mw.Logger().Infof("Successfully added/updated stream: %s", streamFullID)
	}

	cgm.mw.Logger().Debugf("Current streams after add/update: %+v", cgm.streamManager.Streams())

	return err
}

// ProcessRequest will handle the streaming functionality
func (s *StreamingMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	strippedPath := s.Spec.StripListenPath(r, r.URL.Path)

	s.Logger().Debugf("Processing request: %s, %s", r.URL.Path, strippedPath)

	consumerGroup := s.getConsumerGroup(r)
	consumerGroupManager := s.getConsumerGroupManager(consumerGroup)

	newRequest := r.Clone(r.Context())
	newRequest.URL.Path = strippedPath

	var match mux.RouteMatch
	if consumerGroupManager.muxer.Match(newRequest, &match) {
		pathRegexp, _ := match.Route.GetPathRegexp()
		s.Logger().Debugf("Matched stream: %v", pathRegexp)
		handler, _ := match.Handler.(http.HandlerFunc)
		if handler != nil {
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
	s.consumerGroupManagers.Range(func(_, value interface{}) bool {
		manager := value.(*ConsumerGroupManager)
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

	s.consumerGroupManagers.Range(func(_, value interface{}) bool {
		manager := value.(*ConsumerGroupManager)
		manager.Lock()
		s.Logger().Infof("Consumer Group %s: Closing %d connections, last access: %v", manager.consumerGroup, manager.connections, manager.lastAccess)
		manager.Unlock()
		manager.streamManager.Reset()
		return true
	})

	s.consumerGroupManagers = sync.Map{}
	s.connections = sync.Map{}

	s.Logger().Info("All streams successfully removed and connections closed")
}

type handleFuncAdapter struct {
	streamID      string
	consumerGroup string
	mw            *StreamingMiddleware
	muxer         *mux.Router
	cgm           *ConsumerGroupManager
}

func (h *handleFuncAdapter) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) {
	log.Debugf("Registering streaming handleFunc for path: %s", path)

	if h.mw == nil || h.muxer == nil {
		log.Error("StreamingMiddleware or muxer is nil")
		return
	}

	h.muxer.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		h.cgm.Lock()
		h.cgm.connections++
		h.cgm.lastAccess = time.Now()
		h.cgm.Unlock()

		f(w, r)

		h.cgm.Lock()
		h.cgm.connections--
		h.cgm.Unlock()
	})
	log.Debugf("Registered handler for path: %s", path)
}
