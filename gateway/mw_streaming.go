package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/internal/streaming"
)

const (
	ExtensionTykStreaming = "x-tyk-streaming"
)

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
	streamManagers       sync.Map // Map of consumer group IDs to StreamManager
	ctx                  context.Context
	cancel               context.CancelFunc
	allowedUnsafe        []string
	defaultStreamManager *StreamManager
}

type StreamManager struct {
	streams     sync.Map
	routeLock   sync.Mutex
	muxer       *mux.Router
	mw          *StreamingMiddleware
	dryRun      bool
	listenPaths []string
}

func (sm *StreamManager) initStreams(config *StreamsConfig) {
	// Clear existing routes for this consumer group
	sm.muxer = mux.NewRouter()

	for streamID, streamConfig := range config.Streams {
		if streamMap, ok := streamConfig.(map[string]any); ok {
			hasHttp := HasHttp(streamMap)
			if sm.dryRun {
				if !hasHttp {
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
			sm.listenPaths = GetHTTPPaths(streamMap)

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

		config := s.getStreamsConfig(nil)
		globalStreamCounter.Add(int64(len(config.Streams)))

		s.Logger().Debug("Total streams count: ", len(config.Streams))

		if len(config.Streams) == 0 {
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
}

func (s *StreamingMiddleware) createStreamManager(r *http.Request) *StreamManager {
	newStreamManager := &StreamManager{
		muxer:  mux.NewRouter(),
		mw:     s,
		dryRun: r == nil,
	}
	streamID := fmt.Sprintf("_%d", time.Now().UnixNano())
	s.streamManagers.Store(streamID, newStreamManager)

	// Call initStreams for the new StreamManager
	newStreamManager.initStreams(s.getStreamsConfig(r))

	return newStreamManager
}

func HasHttp(config map[string]interface{}) bool {
	for key := range config {
		keyConfig := config[key]
		keyConfigMap, ok := keyConfig.(map[string]interface{})
		if !ok {
			continue
		}

		if _, found := keyConfigMap["http_server"]; found {
			return true
		}
	}
	return false
}

func GetHTTPPaths(streamConfig map[string]interface{}) []string {
    paths := []string{}

    // Define the path keys and their default values
    pathKeys := []string{"path", "ws_path", "stream_path"}
    defaultPaths := map[string]string{
        "path":        "/post",
        "ws_path":     "/post/ws",
        "stream_path": "/get/stream",
    }

    // Components to process: 'input' and 'output'
    components := []string{"input", "output"}

    // Helper function to extract paths from an http_server config
    extractPaths := func(httpConfig map[string]interface{}) {
        for _, key := range pathKeys {
            val, exists := httpConfig[key]
            if !exists {
                // Use default if key is missing
                paths = append(paths, defaultPaths[key])
            } else if pathStr, ok := val.(string); ok {
                paths = append(paths, pathStr)
            } else {
                // Use default if value is not a string
                paths = append(paths, defaultPaths[key])
            }
        }
    }

    for _, component := range components {
        componentConfig, exists := streamConfig[component]
        if !exists {
            continue
        }

        componentMap, ok := componentConfig.(map[string]interface{})
        if !ok {
            continue
        }

        // Check if 'broker' exists under this component
        if brokerConfig, exists := componentMap["broker"]; exists {
            // 'broker' is a list of configurations
            brokerList, ok := brokerConfig.([]interface{})
            if !ok {
                continue
            }
            for _, brokerItem := range brokerList {
                brokerItemMap, ok := brokerItem.(map[string]interface{})
                if !ok {
                    continue
                }
                // Check if 'http_server' exists under this broker item
                if httpServerConfig, exists := brokerItemMap["http_server"]; exists {
                    if httpConfigMap, ok := httpServerConfig.(map[string]interface{}); ok {
                        extractPaths(httpConfigMap)
                    }
                }
            }
        } else if httpServerConfig, exists := componentMap["http_server"]; exists {
            // 'http_server' directly under component
            if httpConfigMap, ok := httpServerConfig.(map[string]interface{}); ok {
                extractPaths(httpConfigMap)
            }
        }
    }

    return paths
}

func (s *StreamingMiddleware) getStreamsConfig(r *http.Request) *StreamsConfig {
	if !s.Spec.IsOAS {
		return nil
	}

	tykStreamingConfig, ok := s.Spec.OAS.T.Extensions[ExtensionTykStreaming]
	if !ok {
		return nil
	}

	data, err := json.Marshal(tykStreamingConfig)
	if err != nil {
		return nil
	}

	streamsConfig := &StreamsConfig{}
	err = json.Unmarshal(data, streamsConfig)
	if err != nil {
		return nil
	}

	for streamID, stream := range streamsConfig.Streams {
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

			var unmarshaledStream map[string]any
			err = json.Unmarshal([]byte(replacedStream), &unmarshaledStream)
			if err != nil {
				s.Logger().Errorf("Failed to unmarshal replaced stream config: %v", err)
				continue
			}
			stream = unmarshaledStream
		} else {
			s.Logger().Debugf("No request available to replace variables in stream config for %s", streamID)
		}
	}
	return streamsConfig
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

	newRequest := r.Clone(r.Context())
	newRequest.URL.Path = strippedPath

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
	s.streamManagers.Range(func(_, value interface{}) bool {
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
		defer func() {
			// Stop the stream when the HTTP request finishes
			if err := h.sm.removeStream(h.streamID); err != nil {
				h.logger.Errorf("Failed to stop stream %s: %v", h.streamID, err)
			}
		}()

		f(w, r)
	})
	h.sm.routeLock.Unlock()
	h.logger.Debugf("Registered handler for path: %s", path)
}
