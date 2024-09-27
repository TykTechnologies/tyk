package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/streaming"
)

const (
	strippedRequestKey     = "stripped-request-key"
	tykStreamsVariablesKey = "tyk-streams-variables-key"
	// ExtensionTykStreaming is the oas extension for tyk streaming
	ExtensionTykStreaming = "x-tyk-streaming"
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
	streamManagers sync.Map // Map of consumer group IDs to StreamManager
	ctx            context.Context
	cancel         context.CancelFunc
	allowedUnsafe  []string
	router         *mux.Router
}

// StreamManager is responsible for creating a single stream
type StreamManager struct {
	streams   sync.Map
	routeLock sync.Mutex
	muxer     *mux.Router
	mw        *StreamingMiddleware
}

func (sm *StreamManager) initStreams(r *http.Request, config *StreamsConfig) {
	// Clear existing routes for this consumer group
	sm.muxer = mux.NewRouter()

	for streamID, streamConfig := range config.Streams {
		if streamMap, ok := streamConfig.(map[string]interface{}); ok {
			err := sm.createStream(streamID, streamMap)
			if err != nil {
				sm.mw.Logger().WithError(err).Errorf("Error creating stream %s", streamID)
			}
		}
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

func (s *StreamingMiddleware) registerHandlers(config *StreamsConfig) {
	for streamId, rawConfig := range config.Streams {
		streamConfig := rawConfig.(map[string]interface{})

		httpServerInputPath := findHTTPServerInputPath(streamConfig)
		for _, path := range GetHTTPPaths(streamConfig) {
			if path == httpServerInputPath {
				// We only use this handler to receive messages from the HTTP endpoint
				// Consider this:
				//     input:
				//      http_server:
				//        path: /post
				//        timeout: 1s
				//    output:
				//      http_server:
				//        ws_path: /subscribe
				s.router.HandleFunc(path, s.inputHttpServerPublishHandler)
			} else {
				// Subscription handler responds to WebSocket requests and hands over the request to Bento
				s.router.HandleFunc(path, s.subscriptionHandler)
			}
		}
		s.Logger().Debugf("Tyk Stream handlers have been registered for stream: %s", streamId)
	}
}

// Init initializes the middleware
func (s *StreamingMiddleware) Init() {
	s.Logger().Debug("Initializing StreamingMiddleware")

	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.router = mux.NewRouter()

	s.registerHandlers(s.getStreamsConfig(nil))
}

func (s *StreamingMiddleware) createStreamManager(r *http.Request) *StreamManager {
	newStreamManager := &StreamManager{
		muxer: mux.NewRouter(),
		mw:    s,
	}
	streamID := fmt.Sprintf("_%d", time.Now().UnixNano())
	s.streamManagers.Store(streamID, newStreamManager)

	// Call initStreams for the new StreamManager
	newStreamManager.initStreams(r, s.getStreamsConfig(r))

	return newStreamManager
}

// Helper function to extract paths from a http_server configuration
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

func findHTTPServerInputPath(streamConfig map[string]interface{}) string {
	if componentMap, ok := streamConfig["input"].(map[string]interface{}); ok {
		if httpServerConfig, ok := componentMap["http_server"].(map[string]interface{}); ok {
			if val, ok := httpServerConfig["path"].(string); ok {
				return val
			}
		}
	}
	return ""
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
		logger:              sm.mw.Logger().WithField("stream", streamFullID),
		httpServerInputPath: findHTTPServerInputPath(config),
	})
	if err != nil {
		sm.mw.Logger().Errorf("Failed to start stream %s: %v", streamFullID, err)
		return err
	}

	sm.streams.Store(streamFullID, stream)
	sm.mw.Logger().Infof("Successfully created stream: %s", streamFullID)

	return nil
}

// ProcessRequest will handle the streaming functionality
func (s *StreamingMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	strippedPath := s.Spec.StripListenPath(r.URL.Path)

	s.Logger().Debugf("Processing request: %s, %s", r.URL.Path, strippedPath)

	variables := make(map[string]any)
	// Clone the request here to transfer some variables to the underlying components such as Bento
	clonedRequest := r.Clone(context.WithValue(r.Context(), tykStreamsVariablesKey, variables))

	strippedPathRequest := &http.Request{
		Method: clonedRequest.Method,
		URL:    &url.URL{Scheme: clonedRequest.URL.Scheme, Host: clonedRequest.URL.Host, Path: strippedPath},
	}
	variables[strippedRequestKey] = strippedPathRequest

	// Use the muxer to find a matched route for the request.
	routeMatch := &mux.RouteMatch{}
	if !s.router.Match(strippedPathRequest, routeMatch) {
		return nil, http.StatusOK
	}

	routeMatch.Handler.ServeHTTP(w, clonedRequest)
	return nil, mwStatusRespond
}

func (s *StreamingMiddleware) inputHttpServerPublishHandler(w http.ResponseWriter, r *http.Request) {
	// This method handles publishing messages via an HTTP endpoint without creating a new
	// Bento stream for every HTTP request.
	//
	// It simply iterates over the existing streams and hands over the request to Bento.
	//
	// TODO: We may implement a queue or buffer here to store or distribute messages in a different way.

	var err error
	s.streamManagers.Range(func(_, value interface{}) bool {
		manager := value.(*StreamManager)
		dummyResponse := &dummyResponseWriter{}

		var body io.ReadCloser
		body, err = copyBody(r.Body, true)
		if err != nil {
			return false // break
		}
		clonedRequest := r.Clone(r.Context())
		clonedRequest.Body = body
		s.handOverRequestToBento(manager, dummyResponse, clonedRequest)
		return true // continue
	})

	if err != nil {
		doJSONWrite(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Message received
	w.WriteHeader(http.StatusOK)
}

func (s *StreamingMiddleware) subscriptionHandler(w http.ResponseWriter, r *http.Request) {
	manager := s.createStreamManager(r)
	s.handOverRequestToBento(manager, w, r)
}

func (s *StreamingMiddleware) getRouteMatch(manager *StreamManager, r *http.Request) (*mux.RouteMatch, error) {
	manager.routeLock.Lock()
	defer manager.routeLock.Unlock()

	var match mux.RouteMatch
	if !manager.muxer.Match(r, &match) {
		// request does not match any of this router's or its subrouters' routes then this function returns false.
		return nil, mux.ErrNotFound
	}
	if match.MatchErr != nil {
		return nil, match.MatchErr
	}
	return &match, nil
}

func getStrippedRequest(r *http.Request) (*http.Request, error) {
	variables, ok := r.Context().Value(tykStreamsVariablesKey).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s could not be found in request context", tykStreamsVariablesKey)
	}
	strippedRequest, ok := variables[strippedRequestKey].(*http.Request)
	if !ok {
		return nil, fmt.Errorf("%s could not be found in request variables", strippedRequestKey)
	}
	return strippedRequest, nil
}

func (s *StreamingMiddleware) handOverRequestToBento(manager *StreamManager, w http.ResponseWriter, r *http.Request) {
	strippedRequest, err := getStrippedRequest(r)
	if err != nil {
		doJSONWrite(w, http.StatusInternalServerError, apiError(err.Error()))
		return
	}

	match, err := s.getRouteMatch(manager, strippedRequest)
	if err != nil {
		var code int = http.StatusInternalServerError
		if errors.Is(err, mux.ErrNotFound) {
			code = http.StatusNotFound
		}
		doJSONWrite(w, code, apiError(err.Error()))
		return
	}

	// direct Bento handler
	handler, ok := match.Handler.(http.HandlerFunc)
	if !ok {
		doJSONWrite(w, http.StatusInternalServerError, apiError("invalid route handler"))
		return
	}

	// Wait until the subscription has killed by one of the parties.
	handler.ServeHTTP(w, r)
}

// Unload closes and remove active streams
func (s *StreamingMiddleware) Unload() {
	s.Logger().Debugf("Unloading streaming middleware %s", s.Spec.Name)

	totalStreams := 0
	s.streamManagers.Range(func(_, value interface{}) bool {
		manager, ok := value.(*StreamManager)
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
		manager, ok := value.(*StreamManager)
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

type handleFuncAdapter struct {
	streamID            string
	sm                  *StreamManager
	mw                  *StreamingMiddleware
	muxer               *mux.Router
	logger              *logrus.Entry
	httpServerInputPath string
}

func (h *handleFuncAdapter) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) {
	h.logger.Debugf("Registering streaming handleFunc for path: %s", path)

	if h.mw == nil || h.muxer == nil {
		h.logger.Error("StreamingMiddleware or muxer is nil")
		return
	}

	h.sm.routeLock.Lock()
	defer h.sm.routeLock.Unlock()

	h.muxer.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			// If this handler handles a request that publishes a message via HTTP, we don't need to
			// remove the stream. It was just an HTTP request that handled by Bento
			if h.httpServerInputPath != path {
				// Stop the stream when the HTTP request finishes
				if err := h.sm.removeStream(h.streamID); err != nil {
					h.logger.Errorf("Failed to stop stream %s: %v", h.streamID, err)
				}
			}
		}()

		f(w, r)
	})

	h.logger.Debugf("Registered handler for path: %s", path)
}

type dummyResponseWriter struct {
}

func (m dummyResponseWriter) Header() http.Header {
	return http.Header{}
}

func (m dummyResponseWriter) Write(bytes []byte) (int, error) {
	return len(bytes), nil
}

func (m dummyResponseWriter) WriteHeader(statusCode int) {
	return
}

var _ http.ResponseWriter = (*dummyResponseWriter)(nil)
