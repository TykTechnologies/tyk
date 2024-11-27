package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

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

	// Determine if caching should be disabled
	disableCache := s.shouldDisableCache(streamsConfig)

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
	if !disableCache {
		if cachedManager, found := s.streamManagerCache.Load(cacheKey); found {
			s.Logger().Debug("Found cached stream manager")
			return cachedManager.(*StreamManager)
		}
	}

	newStreamManager := &StreamManager{
		muxer:           mux.NewRouter(),
		mw:              s,
		dryRun:          r == nil,
		activityCounter: atomic.Int32{},
	}
	newStreamManager.initStreams(r, streamsConfig)

	if !disableCache && r != nil {
		s.streamManagerCache.Store(cacheKey, newStreamManager)
	}
	return newStreamManager
}

func (s *StreamingMiddleware) shouldDisableCache(streamsConfig *StreamsConfig) bool {
	for _, stream := range streamsConfig.Streams {
		if streamMap, ok := stream.(map[string]interface{}); ok {
			inputType := s.getComponentType(streamMap, "input")
			outputType := s.getComponentType(streamMap, "output")
			if inputType == "http_client" && outputType == "http_server" {
				return true
			}
		}
	}
	return false
}

// getComponentType returns the type of the input or output component from the stream configuration
func (s *StreamingMiddleware) getComponentType(streamConfig map[string]interface{}, component string) string {
	if componentMap, ok := streamConfig[component].(map[string]interface{}); ok {
		if typeStr, ok := componentMap["type"].(string); ok {
			return typeStr
		}
	}
	return ""
}

// Helper function to extract paths from an http_server configuration
func extractPaths(httpConfig map[string]interface{}) map[string]string {
	paths := make(map[string]string)
	defaultPaths := map[string]string{
		"path":        "/post",
		"ws_path":     "/post/ws",
		"stream_path": "/get/stream",
	}
	for key, defaultValue := range defaultPaths {
		if val, ok := httpConfig[key].(string); ok {
			paths[key] = val
		} else {
			paths[key] = defaultValue
		}
	}
	return paths
}

// Helper function to extract HTTP server paths from a given configuration
func extractHTTPServerPaths(config map[string]interface{}) map[string]string {
	if httpServerConfig, ok := config["http_server"].(map[string]interface{}); ok {
		return extractPaths(httpServerConfig)
	}
	return nil
}

// Helper function to handle broker configurations
func handleBroker(brokerConfig map[string]interface{}) map[string]string {
	paths := make(map[string]string)
	for _, ioKey := range []string{"inputs", "outputs"} {
		if ioList, ok := brokerConfig[ioKey].([]interface{}); ok {
			for _, ioItem := range ioList {
				if ioItemMap, ok := ioItem.(map[string]interface{}); ok {
					for k, v := range extractHTTPServerPaths(ioItemMap) {
						paths[k] = v
					}
				}
			}
		}
	}
	return paths
}

// GetHTTPPaths is the main function to get HTTP paths from the stream configuration
func GetHTTPPaths(streamConfig map[string]interface{}) []string {
	paths := make(map[string]string)
	for _, component := range []string{"input", "output"} {
		if componentMap, ok := streamConfig[component].(map[string]interface{}); ok {
			for k, v := range extractHTTPServerPaths(componentMap) {
				paths[k] = v
			}
			if brokerConfig, ok := componentMap["broker"].(map[string]interface{}); ok {
				for k, v := range handleBroker(brokerConfig) {
					paths[k] = v
				}
			}
		}
	}
	// Convert map to slice of paths
	var deduplicated []string
	exists := make(map[string]struct{})
	for _, item := range paths {
		if _, ok := exists[item]; !ok {
			deduplicated = append(deduplicated, item)
			exists[item] = struct{}{}
		}
	}
	return deduplicated
}

// GetPathType returns whether a given path is for input or output, along with the path key
func GetPathType(streamConfig map[string]interface{}, path string) (string, string) {
	for _, component := range []string{"input", "output"} {
		if componentMap, ok := streamConfig[component].(map[string]interface{}); ok {
			paths := extractHTTPServerPaths(componentMap)
			for key, p := range paths {
				if p == path {
					return component, key
				}
			}
			if brokerConfig, ok := componentMap["broker"].(map[string]interface{}); ok {
				brokerPaths := handleBroker(brokerConfig)
				for key, p := range brokerPaths {
					if p == path {
						return component, key
					}
				}
			}
		}
	}
	return "", ""
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
		config:   config,
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
	logger   *logrus.Entry
	config   map[string]interface{}

	inputHandlers  map[string]func(http.ResponseWriter, *http.Request)
	outputHandlers map[string]func(http.ResponseWriter, *http.Request)
}

func (h *handleFuncAdapter) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) {
	h.sm.routeLock.Lock()
	defer h.sm.routeLock.Unlock()

	h.logger.Debugf("Registering streaming handleFunc for path: %s. Stream ID: %s", path, h.streamID)

	if h.mw == nil || h.sm.muxer == nil {
		h.logger.Error("StreamingMiddleware or muxer is nil")
		return
	}

	if h.inputHandlers == nil {
		h.inputHandlers = make(map[string]func(http.ResponseWriter, *http.Request))
	}
	if h.outputHandlers == nil {
		h.outputHandlers = make(map[string]func(http.ResponseWriter, *http.Request))
	}

	componentType, pathKey := GetPathType(h.config, path)
	if componentType == "input" {
		h.inputHandlers[path] = f
	} else {
		h.outputHandlers[path] = f
	}

	var match mux.RouteMatch
	newRequest := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: path},
	}
	h.sm.muxer.Match(newRequest, &match)

	existingHandler, ok := match.Handler.(http.HandlerFunc)
	if !ok {
		// h.logger.Errorf("Invalid route handler for path: %s", path)
	} else {
		// If the existing handler is for input, assign the output handler, and vice versa
		if componentType == "input" {
			h.outputHandlers[path] = existingHandler
		} else {
			h.inputHandlers[path] = existingHandler
		}

		h.logger.Debugf("Handler already exists for path: %s. Assigning reverse handler.", path)
		h.logger.Debugf("Input handler for path %s: %v", path, h.inputHandlers)
		h.logger.Debugf("Output handler for path %s: %v", path, h.outputHandlers)

		h.sm.muxer = cloneRouter(h.sm.muxer, path)
	}

	h.sm.muxer.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		h.sm.activityCounter.Add(1)
		defer h.sm.activityCounter.Add(-1)

		hasInput := h.inputHandlers[path] != nil
		hasOutput := h.outputHandlers[path] != nil

		if !hasInput || !hasOutput {
			h.logger.Debugf("Only output handler found for path: %s, executing directly", path)
			f(w, r)
			return
		}

		switch {
		case pathKey == "path":
			var handler func(http.ResponseWriter, *http.Request)
			var handlerType string
			handler = f

			if r.Method == http.MethodGet {
				handler, _ = h.outputHandlers[path]
				handlerType = "output"
			} else if r.Method == http.MethodPost {
				handler, _ = h.inputHandlers[path]
				handlerType = "input"
			}

			if handlerType != "" {
				h.logger.Debugf("Handling %s request for path: %s", handlerType, path)
			} else {
				h.logger.Debugf("No handler found for %s request for path: %s", r.Method, path)
			}

			handler(w, r)
			if handlerType == "output" {
				streamsConfig := &StreamsConfig{
					Streams: map[string]any{
						"stream": h.config,
					},
				}
				if h.mw.shouldDisableCache(streamsConfig) {
					h.logger.Debugf("Cache disabled, removing stream %s after output handler", h.streamID)
					h.sm.removeStream(h.streamID)
				}
			}
		case pathKey == "ws_path" && websocket.IsWebSocketUpgrade(r):
			h.handleWebSocket(f, w, r, path)
		default:
			h.logger.Debugf("Using default handler for path: %s", path)
			f(w, r)
		}
	})

	h.logger.Debugf("Registered handler for path: %s", path)
}

func (h *handleFuncAdapter) handleWebSocket(f func(w http.ResponseWriter, r *http.Request), w http.ResponseWriter, r *http.Request, path string) {
	if h.inputHandlers[path] == nil || h.outputHandlers[path] == nil {
		h.logger.Debugf("Executing directly %s", path)
		f(w, r)
		return
	}

	// Upgrade the client connection to WebSocket
	upgrader := websocket.Upgrader{}
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Errorf("Failed to upgrade client connection to WebSocket: %v", err)
		return
	}
	defer clientConn.Close()

	h.logger.Debugf("Upgraded client connection to WebSocket for path: %s", path)

	// Create net.Conn pairs for input and output handlers
	inputServerConn, inputClientConn := net.Pipe()
	outputServerConn, outputClientConn := net.Pipe()

	h.logger.Debugf("[WS] Input handler for path %s: %v", path, h.inputHandlers)
	h.logger.Debugf("[WS] Output handler for path %s: %v", path, h.outputHandlers)

	// Start HTTP servers for input and output handlers over their respective server conns
	go h.serveHandlerOverConn(inputServerConn, h.inputHandlers[path])
	go h.serveHandlerOverConn(outputServerConn, h.outputHandlers[path])

	// Perform client-side WebSocket handshakes over the client conns
	inputWsConn, err := h.performClientWebSocketHandshake(inputClientConn)
	if err != nil {
		h.logger.Errorf("Input handler handshake error: %v", err)
		return
	}
	defer inputWsConn.Close()

	outputWsConn, err := h.performClientWebSocketHandshake(outputClientConn)
	if err != nil {
		h.logger.Errorf("Output handler handshake error: %v", err)
		return
	}
	defer outputWsConn.Close()

	// Forward messages from client to input handler
	clientToInputErr := make(chan error, 1)
	go func() {
		for {
			mt, msg, err := clientConn.ReadMessage()
			if err != nil {
				clientToInputErr <- err
				return
			}
			err = inputWsConn.WriteMessage(mt, msg)
			if err != nil {
				clientToInputErr <- err
				return
			}
		}
	}()

	// Forward messages from output handler to client
	outputToClientErr := make(chan error, 1)
	go func() {
		for {
			mt, msg, err := outputWsConn.ReadMessage()
			if err != nil {
				outputToClientErr <- err
				return
			}
			err = clientConn.WriteMessage(mt, msg)
			if err != nil {
				outputToClientErr <- err
				return
			}
		}
	}()

	// Wait for any of the connections to error out
	select {
	case err := <-clientToInputErr:
		h.logger.Debugf("Client to input handler error: %v", err)
	case err := <-outputToClientErr:
		h.logger.Debugf("Output handler to client error: %v", err)
	}
}

func (h *handleFuncAdapter) serveHandlerOverConn(conn net.Conn, handlerFunc http.HandlerFunc) {
	if handlerFunc == nil {
		h.logger.Errorf("Handler function is nil for connection: %v", conn)
		conn.Close()
		return
	}
	listener := newOneConnListener(conn)
	server := &http.Server{
		Handler: handlerFunc,
	}
	server.Serve(listener)
}

func (h *handleFuncAdapter) performClientWebSocketHandshake(conn net.Conn) (*websocket.Conn, error) {
	// Use websocket.Dialer with a custom NetDial function
	d := websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return conn, nil
		},
	}

	// Since we're dialing over an existing connection, the URL and headers can be placeholders
	wsConn, _, err := d.Dial("ws://localhost/", nil)
	if err != nil {
		return nil, fmt.Errorf("dial error: %v", err)
	}
	return wsConn, nil
}

// oneConnListener is a net.Listener that returns a single net.Conn
type oneConnListener struct {
	conn net.Conn
	once sync.Once
	ch   chan net.Conn
}

func newOneConnListener(conn net.Conn) *oneConnListener {
	l := &oneConnListener{
		conn: conn,
		ch:   make(chan net.Conn, 1),
	}
	l.once.Do(func() {
		l.ch <- conn
	})
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, errors.New("listener closed")
	}
	return conn, nil
}

func (l *oneConnListener) Close() error {
	close(l.ch)
	return nil
}

func (l *oneConnListener) Addr() net.Addr {
	return dummyAddr("pipe")
}

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

func cloneRouter(r *mux.Router, excludePaths ...string) *mux.Router {
	newRouter := mux.NewRouter()

	err := r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()

		// Check if the current path should be excluded
		for _, excludePath := range excludePaths {
			if strings.HasPrefix(path, excludePath) {
				return nil // Skip this route
			}
		}

		// Clone the current route
		newRoute := newRouter.NewRoute()

		// Copy path
		newRoute.Path(path)

		// Copy methods
		if methods, err := route.GetMethods(); err == nil {
			newRoute.Methods(methods...)
		}

		// Copy handler
		if handler := route.GetHandler(); handler != nil {
			newRoute.Handler(handler)
		}

		// Copy queries
		if queries, err := route.GetQueriesTemplates(); err == nil {
			for i := 0; i < len(queries); i += 2 {
				newRoute.Queries(queries[i], queries[i+1])
			}
		}

		// Copy host
		if host, err := route.GetHostTemplate(); err == nil {
			newRoute.Host(host)
		}

		// Copy name
		if name := route.GetName(); name != "" {
			newRoute.Name(name)
		}

		// Handle subrouters
		if len(ancestors) > 0 {
			parent := ancestors[len(ancestors)-1]
			if parentPath, err := parent.GetPathTemplate(); err == nil {
				// Check if the parent path should be excluded
				shouldExclude := false
				for _, excludePath := range excludePaths {
					if strings.HasPrefix(parentPath, excludePath) {
						shouldExclude = true
						break
					}
				}
				if !shouldExclude {
					// Find or create the corresponding subrouter in the new router
					subRouter := newRouter.PathPrefix(parentPath).Subrouter()
					subRouter.Handle(path, route.GetHandler())
				}
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("Error cloning router: %v", err)
		return r
	}

	return newRouter
}

// Custom Reader that reads from a WebSocket connection
type websocketReader struct {
	conn *websocket.Conn
}

func (r *websocketReader) Read(p []byte) (n int, err error) {
	_, message, err := r.conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	copy(p, message)
	return len(message), nil
}

// Custom Writer that writes to a WebSocket connection
type websocketWriter struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (w *websocketWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	err = w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

type wsResponseWriter struct {
	header http.Header
	conn   *websocket.Conn
}

func (w *wsResponseWriter) Header() http.Header {
	return w.header
}

func (w *wsResponseWriter) Write(data []byte) (int, error) {
	err := w.conn.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func (w *wsResponseWriter) WriteHeader(statusCode int) {
	// No-op or handle as needed
}

// Implement http.Hijacker
func (w *wsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	netConn := newWsNetConn(w.conn)
	rw := bufio.NewReadWriter(bufio.NewReader(netConn), bufio.NewWriter(netConn))
	return netConn, rw, nil
}

// dummyResponseWriter is a no-op ResponseWriter for the Benthos input handler
type dummyResponseWriter struct {
	header http.Header
}

func (w *dummyResponseWriter) Header() http.Header {
	return w.header
}

func (w *dummyResponseWriter) Write(data []byte) (int, error) {
	// Benthos input handler shouldn't write data, so we discard it
	return len(data), nil
}

func (w *dummyResponseWriter) WriteHeader(statusCode int) {
	// No-op
}

func (w *dummyResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	dummyConn := &net.TCPConn{}
	reader := bufio.NewReader(strings.NewReader(""))
	writer := bufio.NewWriter(ioutil.Discard)
	return dummyConn, bufio.NewReadWriter(reader, writer), nil
}

func getHijackableResponseWriter(w http.ResponseWriter) (http.ResponseWriter, error) {
	type hijacker interface {
		http.ResponseWriter
		http.Hijacker
	}

	if _, ok := w.(hijacker); ok {
		return w, nil
	}

	// Unwrapping loop
	for {
		switch v := w.(type) {
		case interface{ Unwrap() http.ResponseWriter }:
			w = v.Unwrap()
		case interface{ Delegate() http.ResponseWriter }:
			w = v.Delegate()
		case interface{ UnderlyingResponseWriter() http.ResponseWriter }:
			w = v.UnderlyingResponseWriter()
		default:
			// Log the type of w for debugging purposes
			fmt.Printf("getHijackableResponseWriter: final type of w is %T\n", w)
			return nil, fmt.Errorf("ResponseWriter does not implement http.Hijacker")
		}

		if _, ok := w.(hijacker); ok {
			return w, nil
		}
	}
}

// wsNetConn implements net.Conn over a *websocket.Conn
type wsNetConn struct {
	wsConn     *websocket.Conn
	readBuffer bytes.Buffer
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closed     chan struct{}
}

func newWsNetConn(wsConn *websocket.Conn) *wsNetConn {
	return &wsNetConn{
		wsConn: wsConn,
		closed: make(chan struct{}),
	}
}

// Read implements the net.Conn Read method
func (c *wsNetConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	for {
		if c.readBuffer.Len() > 0 {
			return c.readBuffer.Read(b)
		}

		// Check if the connection is closed
		select {
		case <-c.closed:
			return 0, io.EOF
		default:
			// Read a new message from the WebSocket
			_, message, err := c.wsConn.ReadMessage()
			if err != nil {
				return 0, err
			}

			// Write the message to the buffer
			c.readBuffer.Write(message)
		}
	}
}

// Write implements the net.Conn Write method
func (c *wsNetConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// Write the data as a single WebSocket message
	err = c.wsConn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close implements the net.Conn Close method
func (c *wsNetConn) Close() error {
	close(c.closed)
	return c.wsConn.Close()
}

// LocalAddr returns the local network address
func (c *wsNetConn) LocalAddr() net.Addr {
	return c.wsConn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (c *wsNetConn) RemoteAddr() net.Addr {
	return c.wsConn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines
func (c *wsNetConn) SetDeadline(t time.Time) error {
	err := c.wsConn.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return c.wsConn.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
func (c *wsNetConn) SetReadDeadline(t time.Time) error {
	return c.wsConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
func (c *wsNetConn) SetWriteDeadline(t time.Time) error {
	return c.wsConn.SetWriteDeadline(t)
}
