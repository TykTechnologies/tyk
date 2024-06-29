package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/internal/streaming"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

const (
	ExtensionTykStreaming = "x-tyk-streaming"
)

// Used for testing
var globalStreamCounter atomic.Int64

// StreamingMiddleware is a middleware that handles streaming functionality
type StreamingMiddleware struct {
	*BaseMiddleware
	streams         map[string]*streamInfo
	streamsLock     sync.RWMutex
	muxer           *mux.Router
	streamingServer *streaming.StreamManager
	connections     map[string]map[string]connection
	connectionsLock sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
}

type streamInfo struct {
	config map[string]interface{}
}

type connection struct {
	id     string
	cancel context.CancelFunc
}

func (s *StreamingMiddleware) Name() string {
	return "StreamingMiddleware"
}

func (s *StreamingMiddleware) EnabledForSpec() bool {
	s.Logger().Error("Streams count: ", len(s.getStreams()))
	return len(s.getStreams()) > 0
}

// Init initializes the middleware
func (s *StreamingMiddleware) Init() {
	s.streams = make(map[string]*streamInfo)
	s.muxer = mux.NewRouter()
	s.connections = make(map[string]map[string]connection)
	s.ctx, s.cancel = context.WithCancel(context.Background())

	streamingConn := &storage.RedisCluster{ConnectionHandler: s.Gw.StorageConnectionHandler}
	client, err := streamingConn.Client()
	if err != nil {
		s.Logger().Errorf("Error getting streaming redis client: %v", err)
		return
	}

	s.streamingServer = streaming.NewStreamManager(client)
	s.updateStreams()
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

// updateStreams synchronizes the middleware's streams with the API spec
func (s *StreamingMiddleware) updateStreams() {
	s.streamsLock.Lock()
	defer s.streamsLock.Unlock()

	// Clear existing routes
	s.muxer = mux.NewRouter()

	specStreams := s.getStreams()

	globalStreamCounter.Add(int64(len(specStreams)))

	// Add or update streams from the spec
	for streamID, streamConfig := range specStreams {
		if streamMap, ok := streamConfig.(map[string]interface{}); ok {
			err := s.addOrUpdateStream(streamID, streamMap)
			if err != nil {
				s.Logger().Errorf("Error adding stream %s: %v", streamID, err)
			}
		}
	}
}

// addOrUpdateStream adds a new stream or updates an existing one
func (s *StreamingMiddleware) addOrUpdateStream(streamID string, config map[string]interface{}) error {
	streamFullID := s.Spec.APIID + "_" + streamID

	s.streams[streamFullID] = &streamInfo{config: config}

	return s.streamingServer.AddStream(streamFullID, config, &handleFuncAdapter{mw: s, streamID: streamFullID})
}

// removeStream removes a stream
func (s *StreamingMiddleware) removeStream(streamID string) error {
	streamFullID := s.Spec.APIID + "_" + streamID

	if _, exists := s.streams[streamFullID]; exists {
		err := s.streamingServer.RemoveStream(streamFullID)
		if err != nil {
			return err
		}
		delete(s.streams, streamFullID)
	}
	return nil
}

// ProcessRequest will handle the streaming functionality
func (s *StreamingMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	s.streamsLock.RLock()
	defer s.streamsLock.RUnlock()

	strippedPath := s.Spec.StripListenPath(r, r.URL.Path)

	s.Logger().Debugf("Processing request: %s, %s", r.URL.Path, strippedPath)

	newRequest := r.Clone(r.Context())
	newRequest.URL.Path = strippedPath

	var match mux.RouteMatch
	if s.muxer.Match(newRequest, &match) {
		pathRegexp, _ := match.Route.GetPathRegexp()
		s.Logger().Debugf("Matched stream: %v", pathRegexp)
		handler, _ := match.Handler.(http.HandlerFunc)
		if handler != nil {
			s.Logger().Debugf("Handling stream: %s", match.Route.GetName())
			handler.ServeHTTP(w, r)
			return nil, mwStatusRespond
		}
	}

	// If no stream matches, continue with the next middleware
	return nil, http.StatusOK
}

func (s *StreamingMiddleware) handleWebSocket(streamID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			s.Logger().Errorf("Failed to set websocket upgrade: %v", err)
			return
		}

		ctx, cancel := context.WithCancel(s.ctx)
		defer cancel()

		connID := uuid.New()
		s.addConnection(streamID, connection{id: connID, cancel: cancel})
		defer s.removeConnection(streamID, connID)

		consumerGroup := s.getConsumerGroup(r, streamID)
		messageChan, subCancel, err := s.streamingServer.Subscribe(streamID, consumerGroup, 100)
		if err != nil {
			s.Logger().Errorf("Failed to subscribe to stream: %v", err)
			conn.Close()
			return
		}
		defer s.streamingServer.Unsubscribe(streamID, consumerGroup, messageChan, subCancel)

		go s.websocketReadPump(ctx, conn)

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		s.websocketWritePump(ctx, conn, messageChan, ticker.C)
	}
}

func (s *StreamingMiddleware) websocketReadPump(ctx context.Context, conn *websocket.Conn) {
	defer conn.Close()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, _, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					s.Logger().Errorf("WebSocket read error: %v", err)
				}
				return
			}
		}
	}
}

func (s *StreamingMiddleware) websocketWritePump(ctx context.Context, conn *websocket.Conn, messageChan <-chan []byte, ticker <-chan time.Time) {
	defer conn.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				s.Logger().Errorf("Failed to write WebSocket ping message: %v", err)
				return
			}
		case message, ok := <-messageChan:
			if !ok {
				err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				if err != nil {
					s.Logger().Errorf("Failed to write WebSocket close message: %v", err)
				}
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
				s.Logger().Errorf("Failed to write message to WebSocket: %v", err)
				return
			}
		}
	}
}

func (s *StreamingMiddleware) handleSSE(streamID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		ctx, cancel := context.WithCancel(s.ctx)
		defer cancel()

		connID := uuid.New()
		s.addConnection(streamID, connection{id: connID, cancel: cancel})
		defer s.removeConnection(streamID, connID)

		consumerGroup := s.getConsumerGroup(r, streamID)
		messageChan, subCancel, err := s.streamingServer.Subscribe(streamID, consumerGroup, 100)
		if err != nil {
			s.Logger().Errorf("Failed to subscribe to SSE stream: %v", err)
			return
		}
		defer s.streamingServer.Unsubscribe(streamID, consumerGroup, messageChan, subCancel)

		go s.sseReadPump(ctx, r)

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		s.sseWritePump(ctx, w, flusher, messageChan, ticker.C)
	}
}

func (s *StreamingMiddleware) sseReadPump(ctx context.Context, r *http.Request) {
	<-ctx.Done()
	s.Logger().Debug("SSE context cancelled, closing connection")
}

func (s *StreamingMiddleware) sseWritePump(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, messageChan <-chan []byte, ticker <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			s.Logger().Debug("SSE context cancelled, stopping write pump")
			return
		case <-ticker:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				s.Logger().Errorf("Failed to write SSE ping: %v", err)
				return
			}
			flusher.Flush()
		case message, ok := <-messageChan:
			if !ok {
				s.Logger().Debug("SSE message channel closed")
				return
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", message); err != nil {
				s.Logger().Errorf("Failed to write SSE message: %v", err)
				return
			}
			flusher.Flush()
		}
	}
}

func (s *StreamingMiddleware) addConnection(streamID string, conn connection) {
	s.connectionsLock.Lock()
	defer s.connectionsLock.Unlock()
	if _, ok := s.connections[streamID]; !ok {
		s.connections[streamID] = make(map[string]connection)
	}
	s.connections[streamID][conn.id] = conn
}

func (s *StreamingMiddleware) removeConnection(streamID, connID string) {
	s.connectionsLock.Lock()
	defer s.connectionsLock.Unlock()

	if conns, ok := s.connections[streamID]; ok {
		delete(conns, connID)
		if len(conns) == 0 {
			delete(s.connections, streamID)
		}
	}
}

func (s *StreamingMiddleware) getConsumerGroup(r *http.Request, streamID string) string {
	consumerGroup := ctxGetAuthToken(r)
	streamConsumerGroup, _ := s.streamingServer.ConsumerGroup(streamID)

	if streamConsumerGroup != "" {
		consumerGroup = streamConsumerGroup
	}

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

	return consumerGroup
}

func (s *StreamingMiddleware) Unload() {
	s.Logger().Debugf("Unloading streaming middleware %s", s.Spec.Name)

	globalStreamCounter.Add(-int64(len(s.streams)))

	// Cancel the main context to signal all connec	s.cancel()
	s.cancel()

	// Close all active connections
	s.connectionsLock.Lock()
	s.Logger().Debugf("Closing %d active connections", len(s.connections))
	for _, conns := range s.connections {
		for _, conn := range conns {
			conn.cancel()
		}
	}
	s.connectionsLock.Unlock()

	// Wait for a short period to allow connections to close gracefully
	time.Sleep(500 * time.Millisecond)

	s.streamingServer.Reset()

	// Clear the streams map
	s.streams = make(map[string]*streamInfo)
	// Clear the muxer
	s.muxer = mux.NewRouter()
	// Clear the connections map
	s.connections = make(map[string]map[string]connection)

	s.Logger().Info("All streams successfully removed and connections closed")
}

type handleFuncAdapter struct {
	streamID string
	mw       *StreamingMiddleware
}

func (h *handleFuncAdapter) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) {
	log.Debugf("Registering streaming handleFunc for path: %s", path)

	httpOutputConfig, _ := h.mw.streamingServer.GetHTTPPaths("output", h.streamID)

	wrappedFunc := func(w http.ResponseWriter, r *http.Request) {
		log.Debug("Entering debug for wrapped function on path: ", path)

		var targetFunc func(http.ResponseWriter, *http.Request) = f

		if httpOutputConfig["ws_path"] == path {
			log.Debug("Handling websocket subscription")
			targetFunc = h.mw.handleWebSocket(h.streamID)

			// Internal benthos magic, we still need to consumer original handler
			wsConsumer := consumeWebsocket(f)
			defer wsConsumer.Close()
		} else if httpOutputConfig["sse_path"] == path {
			log.Debug("Handling SSE subscription")
			targetFunc = h.mw.handleSSE(h.streamID)

			// Internal benthos magic, we still need to consumer original handler
			sseConsumer := consumeSSE(f)
			defer sseConsumer.Close()
		}

		targetFunc(w, r)

		log.Debug("Exiting debug for wrapped function on path: ", path)
	}

	h.mw.muxer.HandleFunc(path, wrappedFunc)
}

func consumeWebsocket(f func(http.ResponseWriter, *http.Request)) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(f))

	go func() {
		ws, _, err := websocket.DefaultDialer.Dial(strings.Replace(server.URL, "http", "ws", 1), nil)
		if err != nil {
			log.Fatal("dial:", err)
		}

		defer ws.Close()

		for {
			_, message, err := ws.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				return
			}
			log.Printf("recv: %s", message)
		}
	}()

	return server
}

func consumeSSE(f func(http.ResponseWriter, *http.Request)) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(f))

	go func() {
		resp, err := http.Get(server.URL)
		if err != nil {
			log.Fatal("get:", err)
		}
		defer resp.Body.Close()

		reader := bufio.NewReader(resp.Body)

		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Println("read:", err)
				return
			}
			log.Printf("recv: %s", line)
		}
	}()

	return server
}
