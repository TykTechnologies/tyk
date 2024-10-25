package streams

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/model"
)

// Middleware implements a streaming middleware.
type Middleware struct {
	Spec     model.MergedAPI
	Gw       Gateway
	logEntry *logrus.Entry

	createStreamManagerLock sync.Mutex
	StreamManagerCache      sync.Map // Map of payload hash to Manager

	ctx            context.Context
	cancel         context.CancelFunc
	allowedUnsafe  []string
	defaultManager *Manager
}

// Name holds the middleware name as a constant.
const Name = "StreamingMiddleware"

// Middleware implements model.Middleware.
var _ model.Middleware = &Middleware{}

// NewMiddleware returns a new instance of Middleware.
func NewMiddleware(gw Gateway, logger *logrus.Entry, spec model.MergedAPI) *Middleware {
	return &Middleware{
		Gw:       gw,
		Spec:     spec,
		logEntry: logger.WithField("mw", Name),
	}
}

// Logger returns a logger with middleware filled out.
func (s *Middleware) Logger() *logrus.Entry {
	return s.logEntry
}

// Name returns the name for the middleware.
func (s *Middleware) Name() string {
	return Name
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
	s.defaultManager = s.CreateStreamManager(nil)

	// Start garbage collection routine
	go func() {
		ticker := time.NewTicker(StreamGCInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.GC()
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

// CreateStreamManager creates or retrieves a stream manager based on the request.
func (s *Middleware) CreateStreamManager(r *http.Request) *Manager {
	streamsConfig := s.getStreamsConfig(r)
	configJSON, _ := json.Marshal(streamsConfig)
	cacheKey := fmt.Sprintf("%x", sha256.Sum256(configJSON))

	s.createStreamManagerLock.Lock()
	defer s.createStreamManagerLock.Unlock()

	s.Logger().Debug("Attempting to load stream manager from cache")
	s.Logger().Debugf("Cache key: %s", cacheKey)
	if cachedManager, found := s.StreamManagerCache.Load(cacheKey); found {
		s.Logger().Debug("Found cached stream manager")
		return cachedManager.(*Manager)
	}

	newManager := &Manager{
		muxer:           mux.NewRouter(),
		mw:              s,
		dryRun:          r == nil,
		activityCounter: atomic.Int32{},
	}
	newManager.initStreams(r, streamsConfig)

	if r != nil {
		s.StreamManagerCache.Store(cacheKey, newManager)
	}
	return newManager
}

// GC removes inactive stream managers.
func (s *Middleware) GC() {
	s.Logger().Debug("Starting garbage collection for inactive stream managers")

	s.StreamManagerCache.Range(func(key, value interface{}) bool {
		manager := value.(*Manager)
		if manager == s.defaultManager {
			return true
		}

		if manager.activityCounter.Load() <= 0 {
			s.Logger().Infof("Removing inactive stream manager: %v", key)
			manager.streams.Range(func(streamKey, streamValue interface{}) bool {
				streamID := streamKey.(string)
				err := manager.removeStream(streamID)
				if err != nil {
					s.Logger().WithError(err).Errorf("Error removing stream %s", streamID)
				}
				return true
			})
			s.StreamManagerCache.Delete(key)
		}

		return true
	})
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
	streamManager := s.CreateStreamManager(r)
	streamManager.routeLock.Lock()
	streamManager.muxer.Match(newRequest, &match)
	streamManager.routeLock.Unlock()

	// direct Bento handler
	handler, ok := match.Handler.(http.HandlerFunc)
	if !ok {
		return errors.New("invalid route handler"), http.StatusInternalServerError
	}

	streamManager.activityCounter.Add(1)
	defer streamManager.activityCounter.Add(-1)

	handler.ServeHTTP(w, r)

	return nil, middleware.StatusRespond
}

// Unload closes and remove active streams.
func (s *Middleware) Unload() {
	s.Logger().Debugf("Unloading streaming middleware %s", s.Spec.Name)

	totalStreams := 0
	s.cancel()

	s.StreamManagerCache.Range(func(_, value interface{}) bool {
		manager, ok := value.(*Manager)
		if !ok {
			return true
		}
		manager.streams.Range(func(_, streamValue interface{}) bool {
			totalStreams++
			if stream, ok := streamValue.(*Stream); ok {
				if err := stream.Reset(); err != nil {
					s.Logger().WithError(err).Error("Failed to reset stream")
				}
			}
			return true
		})
		return true
	})

	GlobalStreamCounter.Add(-int64(totalStreams))
	s.StreamManagerCache = sync.Map{}
	s.Logger().Info("All streams successfully removed")
}
