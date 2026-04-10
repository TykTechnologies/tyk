package streams

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gorilla/mux"
)

// Manager is responsible for creating a single stream.
type Manager struct {
	streams          sync.Map
	routeLock        sync.Mutex
	muxer            *mux.Router
	mw               *Middleware
	dryRun           bool
	listenPaths      []string
	activityCounter  atomic.Int32 // Counts active subscriptions, requests.
	analyticsFactory StreamAnalyticsFactory
}

func (sm *Manager) initStreams(r *http.Request, config *StreamsConfig) {
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

func (sm *Manager) setUpOrDryRunStream(streamConfig any, streamID string) {
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
func (sm *Manager) removeStream(streamID string) error {
	if streamValue, exists := sm.streams.Load(streamID); exists {
		stream, ok := streamValue.(*Stream)
		if !ok {
			return fmt.Errorf("stream %s is not a valid stream", streamID)
		}
		err := stream.Stop()
		if err != nil {
			return err
		}
		sm.streams.Delete(streamID)
	} else {
		return fmt.Errorf("stream %s does not exist", streamID)
	}
	return nil
}

// createStream creates a new stream
func (sm *Manager) createStream(streamID string, config map[string]interface{}) error {
	streamFullID := fmt.Sprintf("%s_%s", sm.mw.Spec.APIID, streamID)
	sm.mw.Logger().Debugf("Creating stream: %s", streamFullID)

	// add logger to config
	config["logger"] = map[string]interface{}{
		"level":         "INFO",
		"format":        "json",
		"add_timestamp": true,
		"static_fields": map[string]interface{}{
			"stream": streamID,
		},
	}

	stream := NewStream(sm.mw.allowedUnsafe)
	err := stream.Start(config, &HandleFuncAdapter{
		StreamMiddleware: sm.mw,
		StreamID:         streamFullID,
		Muxer:            sm.muxer,
		StreamManager:    sm,
		// child logger is necessary to prevent race condition
		Logger: sm.mw.Logger().WithField("stream", streamFullID),
	})
	if err != nil {
		sm.mw.Logger().Errorf("Failed to start stream %s: %v", streamFullID, err)
		return err
	}

	sm.streams.Store(streamFullID, stream)
	sm.mw.Logger().Infof("Successfully created stream: %s", streamFullID)

	return nil
}

func (sm *Manager) hasPath(path string) bool {
	for _, p := range sm.listenPaths {
		if strings.TrimPrefix(path, "/") == strings.TrimPrefix(p, "/") {
			return true
		}
	}
	return false
}

func (sm *Manager) SetAnalyticsFactory(factory StreamAnalyticsFactory) {
	if factory == nil {
		factory = &NoopStreamAnalyticsFactory{}
	}
	sm.analyticsFactory = factory
}
