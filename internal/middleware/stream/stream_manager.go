package stream

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/internal/streaming"
)

// Manager is responsible for creating a single stream.
type Manager struct {
	streams     sync.Map
	routeLock   sync.Mutex
	muxer       *mux.Router
	mw          *StreamingMiddleware
	dryRun      bool
	listenPaths []string
}

// NewManager creates a new Manager from a request. If request is
// nil, the stream manager runs with "dry run" enabled.
func NewManager(s *StreamingMiddleware, r *http.Request) *Manager {
	newManager := &Manager{
		muxer:  mux.NewRouter(),
		mw:     s,
		dryRun: r == nil,
	}
	streamID := fmt.Sprintf("_%d", time.Now().UnixNano())
	s.streamManagers.Store(streamID, newManager)

	// Call initStreams for the new Manager
	newManager.initStreams(r, s.getStreamsConfig(r))

	return newManager
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

// createStream creates a new stream
func (sm *Manager) createStream(streamID string, config map[string]interface{}) error {
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

func (sm *Manager) hasPath(path string) bool {
	for _, p := range sm.listenPaths {
		if strings.TrimPrefix(path, "/") == strings.TrimPrefix(p, "/") {
			return true
		}
	}
	return false
}
