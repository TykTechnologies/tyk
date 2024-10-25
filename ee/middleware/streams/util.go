package streams

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type HandleFuncAdapter struct {
	StreamID         string
	StreamManager    *Manager
	StreamMiddleware *Middleware
	Muxer            *mux.Router
	Logger           *logrus.Entry
}

func (h *HandleFuncAdapter) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) {
	h.Logger.Debugf("Registering streaming handleFunc for path: %s", path)

	if h.StreamMiddleware == nil || h.Muxer == nil {
		h.Logger.Error("Middleware or muxer is nil")
		return
	}

	h.StreamManager.routeLock.Lock()
	h.Muxer.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		recorder := h.StreamManager.analyticsFactory.CreateRecorder(r)
		analyticsResponseWriter := h.StreamManager.analyticsFactory.CreateResponseWriter(w, r, h.StreamID, recorder)

		h.StreamManager.activityCounter.Add(1)
		defer h.StreamManager.activityCounter.Add(-1)
		f(analyticsResponseWriter, r)
	})
	h.StreamManager.routeLock.Unlock()
	h.Logger.Debugf("Registered handler for path: %s", path)
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

// extractHTTPServerPaths is a helper function to extract HTTP server paths from a given configuration.
func extractHTTPServerPaths(config map[string]interface{}) []string {
	if httpServerConfig, ok := config["http_server"].(map[string]interface{}); ok {
		return extractPaths(httpServerConfig)
	}
	return nil
}

// handleBroker is a helper function to handle broker configurations.
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

// GetHTTPPaths is the main function to get HTTP paths from the stream configuration.
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
