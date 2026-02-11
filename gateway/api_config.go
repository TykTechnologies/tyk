package gateway

import (
	"net/http"
	"sync"

	"github.com/TykTechnologies/structviewer"
)

const errMsgConfigViewerInit = "Failed to initialize config viewer"

// configViewerFactory is used to create config viewers.
// It can be overridden in tests to simulate errors.
var configViewerFactory = func(gw *Gateway) (*structviewer.Viewer, error) {
	return gw.getOrCreateConfigViewer()
}

// configViewerCache holds a cached structviewer.Viewer to avoid expensive
// reflection-based initialization on every request. The cache is invalidated
// when the gateway configuration is reloaded (see SetConfig).
type configViewerCache struct {
	mu     sync.RWMutex
	viewer *structviewer.Viewer
}

// get returns the cached viewer, or nil if the cache is empty.
func (c *configViewerCache) get() *structviewer.Viewer {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.viewer
}

// set stores a viewer in the cache.
func (c *configViewerCache) set(v *structviewer.Viewer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.viewer = v
}

// invalidate clears the cached viewer, forcing re-creation on next access.
func (c *configViewerCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.viewer = nil
}

// getOrCreateConfigViewer returns a cached viewer or creates a new one.
// The viewer is cached to avoid reflection overhead on every request.
func (gw *Gateway) getOrCreateConfigViewer() (*structviewer.Viewer, error) {
	if gw.configViewerCache == nil {
		gw.configViewerCache = &configViewerCache{}
	}

	if v := gw.configViewerCache.get(); v != nil {
		return v, nil
	}

	v, err := gw.initConfigViewer()
	if err != nil {
		return nil, err
	}

	gw.configViewerCache.set(v)
	return v, nil
}

// initConfigViewer creates a new structviewer.Viewer for the current gateway configuration.
func (gw *Gateway) initConfigViewer() (*structviewer.Viewer, error) {
	cfg := gw.GetConfig()
	viewerCfg := &structviewer.Config{
		Object:        &cfg,
		ParseComments: false,
	}
	return structviewer.New(viewerCfg, "TYK_GW_")
}

// configHandler handles GET /config requests.
// Returns the full gateway configuration as JSON, or a specific field if ?field=<path> is provided.
// Sensitive fields are automatically redacted based on structviewer:"obfuscate" tags.
func (gw *Gateway) configHandler(w http.ResponseWriter, r *http.Request) {
	viewer, err := configViewerFactory(gw)
	if err != nil {
		mainLog.WithError(err).Error(errMsgConfigViewerInit)
		doJSONWrite(w, http.StatusInternalServerError, apiError(errMsgConfigViewerInit))
		return
	}
	viewer.ConfigHandler(w, r)
}

// envHandler handles GET /env requests.
// Returns all environment variable mappings, or a specific one if ?env=<ENV_VAR> is provided.
// Sensitive fields are automatically redacted based on structviewer:"obfuscate" tags.
func (gw *Gateway) envHandler(w http.ResponseWriter, r *http.Request) {
	viewer, err := configViewerFactory(gw)
	if err != nil {
		mainLog.WithError(err).Error(errMsgConfigViewerInit)
		doJSONWrite(w, http.StatusInternalServerError, apiError(errMsgConfigViewerInit))
		return
	}
	viewer.EnvsHandler(w, r)
}
