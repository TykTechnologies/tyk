package gateway

import (
	"net/http"

	"github.com/TykTechnologies/structviewer"
)

const errMsgConfigViewerInit = "Failed to initialize config viewer"

// configViewerFactory is used to create config viewers.
// It can be overridden in tests to simulate errors.
var configViewerFactory = func(gw *Gateway) (*structviewer.Viewer, error) {
	return gw.initConfigViewer()
}

// initConfigViewer creates a new structviewer.Viewer for the current gateway configuration.
// A new viewer is created per-request to ensure hot-reloaded config is reflected immediately.
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
