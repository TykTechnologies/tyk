package gateway

import (
	"net/http"

	"github.com/TykTechnologies/structviewer"
)

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
	viewer, err := gw.initConfigViewer()
	if err != nil {
		mainLog.WithError(err).Error("Failed to initialize config viewer")
		doJSONWrite(w, http.StatusInternalServerError, apiError("Failed to initialize config viewer"))
		return
	}
	viewer.ConfigHandler(w, r)
}

// envHandler handles GET /env requests.
// Returns all environment variable mappings, or a specific one if ?env=<ENV_VAR> is provided.
// Sensitive fields are automatically redacted based on structviewer:"obfuscate" tags.
func (gw *Gateway) envHandler(w http.ResponseWriter, r *http.Request) {
	viewer, err := gw.initConfigViewer()
	if err != nil {
		mainLog.WithError(err).Error("Failed to initialize config viewer")
		doJSONWrite(w, http.StatusInternalServerError, apiError("Failed to initialize config viewer"))
		return
	}
	viewer.EnvsHandler(w, r)
}
