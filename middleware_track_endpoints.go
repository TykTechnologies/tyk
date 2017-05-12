package main

import (
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
)

// TrackEndpointMiddleware sets context variables to enable or disable whether Tyk should record analytitcs for a specific path.
type TrackEndpointMiddleware struct {
	*TykMiddleware
}

// New lets you do any initialisations for the object can be done here
func (a *TrackEndpointMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (a *TrackEndpointMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

func (a *TrackEndpointMiddleware) GetName() string {
	return "TrackEndpointMiddleware"
}

func (a *TrackEndpointMiddleware) IsEnabledForSpec() bool { return true }

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (a *TrackEndpointMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	_, versionPaths, _, _ := a.TykMiddleware.Spec.GetVersionData(r)
	foundTracked, metaTrack := a.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, RequestTracked)
	if foundTracked {
		ctxSetTrackedPath(r, metaTrack.(*apidef.TrackEndpointMeta).Path)
	}

	foundDnTrack, _ := a.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, RequestNotTracked)
	if foundDnTrack {
		ctxSetDoNotTrack(r, true)
	}

	return nil, 200
}
