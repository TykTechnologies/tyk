package main

import (
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
)

// TrackEndpointMiddleware sets context variables to enable or disable whether Tyk should record analytitcs for a specific path.
type TrackEndpointMiddleware struct {
	*BaseMiddleware
}

func (a *TrackEndpointMiddleware) Name() string {
	return "TrackEndpointMiddleware"
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (a *TrackEndpointMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	_, versionPaths, _, _ := a.Spec.Version(r)
	foundTracked, metaTrack := a.Spec.CheckSpecMatchesStatus(r, versionPaths, RequestTracked)
	if foundTracked {
		ctxSetTrackedPath(r, metaTrack.(*apidef.TrackEndpointMeta).Path)
	}

	foundDnTrack, _ := a.Spec.CheckSpecMatchesStatus(r, versionPaths, RequestNotTracked)
	if foundDnTrack {
		ctxSetDoNotTrack(r, true)
	}

	return nil, 200
}
