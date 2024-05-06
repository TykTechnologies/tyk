package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
)

// TrackEndpoint configures Track or DoNotTrack behaviour for an endpoint.
// Tyk classic API definition: `version_data.versions..extended_paths.track_endpoints`, `version_data.versions..extended_paths.do_not_track_endpoints`.
type TrackEndpoint struct {
	// Enabled if set to true enables or disables tracking for an endpoint depending
	// if it's used in `trackEndpoint` or `doNotTrackEndpoint`.
	Enabled bool `bson:"enabled" json:"enabled"`
}

// Fill fills *TrackEndpoint receiver with data from apidef.TrackEndpointMeta.
func (i *TrackEndpoint) Fill(meta apidef.TrackEndpointMeta) {
	i.Enabled = !meta.Disabled
}

// ExtractTo fills *apidef.TrackEndpointMeta from *TrackEndpoint.
func (i *TrackEndpoint) ExtractTo(meta *apidef.TrackEndpointMeta) {
	meta.Disabled = !i.Enabled
}

func (s *OAS) fillTrackEndpoint(metas []apidef.TrackEndpointMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)

		if operation.TrackEndpoint == nil {
			operation.TrackEndpoint = &TrackEndpoint{}
		}

		operation.TrackEndpoint.Fill(meta)
		if ShouldOmit(operation.TrackEndpoint) {
			operation.TrackEndpoint = nil
		}
	}
}

func (s *OAS) fillDoNotTrackEndpoint(metas []apidef.TrackEndpointMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)

		if operation.DoNotTrackEndpoint == nil {
			operation.DoNotTrackEndpoint = &TrackEndpoint{}
		}

		operation.DoNotTrackEndpoint.Fill(meta)
		if ShouldOmit(operation.DoNotTrackEndpoint) {
			operation.DoNotTrackEndpoint = nil
		}
	}
}

func (o *Operation) extractTrackEndpointTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.TrackEndpoint == nil {
		return
	}

	meta := apidef.TrackEndpointMeta{Path: path, Method: method}
	o.TrackEndpoint.ExtractTo(&meta)
	ep.TrackEndpoints = append(ep.TrackEndpoints, meta)
}

func (o *Operation) extractDoNotTrackEndpointTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.DoNotTrackEndpoint == nil {
		return
	}

	meta := apidef.TrackEndpointMeta{Path: path, Method: method}
	o.DoNotTrackEndpoint.ExtractTo(&meta)
	ep.DoNotTrackEndpoints = append(ep.DoNotTrackEndpoints, meta)
}
