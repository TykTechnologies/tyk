package oas

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-054
// SW-REQ-054:nominal:nominal
// SW-REQ-054:boundary:nominal
// SW-REQ-054:determinism:nominal
func TestTrackEndpointPreservesEndpointShape(t *testing.T) {
	t.Run("classic disabled flag maps to OAS enabled flag", func(t *testing.T) {
		for _, tc := range []struct {
			name            string
			classicDisabled bool
			wantEnabled     bool
		}{
			{name: "enabled", classicDisabled: false, wantEnabled: true},
			{name: "disabled", classicDisabled: true, wantEnabled: false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				endpoint := TrackEndpoint{Enabled: !tc.wantEnabled}

				endpoint.Fill(apidef.TrackEndpointMeta{Disabled: tc.classicDisabled})

				assert.Equal(t, tc.wantEnabled, endpoint.Enabled)
			})
		}
	})

	t.Run("OAS enabled flag maps back to classic disabled flag without dropping endpoint identity", func(t *testing.T) {
		for _, tc := range []struct {
			name         string
			enabled      bool
			wantDisabled bool
		}{
			{name: "enabled", enabled: true, wantDisabled: false},
			{name: "disabled", enabled: false, wantDisabled: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				meta := apidef.TrackEndpointMeta{Path: "/analytics", Method: http.MethodPatch, Disabled: !tc.wantDisabled}
				endpoint := TrackEndpoint{Enabled: tc.enabled}

				endpoint.ExtractTo(&meta)

				assert.Equal(t, "/analytics", meta.Path)
				assert.Equal(t, http.MethodPatch, meta.Method)
				assert.Equal(t, tc.wantDisabled, meta.Disabled)
			})
		}
	})

	t.Run("operation extraction appends track and do-not-track metadata to distinct classic lists", func(t *testing.T) {
		ep := &apidef.ExtendedPathsSet{}
		omitted := Operation{}
		operation := Operation{
			TrackEndpoint:      &TrackEndpoint{Enabled: true},
			DoNotTrackEndpoint: &TrackEndpoint{Enabled: false},
		}

		omitted.extractTrackEndpointTo(ep, "/omitted-track", http.MethodGet)
		omitted.extractDoNotTrackEndpointTo(ep, "/omitted-do-not-track", http.MethodGet)
		require.Empty(t, ep.TrackEndpoints)
		require.Empty(t, ep.DoNotTrackEndpoints)

		operation.extractTrackEndpointTo(ep, "/tracked", http.MethodPost)
		operation.extractDoNotTrackEndpointTo(ep, "/not-tracked", http.MethodDelete)

		require.Len(t, ep.TrackEndpoints, 1)
		require.Len(t, ep.DoNotTrackEndpoints, 1)
		assert.Equal(t, apidef.TrackEndpointMeta{Path: "/tracked", Method: http.MethodPost, Disabled: false}, ep.TrackEndpoints[0])
		assert.Equal(t, apidef.TrackEndpointMeta{Path: "/not-tracked", Method: http.MethodDelete, Disabled: true}, ep.DoNotTrackEndpoints[0])
	})

	t.Run("OAS fill preserves enabled tracking operations and omits disabled empty tracking config", func(t *testing.T) {
		spec := minimumValidOAS()
		spec.Paths = openapi3.NewPaths()
		spec.SetTykExtension(&XTykAPIGateway{})

		spec.fillTrackEndpoint([]apidef.TrackEndpointMeta{
			{Path: "/tracked", Method: http.MethodGet, Disabled: false},
			{Path: "/track-disabled", Method: http.MethodPost, Disabled: true},
		})
		spec.fillDoNotTrackEndpoint([]apidef.TrackEndpointMeta{
			{Path: "/not-tracked", Method: http.MethodPut, Disabled: false},
			{Path: "/do-not-track-disabled", Method: http.MethodDelete, Disabled: true},
		})

		operations := spec.GetTykExtension().Middleware.Operations

		require.NotNil(t, operations["tracked"+http.MethodGet].TrackEndpoint)
		assert.True(t, operations["tracked"+http.MethodGet].TrackEndpoint.Enabled)
		assert.Nil(t, operations["track-disabled"+http.MethodPost].TrackEndpoint)

		require.NotNil(t, operations["not-tracked"+http.MethodPut].DoNotTrackEndpoint)
		assert.True(t, operations["not-tracked"+http.MethodPut].DoNotTrackEndpoint.Enabled)
		assert.Nil(t, operations["do-not-track-disabled"+http.MethodDelete].DoNotTrackEndpoint)
	})
}
