package oas

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-053
// SW-REQ-053:nominal:nominal
// SW-REQ-053:boundary:nominal
// SW-REQ-053:determinism:nominal
func TestInternalPreservesEndpointShape(t *testing.T) {
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
				internal := Internal{Enabled: !tc.wantEnabled}

				internal.Fill(apidef.InternalMeta{Disabled: tc.classicDisabled})

				assert.Equal(t, tc.wantEnabled, internal.Enabled)
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
				meta := apidef.InternalMeta{Path: "/internal", Method: http.MethodPatch, Disabled: !tc.wantDisabled}
				internal := Internal{Enabled: tc.enabled}

				internal.ExtractTo(&meta)

				assert.Equal(t, "/internal", meta.Path)
				assert.Equal(t, http.MethodPatch, meta.Method)
				assert.Equal(t, tc.wantDisabled, meta.Disabled)
			})
		}
	})

	t.Run("operation extraction appends path and method metadata only when internal config is present", func(t *testing.T) {
		ep := &apidef.ExtendedPathsSet{}
		omitted := Operation{}
		enabled := Operation{Internal: &Internal{Enabled: true}}
		disabled := Operation{Internal: &Internal{Enabled: false}}

		omitted.extractInternalTo(ep, "/omitted", http.MethodGet)
		require.Empty(t, ep.Internal)

		enabled.extractInternalTo(ep, "/enabled", http.MethodPost)
		disabled.extractInternalTo(ep, "/disabled", http.MethodDelete)

		require.Len(t, ep.Internal, 2)
		assert.Equal(t, apidef.InternalMeta{Path: "/enabled", Method: http.MethodPost, Disabled: false}, ep.Internal[0])
		assert.Equal(t, apidef.InternalMeta{Path: "/disabled", Method: http.MethodDelete, Disabled: true}, ep.Internal[1])
	})

	t.Run("OAS fill preserves enabled operations and omits disabled empty internal config", func(t *testing.T) {
		spec := minimumValidOAS()
		spec.Paths = openapi3.NewPaths()
		spec.SetTykExtension(&XTykAPIGateway{})

		spec.fillInternal([]apidef.InternalMeta{
			{Path: "/enabled", Method: http.MethodGet, Disabled: false},
			{Path: "/disabled", Method: http.MethodPost, Disabled: true},
		})

		operations := spec.GetTykExtension().Middleware.Operations

		require.NotNil(t, operations["enabled"+http.MethodGet].Internal)
		assert.True(t, operations["enabled"+http.MethodGet].Internal.Enabled)
		assert.Nil(t, operations["disabled"+http.MethodPost].Internal)
	})
}
