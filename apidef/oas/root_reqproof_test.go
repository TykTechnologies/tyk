package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-061
// SW-REQ-061:nominal:nominal
// SW-REQ-061:boundary:nominal
// SW-REQ-061:determinism:nominal
func TestRootExtensionPreservesClassicModelShape(t *testing.T) {
	t.Run("top level fill and extract preserve info state versioning and error override shape", func(t *testing.T) {
		api := apidef.APIDefinition{
			APIID:      "api-id",
			OrgID:      "org-id",
			Name:       "pets",
			Expiration: "2030-01-01",
			Active:     true,
			Internal:   true,
			VersionDefinition: apidef.VersionDefinition{
				Enabled:              true,
				Name:                 "v1",
				Default:              "v2",
				Location:             "url-param",
				Key:                  "version",
				Versions:             map[string]string{"v2": "api-v2", "v1": "api-v1"},
				StripVersioningData:  true,
				UrlVersioningPattern: "v[0-9]+",
				FallbackToDefault:    true,
			},
			ErrorOverridesDisabled: false,
			ErrorOverrides: apidef.ErrorOverridesMap{
				"404": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 404,
							Body:       `{"error":"missing"}`,
						},
					},
				},
			},
		}

		var root XTykAPIGateway
		root.Fill(api)

		assert.Equal(t, "api-id", root.Info.ID)
		assert.Equal(t, "org-id", root.Info.OrgID)
		assert.Equal(t, "pets", root.Info.Name)
		assert.True(t, root.Info.State.Active)
		assert.True(t, root.Info.State.Internal)
		require.NotNil(t, root.Info.Versioning)
		assert.Equal(t, []VersionToID{{Name: "v1", ID: "api-v1"}, {Name: "v2", ID: "api-v2"}}, root.Info.Versioning.Versions)
		require.NotNil(t, root.ErrorOverrides)
		assert.True(t, root.ErrorOverrides.Enabled)

		var extracted apidef.APIDefinition
		root.ExtractTo(&extracted)

		assert.Equal(t, api.APIID, extracted.APIID)
		assert.Equal(t, api.OrgID, extracted.OrgID)
		assert.Equal(t, api.Name, extracted.Name)
		assert.Equal(t, api.Expiration, extracted.Expiration)
		assert.True(t, extracted.Active)
		assert.True(t, extracted.Internal)
		assert.Equal(t, api.VersionDefinition, extracted.VersionDefinition)
		assert.True(t, extracted.VersionData.NotVersioned)
		assert.Contains(t, extracted.VersionData.Versions, "")
		assert.False(t, extracted.ErrorOverridesDisabled)
		assert.Equal(t, api.ErrorOverrides, extracted.ErrorOverrides)
	})

	t.Run("nil optional root children are restored after extraction and disabled overrides stay explicit", func(t *testing.T) {
		root := XTykAPIGateway{
			Info: Info{
				Name: "minimal",
				State: State{
					Active: true,
				},
			},
			ErrorOverrides: nil,
		}

		var extracted apidef.APIDefinition
		root.ExtractTo(&extracted)

		assert.Nil(t, root.Middleware)
		assert.Nil(t, root.Info.Versioning)
		assert.True(t, extracted.ErrorOverridesDisabled)
		assert.Nil(t, extracted.ErrorOverrides)
		assert.Equal(t, "minimal", extracted.Name)
		assert.True(t, extracted.Active)

		root.ErrorOverrides = &ErrorOverrides{Enabled: false}
		root.ExtractTo(&extracted)
		assert.True(t, extracted.ErrorOverridesDisabled)
		assert.Nil(t, extracted.ErrorOverrides)
	})

	t.Run("info state and versioning helpers preserve boundary values", func(t *testing.T) {
		var state State
		state.Fill(apidef.APIDefinition{Active: true, Internal: false})
		assert.Equal(t, State{Active: true}, state)
		var stateAPI apidef.APIDefinition
		state.ExtractTo(&stateAPI)
		assert.True(t, stateAPI.Active)
		assert.False(t, stateAPI.Internal)

		var info Info
		info.Fill(apidef.APIDefinition{Name: "unversioned"})
		assert.Nil(t, info.Versioning)
		var infoAPI apidef.APIDefinition
		info.ExtractTo(&infoAPI)
		assert.Nil(t, info.Versioning)
		assert.True(t, infoAPI.VersionData.NotVersioned)
		assert.Equal(t, "", infoAPI.VersionData.DefaultVersion)
		assert.Equal(t, map[string]apidef.VersionInfo{"": {}}, infoAPI.VersionData.Versions)

		versioning := Versioning{
			Enabled: true,
			Name:    "v1",
			Versions: []VersionToID{
				{Name: "v1", ID: "api-v1"},
			},
		}
		var versionAPI apidef.APIDefinition
		versioning.ExtractTo(&versionAPI)
		assert.Equal(t, map[string]string{"v1": "api-v1"}, versionAPI.VersionDefinition.Versions)

		versioning.Versions = nil
		versioning.ExtractTo(&versionAPI)
		assert.Nil(t, versionAPI.VersionDefinition.Versions)
	})

	t.Run("import defaults enable only absent global helpers", func(t *testing.T) {
		var root XTykAPIGateway
		root.enableContextVariablesIfEmpty()
		root.enableTrafficLogsIfEmpty()
		require.NotNil(t, root.Middleware)
		require.NotNil(t, root.Middleware.Global)
		require.NotNil(t, root.Middleware.Global.ContextVariables)
		require.NotNil(t, root.Middleware.Global.TrafficLogs)
		assert.True(t, root.Middleware.Global.ContextVariables.Enabled)
		assert.True(t, root.Middleware.Global.TrafficLogs.Enabled)

		root.Middleware.Global.ContextVariables.Enabled = false
		root.Middleware.Global.TrafficLogs.Enabled = false
		root.enableContextVariablesIfEmpty()
		root.enableTrafficLogsIfEmpty()
		assert.False(t, root.Middleware.Global.ContextVariables.Enabled)
		assert.False(t, root.Middleware.Global.TrafficLogs.Enabled)
	})

	t.Run("repeated version fill produces sorted mappings", func(t *testing.T) {
		api := apidef.APIDefinition{
			VersionDefinition: apidef.VersionDefinition{
				Versions: map[string]string{"v3": "api-v3", "v1": "api-v1", "v2": "api-v2"},
			},
		}

		var first Versioning
		var second Versioning
		first.Fill(api)
		second.Fill(api)
		expected := []VersionToID{{Name: "v1", ID: "api-v1"}, {Name: "v2", ID: "api-v2"}, {Name: "v3", ID: "api-v3"}}
		assert.Equal(t, expected, first.Versions)
		assert.Equal(t, expected, second.Versions)
	})
}
