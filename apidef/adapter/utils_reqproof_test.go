package adapter

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

type importAdapterStub struct {
	api *apidef.APIDefinition
	err error
}

func (s importAdapterStub) Import() (*apidef.APIDefinition, error) {
	return s.api, s.err
}

// Verifies: SYS-REQ-104, SW-REQ-068
// SW-REQ-068:nominal:nominal
// SW-REQ-068:boundary:nominal
// SW-REQ-068:determinism:nominal
func TestGraphQLAdapterUtilsPreserveClassificationAndDefaults(t *testing.T) {
	t.Run("disabled and unknown graphQL mode returns unknown adapter type", func(t *testing.T) {
		unknownAdapterType := GraphQLEngineAdapterType(GraphQLEngineAdapterTypeUnknown)
		disabled := &apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Enabled:       false,
				ExecutionMode: apidef.GraphQLExecutionModeProxyOnly,
			},
		}
		assert.Equal(t, unknownAdapterType, graphqlEngineAdapterTypeFromApiDefinition(disabled))

		unknown := &apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Enabled:       true,
				ExecutionMode: apidef.GraphQLExecutionMode("unsupported"),
			},
		}
		assert.Equal(t, unknownAdapterType, graphqlEngineAdapterTypeFromApiDefinition(unknown))
	})

	t.Run("new API definition carries deterministic graphQL adapter defaults", func(t *testing.T) {
		api := newApiDefinition("orders", "org-1")

		require.NotNil(t, api)
		assert.Equal(t, "orders", api.Name)
		assert.Equal(t, "org-1", api.OrgID)
		assert.NotEmpty(t, api.APIID)
		assert.True(t, api.Active)
		assert.True(t, api.GraphQL.Enabled)
		assert.Equal(t, apidef.GraphQLConfigVersion2, api.GraphQL.Version)
		assert.Equal(t, apidef.GraphQLExecutionModeExecutionEngine, api.GraphQL.ExecutionMode)
		assert.NotNil(t, api.GraphQL.Proxy.AuthHeaders)
		assert.False(t, api.VersionDefinition.Enabled)
		assert.Equal(t, "header", api.VersionDefinition.Location)
		assert.True(t, api.VersionData.NotVersioned)
		require.Contains(t, api.VersionData.Versions, "Default")
		assert.Equal(t, "Default", api.VersionData.Versions["Default"].Name)
		assert.True(t, api.VersionData.Versions["Default"].UseExtendedPaths)
		assert.True(t, api.Proxy.StripListenPath)
	})

	t.Run("field configs and data sources sort deterministically by name", func(t *testing.T) {
		api := &apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Engine: apidef.GraphQLEngineConfig{
					FieldConfigs: []apidef.GraphQLFieldConfig{
						{FieldName: "zeta"},
						{FieldName: "alpha"},
						{FieldName: "middle"},
					},
					DataSources: []apidef.GraphQLEngineDataSource{
						{Name: "orders"},
						{Name: "accounts"},
						{Name: "billing"},
					},
				},
			},
		}

		sortFieldConfigsByName(api)
		sortDataSourcesByName(api)

		assert.Equal(t, []apidef.GraphQLFieldConfig{
			{FieldName: "alpha"},
			{FieldName: "middle"},
			{FieldName: "zeta"},
		}, api.GraphQL.Engine.FieldConfigs)
		assert.Equal(t, []apidef.GraphQLEngineDataSource{
			{Name: "accounts"},
			{Name: "billing"},
			{Name: "orders"},
		}, api.GraphQL.Engine.DataSources)
	})

	t.Run("import adapter interface preserves API definition and error result shape", func(t *testing.T) {
		wantAPI := &apidef.APIDefinition{Name: "orders"}
		wantErr := errors.New("import failed")
		var adapter ImportAdapter = importAdapterStub{api: wantAPI, err: wantErr}

		gotAPI, gotErr := adapter.Import()

		assert.Same(t, wantAPI, gotAPI)
		assert.ErrorIs(t, gotErr, wantErr)
	})
}
