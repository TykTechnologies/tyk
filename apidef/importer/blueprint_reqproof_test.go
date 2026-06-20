package importer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-081
// SW-REQ-081:nominal:nominal
// SW-REQ-081:boundary:nominal
// SW-REQ-081:error_handling:negative
// SW-REQ-081:determinism:nominal
func TestBluePrintImporterReqProof_ConvertIntoApiVersion(t *testing.T) {
	var blueprint BluePrintAST
	require.NoError(t, blueprint.LoadFrom(strings.NewReader(reqproofBlueprintJSON)))

	version, err := blueprint.ConvertIntoApiVersion(false)
	require.NoError(t, err)

	assert.True(t, version.UseExtendedPaths)
	assert.Equal(t, "Inventory API", version.Name)
	require.Len(t, version.ExtendedPaths.WhiteList, 2)

	pets := version.ExtendedPaths.WhiteList[0]
	assert.Equal(t, "/pets", pets.Path)
	require.Contains(t, pets.MethodActions, "GET")
	assert.Equal(t, apidef.NoAction, pets.MethodActions["GET"].Action)
	assert.Equal(t, 201, pets.MethodActions["GET"].Code)
	assert.Equal(t, "created", pets.MethodActions["GET"].Data)
	assert.Equal(t, map[string]string{"X-Trace": "abc", "X-Mode": "mock"}, pets.MethodActions["GET"].Headers)

	users := version.ExtendedPaths.WhiteList[1]
	assert.Equal(t, "/users", users.Path)
	require.Contains(t, users.MethodActions, "POST")
	assert.Equal(t, 200, users.MethodActions["POST"].Code)
	assert.Equal(t, "fallback", users.MethodActions["POST"].Data)

	mockVersion, err := blueprint.ConvertIntoApiVersion(true)
	require.NoError(t, err)
	assert.Equal(t, apidef.Reply, mockVersion.ExtendedPaths.WhiteList[0].MethodActions["GET"].Action)

	second, err := blueprint.ConvertIntoApiVersion(false)
	require.NoError(t, err)
	assert.Equal(t, version, second)
}

// Verifies: SYS-REQ-104, SW-REQ-081
// SW-REQ-081:nominal:nominal
// SW-REQ-081:boundary:boundary
// SW-REQ-081:error_handling:negative
// SW-REQ-081:determinism:nominal
func TestBluePrintImporterReqProof_LoadInsertAndBuildAPIDefinition(t *testing.T) {
	t.Run("load rejects malformed JSON", func(t *testing.T) {
		var blueprint BluePrintAST
		require.Error(t, blueprint.LoadFrom(strings.NewReader(`{"name":`)))
	})

	t.Run("conversion rejects missing resource groups and empty groups", func(t *testing.T) {
		_, err := (&BluePrintAST{}).ConvertIntoApiVersion(false)
		require.Error(t, err)

		var blueprint BluePrintAST
		require.NoError(t, blueprint.LoadFrom(strings.NewReader(`{"name":"empty","resourceGroups":[{"name":"group","resources":[]}]}`)))
		_, err = blueprint.ConvertIntoApiVersion(false)
		require.Error(t, err)
	})

	t.Run("insert marks API as versioned and stores the named version", func(t *testing.T) {
		def := &apidef.APIDefinition{VersionData: apidef.VersionData{
			NotVersioned: true,
			Versions:     map[string]apidef.VersionInfo{},
		}}
		version := apidef.VersionInfo{Name: "v1"}

		require.NoError(t, (&BluePrintAST{}).InsertIntoAPIDefinitionAsVersion(version, def, "v1"))

		assert.False(t, def.VersionData.NotVersioned)
		assert.Equal(t, version, def.VersionData.Versions["v1"])
	})

	t.Run("API definition shape is stable apart from generated API ID", func(t *testing.T) {
		load := func(t *testing.T) *BluePrintAST {
			t.Helper()
			var blueprint BluePrintAST
			require.NoError(t, blueprint.LoadFrom(strings.NewReader(reqproofBlueprintJSON)))
			return &blueprint
		}

		first, err := load(t).ToAPIDefinition("org-1", "https://upstream.example.com", false)
		require.NoError(t, err)
		second, err := load(t).ToAPIDefinition("org-1", "https://upstream.example.com", false)
		require.NoError(t, err)

		assert.NotEmpty(t, first.APIID)
		assert.NotEmpty(t, second.APIID)
		assert.NotEqual(t, first.APIID, second.APIID)
		assert.Equal(t, "Inventory API", first.Name)
		assert.True(t, first.Active)
		assert.True(t, first.UseKeylessAccess)
		assert.Equal(t, "org-1", first.OrgID)
		assert.Equal(t, "version", first.VersionDefinition.Key)
		assert.Equal(t, apidef.HeaderLocation, first.VersionDefinition.Location)
		assert.Equal(t, "/"+first.APIID+"/", first.Proxy.ListenPath)
		assert.True(t, first.Proxy.StripListenPath)
		assert.Equal(t, "https://upstream.example.com", first.Proxy.TargetURL)
		require.Contains(t, first.VersionData.Versions, "Inventory API")
		assert.Equal(t, first.VersionData.Versions["Inventory API"], second.VersionData.Versions["Inventory API"])
	})
}

const reqproofBlueprintJSON = `{
  "name": "Inventory API",
  "resourceGroups": [
    {
      "name": "inventory",
      "resources": [
        {
          "uriTemplate": "/pets",
          "actions": [
            {
              "method": "GET",
              "examples": [
                {
                  "responses": [
                    {
                      "name": "201",
                      "body": "created",
                      "headers": [
                        {"name": "X-Trace", "value": "abc"},
                        {"name": "X-Mode", "value": "mock"}
                      ]
                    }
                  ]
                }
              ]
            },
            {
              "method": "DELETE",
              "examples": []
            }
          ]
        },
        {
          "uriTemplate": "/users",
          "actions": [
            {
              "method": "POST",
              "examples": [
                {
                  "responses": [
                    {
                      "name": "default",
                      "body": "fallback",
                      "headers": []
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}`
