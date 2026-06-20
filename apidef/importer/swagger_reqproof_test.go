package importer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-083
// SW-REQ-083:nominal:nominal
// SW-REQ-083:boundary:nominal
// SW-REQ-083:error_handling:negative
// SW-REQ-083:determinism:nominal
func TestSwaggerImporterReqProof_ConvertIntoApiVersion(t *testing.T) {
	var swagger SwaggerAST
	require.NoError(t, swagger.LoadFrom(strings.NewReader(reqproofSwaggerJSON)))

	version, err := swagger.ConvertIntoApiVersion(false)
	require.NoError(t, err)

	assert.True(t, version.UseExtendedPaths)
	assert.Equal(t, " 1.0.0 ", version.Name)
	require.Len(t, version.ExtendedPaths.WhiteList, 2)
	assert.Equal(t, "/pets", version.ExtendedPaths.WhiteList[0].Path)
	assert.Equal(t, "/users", version.ExtendedPaths.WhiteList[1].Path)

	pets := version.ExtendedPaths.WhiteList[0].MethodActions
	require.Contains(t, pets, "GET")
	require.Contains(t, pets, "POST")
	assert.Equal(t, apidef.NoAction, pets["GET"].Action)
	assert.Equal(t, 200, pets["GET"].Code)
	assert.Equal(t, apidef.NoAction, pets["POST"].Action)
	assert.Equal(t, 200, pets["POST"].Code)

	require.Len(t, version.ExtendedPaths.TrackEndpoints, 3)
	assert.Equal(t, []apidef.TrackEndpointMeta{
		{Path: "/pets", Method: "GET"},
		{Path: "/pets", Method: "POST"},
		{Path: "/users", Method: "DELETE"},
	}, version.ExtendedPaths.TrackEndpoints)

	second, err := swagger.ConvertIntoApiVersion(false)
	require.NoError(t, err)
	assert.Equal(t, version, second)

	_, err = swagger.ConvertIntoApiVersion(true)
	require.Error(t, err)
	assert.EqualError(t, err, "Swagger mocks not supported")
}

// Verifies: SYS-REQ-104, SW-REQ-083
// SW-REQ-083:nominal:nominal
// SW-REQ-083:boundary:boundary
// SW-REQ-083:error_handling:negative
// SW-REQ-083:determinism:nominal
func TestSwaggerImporterReqProof_LoadInsertAndBuildAPIDefinition(t *testing.T) {
	t.Run("load rejects malformed JSON", func(t *testing.T) {
		var swagger SwaggerAST
		require.Error(t, swagger.LoadFrom(strings.NewReader(`{"swagger":`)))
	})

	t.Run("conversion rejects empty paths", func(t *testing.T) {
		_, err := (&SwaggerAST{}).ConvertIntoApiVersion(false)
		require.Error(t, err)
		assert.EqualError(t, err, "no paths defined in swagger file")
	})

	t.Run("insert marks API as versioned and stores the named version", func(t *testing.T) {
		def := &apidef.APIDefinition{VersionData: apidef.VersionData{
			NotVersioned: true,
			Versions:     map[string]apidef.VersionInfo{},
		}}
		version := apidef.VersionInfo{Name: "v1"}

		require.NoError(t, (&SwaggerAST{}).InsertIntoAPIDefinitionAsVersion(version, def, "v1"))

		assert.False(t, def.VersionData.NotVersioned)
		assert.Equal(t, version, def.VersionData.Versions["v1"])
	})

	t.Run("API definition shape is stable apart from generated API ID", func(t *testing.T) {
		load := func(t *testing.T) *SwaggerAST {
			t.Helper()
			var swagger SwaggerAST
			require.NoError(t, swagger.LoadFrom(strings.NewReader(reqproofSwaggerJSON)))
			return &swagger
		}

		first, err := load(t).ToAPIDefinition("org-1", "https://upstream.example.com", true)
		require.NoError(t, err)
		second, err := load(t).ToAPIDefinition("org-1", "https://upstream.example.com", false)
		require.NoError(t, err)

		assert.NotEmpty(t, first.APIID)
		assert.NotEqual(t, first.APIID, second.APIID)
		assert.Equal(t, "Inventory Swagger", first.Name)
		assert.True(t, first.Active)
		assert.True(t, first.UseKeylessAccess)
		assert.Equal(t, "org-1", first.OrgID)
		assert.Equal(t, "version", first.VersionDefinition.Key)
		assert.Equal(t, apidef.HeaderLocation, first.VersionDefinition.Location)
		assert.Equal(t, "/"+first.APIID+"/", first.Proxy.ListenPath)
		assert.True(t, first.Proxy.StripListenPath)
		assert.Equal(t, "https://upstream.example.com", first.Proxy.TargetURL)
		require.Contains(t, first.VersionData.Versions, "1.0.0")
		assert.Equal(t, first.VersionData.Versions["1.0.0"], second.VersionData.Versions["1.0.0"])
	})
}

const reqproofSwaggerJSON = `{
  "swagger": "2.0",
  "info": {
    "version": " 1.0.0 ",
    "title": "Inventory Swagger"
  },
  "paths": {
    "/users": {
      "delete": {
        "operationId": "deleteUser",
        "responses": {
          "204": {"description": "deleted"}
        }
      }
    },
    "/pets": {
      "get": {
        "operationId": "listPets",
        "responses": {
          "200": {"description": "ok"}
        }
      },
      "post": {
        "description": "create pet"
      }
    },
    "/ignored": {}
  }
}`
