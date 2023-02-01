package apidef

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	schema "github.com/xeipuuv/gojsonschema"
)

func TestSchema(t *testing.T) {
	schemaLoader := schema.NewBytesLoader([]byte(Schema))

	spec := DummyAPI()
	goLoader := schema.NewGoLoader(spec)
	result, err := schema.Validate(schemaLoader, goLoader)
	if err != nil {
		t.Error(err)
	}

	if !result.Valid() {
		for _, err := range result.Errors() {
			t.Error(err)
		}
	}
}

func TestEncodeForDB(t *testing.T) {
	t.Run("update ScopeClaim when Scopes.JWT is not empty and OIDC is not enabled", func(t *testing.T) {
		spec := DummyAPI()
		defaultScopeName := "scope"
		scopeToPolicyMap := map[string]string{
			"user:read": "pID1",
		}
		spec.Scopes.JWT = ScopeClaim{
			ScopeClaimName: defaultScopeName,
			ScopeToPolicy:  scopeToPolicyMap,
		}
		spec.EncodeForDB()
		assert.Equal(t, defaultScopeName, spec.JWTScopeClaimName)
		assert.Equal(t, scopeToPolicyMap, spec.JWTScopeToPolicyMapping)
	})

	t.Run("update ScopeClaim when Scopes.OIDC is not empty and OpenID is enabled", func(t *testing.T) {
		spec := DummyAPI()
		defaultScopeName := "scope"
		scopeToPolicyMap := map[string]string{
			"user:read": "pID1",
		}
		spec.Scopes.OIDC = ScopeClaim{
			ScopeClaimName: defaultScopeName,
			ScopeToPolicy:  scopeToPolicyMap,
		}
		spec.UseOpenID = true
		spec.EncodeForDB()
		assert.Equal(t, defaultScopeName, spec.JWTScopeClaimName)
		assert.Equal(t, scopeToPolicyMap, spec.JWTScopeToPolicyMapping)
	})

	t.Run("EncodeForDB persist schema objects from extended path", func(t *testing.T) {
		spec := DummyAPI()
		spec.EncodeForDB()
		var schemaNotEmpty bool
		for _, version := range spec.VersionData.Versions {
			for _, validateObj := range version.ExtendedPaths.ValidateJSON {
				schemaNotEmpty = schemaNotEmpty || (validateObj.Schema != nil)
			}
		}
		assert.True(t, schemaNotEmpty, "expected EncodeForDB to persist schema objects")
	})
}

func TestDecodeFromDB(t *testing.T) {
	t.Run("update Scopes.JWT when JWTScopeClaimName is not empty", func(t *testing.T) {
		spec := DummyAPI()
		defaultScopeName := "scope"
		spec.JWTScopeClaimName = defaultScopeName
		scopeToPolicyMap := map[string]string{
			"user:read": "pID1",
		}
		spec.JWTScopeToPolicyMapping = scopeToPolicyMap
		spec.DecodeFromDB()
		expectedJWTScope := ScopeClaim{
			ScopeClaimName: defaultScopeName,
			ScopeToPolicy:  scopeToPolicyMap,
		}
		assert.Equal(t, expectedJWTScope, spec.Scopes.JWT)
	})

	t.Run("update Scopes.OIDC when JWTScopeClaimName is not empty and OpenID is enabled", func(t *testing.T) {
		spec := DummyAPI()
		defaultScopeName := "scope"
		spec.JWTScopeClaimName = defaultScopeName
		scopeToPolicyMap := map[string]string{
			"user:read": "pID1",
		}
		spec.UseOpenID = true
		spec.JWTScopeToPolicyMapping = scopeToPolicyMap
		spec.DecodeFromDB()
		expectedOICScope := ScopeClaim{
			ScopeClaimName: defaultScopeName,
			ScopeToPolicy:  scopeToPolicyMap,
		}
		assert.Equal(t, expectedOICScope, spec.Scopes.OIDC)
	})

	t.Run("json schema validation middleware", func(t *testing.T) {
		apiDef := DummyAPI()
		var (
			bodySchema map[string]interface{}
			v1         = "v1"
			v1B64      = base64.StdEncoding.EncodeToString([]byte(v1))
		)
		err := json.Unmarshal([]byte(`{"$schema":"http://json-schema.org/draft-04/schema#","properties":{"id":{"type":"integer"}},"required":["id"],"type":"object"}`),
			&bodySchema)
		assert.NoError(t, err)
		apiDef.VersionData.Versions[v1] = VersionInfo{
			ExtendedPaths: ExtendedPathsSet{
				ValidateJSON: []ValidatePathMeta{
					{
						Path:   "/",
						Method: http.MethodPost,
						Schema: bodySchema,
					},
				},
			},
		}
		apiDef.EncodeForDB()
		copyAPIDef := apiDef
		copyAPIDef.DecodeFromDB()

		assert.Equal(t, apiDef.VersionData.Versions[v1B64].ExtendedPaths.ValidateJSON[0].Schema,
			copyAPIDef.VersionData.Versions[v1].ExtendedPaths.ValidateJSON[0].Schema)
		assert.Empty(t, copyAPIDef.VersionData.Versions[v1].ExtendedPaths.ValidateJSON[0].SchemaB64)
	})
}

func TestSchemaGraphqlConfig(t *testing.T) {
	schemaLoader := schema.NewBytesLoader([]byte(Schema))

	spec := DummyAPI()
	spec.GraphQL.ExecutionMode = ""

	goLoader := schema.NewGoLoader(spec)

	result, err := schema.Validate(schemaLoader, goLoader)
	if err != nil {
		t.Error(err)
	}

	if !result.Valid() {
		for _, err := range result.Errors() {
			t.Error(err)
		}
	}
}

func TestAPIDefinition_DecodeFromDB_AuthDeprecation(t *testing.T) {
	const authHeader = "authorization"

	spec := DummyAPI()
	spec.Auth = AuthConfig{AuthHeaderName: authHeader}
	spec.UseStandardAuth = true
	spec.DecodeFromDB()

	assert.Equal(t, spec.AuthConfigs, map[string]AuthConfig{
		"authToken": spec.Auth,
	})

	spec.EnableJWT = true
	spec.DecodeFromDB()

	assert.Equal(t, spec.AuthConfigs, map[string]AuthConfig{
		"authToken": spec.Auth,
		"jwt":       spec.Auth,
	})

}

func TestAPIDefinition_GenerateAPIID(t *testing.T) {
	a := APIDefinition{}
	a.GenerateAPIID()
	assert.NotEmpty(t, a.APIID)
}
