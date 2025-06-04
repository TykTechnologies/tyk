package apidef

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/service/gojsonschema"
)

func TestSchema(t *testing.T) {
	schemaLoader := gojsonschema.NewBytesLoader([]byte(Schema))

	spec := DummyAPI()
	goLoader := gojsonschema.NewGoLoader(spec)
	result, err := gojsonschema.Validate(schemaLoader, goLoader)
	if err != nil {
		t.Error(err)
	}

	if !result.Valid() {
		for _, err := range result.Errors() {
			t.Error(err)
		}
	}
}

func TestStringRegexMap(t *testing.T) {
	var v StringRegexMap
	assert.True(t, v.Empty())

	v = StringRegexMap{MatchPattern: ".*"}
	assert.False(t, v.Empty())

	v = StringRegexMap{Reverse: true}
	assert.False(t, v.Empty())
}

func TestRoutingTriggerOptions(t *testing.T) {
	opts := NewRoutingTriggerOptions()

	assert.NotNil(t, opts.HeaderMatches)
	assert.NotNil(t, opts.QueryValMatches)
	assert.NotNil(t, opts.PathPartMatches)
	assert.NotNil(t, opts.SessionMetaMatches)
	assert.NotNil(t, opts.RequestContextMatches)
	assert.Empty(t, opts.PayloadMatches)
}

func TestEncodeForDB(t *testing.T) {
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
	schemaLoader := gojsonschema.NewBytesLoader([]byte(Schema))

	spec := DummyAPI()
	spec.GraphQL.ExecutionMode = ""

	goLoader := gojsonschema.NewGoLoader(spec)

	result, err := gojsonschema.Validate(schemaLoader, goLoader)
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

func TestAPIDefinition_GetScopeClaimName(t *testing.T) {
	var (
		scopeName        = "scope"
		oidcScopeName    = "oidc_scope"
		newScopeName     = "new_scope"
		newOIDCScopeName = "new_oidc_scope"
	)

	getAPIDef := func(deprecatedScopeName, jwtScopeName, oidcScopeName string, useOIDC bool) APIDefinition {
		return APIDefinition{
			UseOpenID:         useOIDC,
			JWTScopeClaimName: deprecatedScopeName,
			Scopes: Scopes{
				JWT: ScopeClaim{
					ScopeClaimName: jwtScopeName,
				},
				OIDC: ScopeClaim{
					ScopeClaimName: oidcScopeName,
				},
			},
		}
	}

	testCases := []struct {
		name                string
		deprecatedScopeName string
		jwtScopeName        string
		oidcScopeName       string
		useOIDC             bool
		expectedScopeName   string
	}{
		{
			name:                "jwt: only deprecated fields",
			deprecatedScopeName: scopeName,
			expectedScopeName:   scopeName,
		},
		{
			name:              "jwt: only scopes.jwt",
			jwtScopeName:      newScopeName,
			expectedScopeName: newScopeName,
		},
		{
			name:              "jwt: both scopes.jwt and scopes.oidc",
			jwtScopeName:      newScopeName,
			oidcScopeName:     newOIDCScopeName,
			expectedScopeName: newScopeName,
		},
		{
			name:                "jwt: deprecated field and jwt.scopes",
			deprecatedScopeName: scopeName,
			jwtScopeName:        newScopeName,
			expectedScopeName:   newScopeName,
		},

		{
			name:                "oidc: only deprecated fields",
			deprecatedScopeName: oidcScopeName,
			expectedScopeName:   oidcScopeName,
			useOIDC:             true,
		},
		{
			name:              "oidc: only scopes.oidc",
			oidcScopeName:     newOIDCScopeName,
			expectedScopeName: newOIDCScopeName,
			useOIDC:           true,
		},
		{
			name:              "oidc: both scopes.jwt and scopes.oidc",
			jwtScopeName:      newScopeName,
			oidcScopeName:     newOIDCScopeName,
			expectedScopeName: newOIDCScopeName,
			useOIDC:           true,
		},
		{
			name:                "oidc: deprecated field and oidc.scopes",
			deprecatedScopeName: oidcScopeName,
			oidcScopeName:       newOIDCScopeName,
			expectedScopeName:   newOIDCScopeName,
			useOIDC:             true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiDef := getAPIDef(tc.deprecatedScopeName, tc.jwtScopeName, tc.oidcScopeName, tc.useOIDC)
			assert.Equal(t, tc.expectedScopeName, apiDef.GetScopeClaimName())
		})
	}
}

func TestAPIDefinition_GetScopeToPolicyMapping(t *testing.T) {
	var (
		scopeToPolicyMapping        = map[string]string{"jwtClaim": "pol1"}
		newScopeToPolicyMapping     = map[string]string{"jwtClaim1": "pol1"}
		oidcScopeToPolicyMapping    = map[string]string{"oidcClaim": "pol1"}
		newOIDCScopeToPolicyMapping = map[string]string{"oidcClaim1": "pol1"}
	)

	getAPIDef := func(deprecatedScopeToPolicy, jwtScopeToPolicy, oidcScopeToPolicy map[string]string, useOIDC bool) APIDefinition {
		return APIDefinition{
			UseOpenID:               useOIDC,
			JWTScopeToPolicyMapping: deprecatedScopeToPolicy,
			Scopes: Scopes{
				JWT: ScopeClaim{
					ScopeToPolicy: jwtScopeToPolicy,
				},
				OIDC: ScopeClaim{
					ScopeToPolicy: oidcScopeToPolicy,
				},
			},
		}
	}

	testCases := []struct {
		name                    string
		deprecatedScopeToPolicy map[string]string
		jwtScopeToPolicy        map[string]string
		oidcScopeToPolicy       map[string]string
		useOIDC                 bool
		expectedScopeToPolicy   map[string]string
	}{
		{
			name:                    "jwt: only deprecated fields",
			deprecatedScopeToPolicy: scopeToPolicyMapping,
			expectedScopeToPolicy:   scopeToPolicyMapping,
		},
		{
			name:                  "jwt: only scopes.jwt",
			jwtScopeToPolicy:      scopeToPolicyMapping,
			expectedScopeToPolicy: scopeToPolicyMapping,
		},
		{
			name:                  "jwt: both scopes.jwt and scopes.oidc",
			jwtScopeToPolicy:      scopeToPolicyMapping,
			oidcScopeToPolicy:     oidcScopeToPolicyMapping,
			expectedScopeToPolicy: scopeToPolicyMapping,
		},
		{
			name:                    "jwt: deprecated field and jwt.scopes",
			deprecatedScopeToPolicy: scopeToPolicyMapping,
			jwtScopeToPolicy:        newScopeToPolicyMapping,
			expectedScopeToPolicy:   newScopeToPolicyMapping,
		},

		{
			name:                    "oidc: only deprecated fields",
			deprecatedScopeToPolicy: oidcScopeToPolicyMapping,
			expectedScopeToPolicy:   oidcScopeToPolicyMapping,
			useOIDC:                 true,
		},
		{
			name:                  "oidc: only scopes.oidc",
			oidcScopeToPolicy:     newOIDCScopeToPolicyMapping,
			expectedScopeToPolicy: newOIDCScopeToPolicyMapping,
			useOIDC:               true,
		},
		{
			name:                  "oidc: both scopes.jwt and scopes.oidc",
			jwtScopeToPolicy:      scopeToPolicyMapping,
			oidcScopeToPolicy:     oidcScopeToPolicyMapping,
			expectedScopeToPolicy: oidcScopeToPolicyMapping,
			useOIDC:               true,
		},
		{
			name:                    "oidc: deprecated field and oidc.scopes",
			deprecatedScopeToPolicy: oidcScopeToPolicyMapping,
			oidcScopeToPolicy:       newOIDCScopeToPolicyMapping,
			expectedScopeToPolicy:   newOIDCScopeToPolicyMapping,
			useOIDC:                 true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apiDef := getAPIDef(tc.deprecatedScopeToPolicy, tc.jwtScopeToPolicy, tc.oidcScopeToPolicy, tc.useOIDC)
			assert.Equal(t, tc.expectedScopeToPolicy, apiDef.GetScopeToPolicyMapping())
		})
	}

}

func TestJSVMEventHandlerConf_Scan(t *testing.T) {
	jsvmEventMeta := map[string]any{
		"disabled": true,
		"id":       "1234",
		"name":     "myMethod",
		"path":     "my_script.js",
	}

	expected := JSVMEventHandlerConf{
		Disabled:   true,
		ID:         "1234",
		MethodName: "myMethod",
		Path:       "my_script.js",
	}

	var jsvmEventConf JSVMEventHandlerConf
	err := jsvmEventConf.Scan(jsvmEventMeta)

	assert.NoError(t, err)
	assert.Equal(t, expected, jsvmEventConf)
}

func TestLogEventHandlerConf_Scan(t *testing.T) {
	logEventMeta := map[string]any{
		"disabled": true,
		"prefix":   "AuthFailureEvent",
	}

	expected := LogEventHandlerConf{
		Disabled: true,
		Prefix:   "AuthFailureEvent",
	}

	var logEventConf LogEventHandlerConf
	err := logEventConf.Scan(logEventMeta)

	assert.NoError(t, err)
	assert.Equal(t, expected, logEventConf)
}
