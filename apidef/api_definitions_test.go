package apidef

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/service/gojsonschema"
)

func TestAPIDefinition_JsonRpcVersion(t *testing.T) {
	t.Run("json-rpc version field marshaling", func(t *testing.T) {
		api := APIDefinition{
			JsonRpcVersion: "2.0",
		}

		data, err := json.Marshal(api)
		assert.NoError(t, err)

		var result APIDefinition
		err = json.Unmarshal(data, &result)
		assert.NoError(t, err)

		assert.Equal(t, "2.0", result.JsonRpcVersion)
	})

	t.Run("empty json-rpc version omitted", func(t *testing.T) {
		api := APIDefinition{
			JsonRpcVersion: "",
		}

		data, err := json.Marshal(api)
		assert.NoError(t, err)

		assert.NotContains(t, string(data), "json_rpc_version")
	})

	t.Run("json-rpc version persists through encode/decode", func(t *testing.T) {
		api := APIDefinition{
			JsonRpcVersion: "2.0",
		}

		api.EncodeForDB()
		api.DecodeFromDB()

		assert.Equal(t, "2.0", api.JsonRpcVersion)
	})
}

func TestAPIDefinition_ApplicationProtocol(t *testing.T) {
	t.Run("application protocol field marshaling", func(t *testing.T) {
		api := APIDefinition{
			ApplicationProtocol: AppProtocolMCP,
		}

		data, err := json.Marshal(api)
		assert.NoError(t, err)

		var result APIDefinition
		err = json.Unmarshal(data, &result)
		assert.NoError(t, err)

		assert.Equal(t, AppProtocolMCP, result.ApplicationProtocol)
	})

	t.Run("empty application protocol omitted", func(t *testing.T) {
		api := APIDefinition{
			ApplicationProtocol: "",
		}

		data, err := json.Marshal(api)
		assert.NoError(t, err)

		assert.NotContains(t, string(data), "application_protocol")
	})

	t.Run("application protocol persists through encode/decode", func(t *testing.T) {
		api := APIDefinition{
			ApplicationProtocol: AppProtocolMCP,
		}

		api.EncodeForDB()
		api.DecodeFromDB()

		assert.Equal(t, AppProtocolMCP, api.ApplicationProtocol)
	})

	t.Run("supports custom protocols", func(t *testing.T) {
		customProtocol := "a2a"
		api := APIDefinition{
			ApplicationProtocol: customProtocol,
		}

		data, err := json.Marshal(api)
		assert.NoError(t, err)

		var result APIDefinition
		err = json.Unmarshal(data, &result)
		assert.NoError(t, err)

		assert.Equal(t, customProtocol, result.ApplicationProtocol)
	})
}

func TestAPIDefinition_SetProtocol(t *testing.T) {
	t.Run("sets transport and application protocol", func(t *testing.T) {
		api := APIDefinition{}

		api.SetProtocol(JsonRPC20, AppProtocolMCP)

		assert.Equal(t, JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, AppProtocolMCP, api.ApplicationProtocol)
		assert.True(t, api.IsMCP())
	})

	t.Run("IsMCP method returns correct value based on application protocol", func(t *testing.T) {
		api := APIDefinition{}

		api.SetProtocol(JsonRPC20, AppProtocolMCP)
		assert.True(t, api.IsMCP())

		api.SetProtocol(JsonRPC20, "a2a")
		assert.False(t, api.IsMCP())

		api.SetProtocol(JsonRPC20, AppProtocolMCP)
		assert.True(t, api.IsMCP())
	})

	t.Run("overwrites existing values", func(t *testing.T) {
		api := APIDefinition{
			JsonRpcVersion:      "1.0",
			ApplicationProtocol: "old",
		}

		api.SetProtocol(JsonRPC20, AppProtocolMCP)

		assert.Equal(t, JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, AppProtocolMCP, api.ApplicationProtocol)
		assert.True(t, api.IsMCP())
	})

	t.Run("allows empty application protocol", func(t *testing.T) {
		api := APIDefinition{}

		api.SetProtocol(JsonRPC20, "")

		assert.Equal(t, JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, "", api.ApplicationProtocol)
		assert.False(t, api.IsMCP())
	})

	t.Run("allows empty transport protocol", func(t *testing.T) {
		api := APIDefinition{}

		api.SetProtocol("", "custom")

		assert.Equal(t, "", api.JsonRpcVersion)
		assert.Equal(t, "custom", api.ApplicationProtocol)
		assert.False(t, api.IsMCP())
	})
}

func TestAPIDefinition_MarkAsMCP(t *testing.T) {
	t.Run("marks API as MCP", func(t *testing.T) {
		api := APIDefinition{}

		api.MarkAsMCP()

		assert.Equal(t, JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, AppProtocolMCP, api.ApplicationProtocol)
		assert.True(t, api.IsMCP())
	})

	t.Run("overwrites existing values", func(t *testing.T) {
		api := APIDefinition{
			JsonRpcVersion:      "1.0",
			ApplicationProtocol: "old",
		}

		api.MarkAsMCP()

		assert.Equal(t, JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, AppProtocolMCP, api.ApplicationProtocol)
		assert.True(t, api.IsMCP())
	})

	t.Run("is idempotent", func(t *testing.T) {
		api := APIDefinition{}

		api.MarkAsMCP()
		api.MarkAsMCP()
		api.MarkAsMCP()

		assert.Equal(t, JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, AppProtocolMCP, api.ApplicationProtocol)
		assert.True(t, api.IsMCP())
	})

	t.Run("does not affect other fields", func(t *testing.T) {
		api := APIDefinition{
			Name:  "test-api",
			APIID: "123",
			Slug:  "test",
		}

		api.MarkAsMCP()

		assert.Equal(t, "test-api", api.Name)
		assert.Equal(t, "123", api.APIID)
		assert.Equal(t, "test", api.Slug)
		assert.Equal(t, JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, AppProtocolMCP, api.ApplicationProtocol)
		assert.True(t, api.IsMCP())
	})

	t.Run("uses SetProtocol internally", func(t *testing.T) {
		api := APIDefinition{}

		api.MarkAsMCP()

		// Verify it's equivalent to calling SetProtocol with MCP constants
		expected := APIDefinition{}
		expected.SetProtocol(JsonRPC20, AppProtocolMCP)

		assert.Equal(t, expected.JsonRpcVersion, api.JsonRpcVersion)
		assert.Equal(t, expected.ApplicationProtocol, api.ApplicationProtocol)
		assert.Equal(t, expected.IsMCP(), api.IsMCP())
	})
}

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

func TestAPIDefinition_IsChildAPI(t *testing.T) {
	tests := []struct {
		name     string
		api      APIDefinition
		expected bool
	}{
		{
			name: "child API - BaseID set and different from APIID",
			api: APIDefinition{
				APIID: "child-api-123",
				VersionDefinition: VersionDefinition{
					BaseID: "base-api-456",
				},
			},
			expected: true,
		},
		{
			name: "not a child - BaseID empty",
			api: APIDefinition{
				APIID: "standalone-api-123",
				VersionDefinition: VersionDefinition{
					BaseID: "",
				},
			},
			expected: false,
		},
		{
			name: "not a child - BaseID equals APIID (base API)",
			api: APIDefinition{
				APIID: "base-api-123",
				VersionDefinition: VersionDefinition{
					BaseID: "base-api-123",
				},
			},
			expected: false,
		},
		{
			name: "not a child - no version definition",
			api: APIDefinition{
				APIID:             "api-123",
				VersionDefinition: VersionDefinition{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.api.IsChildAPI()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAPIDefinition_IsBaseAPI(t *testing.T) {
	tests := []struct {
		name     string
		api      APIDefinition
		expected bool
	}{
		{
			name: "base API - has versions and no BaseID",
			api: APIDefinition{
				APIID: "base-api-123",
				VersionDefinition: VersionDefinition{
					BaseID: "",
					Versions: map[string]string{
						"v1": "child-api-1",
						"v2": "child-api-2",
					},
				},
			},
			expected: true,
		},
		{
			name: "base API - has versions and BaseID equals APIID",
			api: APIDefinition{
				APIID: "base-api-123",
				VersionDefinition: VersionDefinition{
					BaseID: "base-api-123",
					Versions: map[string]string{
						"v1": "child-api-1",
						"v2": "child-api-2",
					},
				},
			},
			expected: true,
		},
		{
			name: "not a base API - no versions",
			api: APIDefinition{
				APIID: "api-123",
				VersionDefinition: VersionDefinition{
					BaseID:   "",
					Versions: map[string]string{},
				},
			},
			expected: false,
		},
		{
			name: "not a base API - is a child (BaseID different from APIID)",
			api: APIDefinition{
				APIID: "child-api-123",
				VersionDefinition: VersionDefinition{
					BaseID: "base-api-456",
					Versions: map[string]string{
						"v1": "child-api-123",
					},
				},
			},
			expected: false,
		},
		{
			name: "not a base API - nil versions",
			api: APIDefinition{
				APIID: "api-123",
				VersionDefinition: VersionDefinition{
					BaseID:   "",
					Versions: nil,
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.api.IsBaseAPI()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAPIDefinition_IsBaseAPIWithVersioning(t *testing.T) {
	tests := []struct {
		name     string
		api      APIDefinition
		expected bool
	}{
		{
			name: "base API with versioning - all conditions met",
			api: APIDefinition{
				APIID: "base-api-123",
				VersionDefinition: VersionDefinition{
					Enabled: true,
					Name:    "v1",
					BaseID:  "",
				},
			},
			expected: true,
		},
		{
			name: "base API with versioning - BaseID equals APIID",
			api: APIDefinition{
				APIID: "base-api-123",
				VersionDefinition: VersionDefinition{
					Enabled: true,
					Name:    "v1",
					BaseID:  "base-api-123",
				},
			},
			expected: true,
		},
		{
			name: "not versioned - Enabled is false",
			api: APIDefinition{
				APIID: "api-123",
				VersionDefinition: VersionDefinition{
					Enabled: false,
					Name:    "v1",
					BaseID:  "",
				},
			},
			expected: false,
		},
		{
			name: "not versioned - Name is empty",
			api: APIDefinition{
				APIID: "api-123",
				VersionDefinition: VersionDefinition{
					Enabled: true,
					Name:    "",
					BaseID:  "",
				},
			},
			expected: false,
		},
		{
			name: "is a child API - BaseID different from APIID",
			api: APIDefinition{
				APIID: "child-api-123",
				VersionDefinition: VersionDefinition{
					Enabled: true,
					Name:    "v2",
					BaseID:  "base-api-456",
				},
			},
			expected: false,
		},
		{
			name: "not versioned - all fields false/empty",
			api: APIDefinition{
				APIID: "api-123",
				VersionDefinition: VersionDefinition{
					Enabled: false,
					Name:    "",
					BaseID:  "",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.api.IsBaseAPIWithVersioning()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVersionDefinition_ResolvedDefault(t *testing.T) {
	tests := []struct {
		name     string
		vd       VersionDefinition
		expected string
	}{
		{
			name: "resolves 'self' to actual version name",
			vd: VersionDefinition{
				Name:    "v1",
				Default: Self,
			},
			expected: "v1",
		},
		{
			name: "keeps specific version unchanged",
			vd: VersionDefinition{
				Name:    "v1",
				Default: "v2",
			},
			expected: "v2",
		},
		{
			name: "handles empty default",
			vd: VersionDefinition{
				Name:    "v1",
				Default: "",
			},
			expected: "",
		},
		{
			name: "handles empty name with self",
			vd: VersionDefinition{
				Name:    "",
				Default: Self,
			},
			expected: "",
		},
		{
			name: "handles both empty",
			vd: VersionDefinition{
				Name:    "",
				Default: "",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.vd.ResolvedDefault()
			assert.Equal(t, tt.expected, result)
		})
	}
}
