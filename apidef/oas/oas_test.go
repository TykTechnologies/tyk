package oas

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/oasdiff/yaml"

	"github.com/TykTechnologies/storage/persistent/model"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/event"
)

func TestOAS(t *testing.T) {
	t.Parallel()

	t.Run("empty paths", func(t *testing.T) {
		t.Parallel()

		var emptyOASPaths OAS
		emptyOASPaths.Components = &openapi3.Components{}
		emptyOASPaths.Paths = openapi3.NewPaths()
		emptyOASPaths.SetTykExtension(&XTykAPIGateway{})

		var convertedAPI apidef.APIDefinition
		emptyOASPaths.ExtractTo(&convertedAPI)

		var resultOAS OAS
		resultOAS.Fill(convertedAPI)

		// This tests that zero-value extensions are cleared
		emptyOASPaths.Extensions = nil
		assert.Equal(t, emptyOASPaths, resultOAS)
	})

	t.Run("nil paths", func(t *testing.T) {
		t.Parallel()

		var nilOASPaths OAS
		nilOASPaths.Components = &openapi3.Components{}
		nilOASPaths.SetTykExtension(&XTykAPIGateway{})

		var convertedAPI apidef.APIDefinition
		nilOASPaths.ExtractTo(&convertedAPI)

		var resultOAS OAS
		resultOAS.Fill(convertedAPI)

		// No paths in base OAS produce empty paths{} when converted back
		nilOASPaths.Paths = openapi3.NewPaths()
		nilOASPaths.Extensions = nil
		assert.Equal(t, nilOASPaths, resultOAS)
	})

	t.Run("extract paths", func(t *testing.T) {
		const operationID = "userGET"
		t.Parallel()

		var oasWithPaths OAS
		oasWithPaths.Components = &openapi3.Components{}
		oasWithPaths.SetTykExtension(&XTykAPIGateway{
			Middleware: &Middleware{
				Operations: Operations{
					operationID: {
						Allow: &Allowance{
							Enabled: true,
						},
					},
				},
			},
		})
		oasWithPaths.Paths = func() *openapi3.Paths {
			paths := openapi3.NewPaths()
			paths.Set("/user", &openapi3.PathItem{
				Get: &openapi3.Operation{
					OperationID: operationID,
					Responses: func() *openapi3.Responses {
						responses := openapi3.NewResponses()
						responses.Set("200", &openapi3.ResponseRef{
							Value: &openapi3.Response{
								Description: getStrPointer("some example endpoint"),
							},
						})
						return responses
					}(),
				},
			})
			return paths
		}()

		var convertedAPI apidef.APIDefinition
		oasWithPaths.ExtractTo(&convertedAPI)

		var resultOAS OAS
		resultOAS.Fill(convertedAPI)

		assert.Equal(t, oasWithPaths, resultOAS)
	})

	t.Run("auth configs", func(t *testing.T) {
		t.Parallel()

		var api apidef.APIDefinition
		api.AuthConfigs = make(map[string]apidef.AuthConfig)

		a := apidef.AuthConfig{}
		Fill(t, &a, 0)
		api.AuthConfigs[apidef.AuthTokenType] = a

		sw := &OAS{}
		sw.Fill(api)

		var converted apidef.APIDefinition
		sw.ExtractTo(&converted)

		assert.Equal(t, api.AuthConfigs, converted.AuthConfigs)
	})
}

func TestOAS_ExtractTo_DontTouchExistingClassicFields(t *testing.T) {
	var api apidef.APIDefinition
	api.VersionData.Versions = map[string]apidef.VersionInfo{
		Main: {
			ExtendedPaths: apidef.ExtendedPathsSet{
				PersistGraphQL: []apidef.PersistGraphQLMeta{
					{},
				},
			},
		},
	}

	var s OAS
	s.ExtractTo(&api)

	assert.Len(t, api.VersionData.Versions[Main].ExtendedPaths.PersistGraphQL, 1)
}

func TestOAS_ExtractTo_ResetAPIDefinition(t *testing.T) {
	var a apidef.APIDefinition
	Fill(t, &a, 0)

	// Fill doesn't populate eventhandlers to a valid value, we do it now.
	a.EventHandlers.Events = map[apidef.TykEvent][]apidef.EventHandlerTriggerConfig{
		event.QuotaExceeded: {
			{
				Handler: event.WebHookHandler,
				HandlerMeta: map[string]any{
					"target_path": "https://webhook.site/uuid",
				},
			},
			{
				Handler: event.JSVMHandler,
				HandlerMeta: map[string]any{
					"name": "myHandler",
					"path": "my_script.js",
				},
			},
			{
				Handler: event.LogHandler,
				HandlerMeta: map[string]any{
					"prefix": "QuotaExceededEvent",
				},
			},
		},
	}

	var vInfo apidef.VersionInfo
	Fill(t, &vInfo, 0)
	a.VersionData.Versions = map[string]apidef.VersionInfo{
		Main: vInfo,
	}

	var s OAS
	s.ExtractTo(&a)

	a.UseKeylessAccess = false
	a.UpstreamCertificatesDisabled = false
	a.CertificatePinningDisabled = false
	a.Proxy.ServiceDiscovery.CacheDisabled = false
	a.CustomMiddlewareBundleDisabled = false
	a.DomainDisabled = false
	a.ConfigDataDisabled = false
	a.CustomMiddleware.AuthCheck.Disabled = false
	a.CustomMiddleware.IdExtractor.Disabled = false
	a.GlobalRateLimit.Disabled = false
	a.TagsDisabled = false
	a.IsOAS = false
	a.IDPClientIDMappingDisabled = false
	a.EnableContextVars = false
	a.DoNotTrack = false
	a.IPAccessControlDisabled = false
	a.UptimeTests.Disabled = false

	// deprecated fields
	a.Auth = apidef.AuthConfig{}
	a.VersionDefinition.StripPath = false
	a.UseGoPluginAuth = false
	a.EnableCoProcessAuth = false
	a.JWTScopeToPolicyMapping = nil
	a.JWTScopeClaimName = ""
	a.VersionData.NotVersioned = false
	vInfo = a.VersionData.Versions[""]
	vInfo.Name = ""
	vInfo.Expires = ""
	vInfo.Paths.Ignored = nil
	vInfo.Paths.WhiteList = nil
	vInfo.Paths.BlackList = nil
	vInfo.OverrideTarget = ""
	vInfo.GlobalHeadersDisabled = false
	vInfo.GlobalResponseHeadersDisabled = false
	vInfo.UseExtendedPaths = false
	vInfo.GlobalSizeLimitDisabled = false

	vInfo.ExtendedPaths.Clear()

	a.VersionData.Versions[""] = vInfo

	a.UptimeTests.Config.ServiceDiscovery.CacheDisabled = false

	assert.Empty(t, a.Name)

	noOASSupportFields := getNonEmptyFields(a, "APIDefinition")

	// The expectedFields value lists fields that do not support migration.
	// When adding a migration for ExtendedPaths sections, clear the list of
	// fields below, and clear the value in ExtendedPaths.Clear() function.

	expectedFields := []string{
		"APIDefinition.Slug",
		"APIDefinition.EnableProxyProtocol",
		"APIDefinition.VersionData.Versions[0].ExtendedPaths.TransformJQ[0].Filter",
		"APIDefinition.VersionData.Versions[0].ExtendedPaths.TransformJQ[0].Path",
		"APIDefinition.VersionData.Versions[0].ExtendedPaths.TransformJQ[0].Method",
		"APIDefinition.VersionData.Versions[0].ExtendedPaths.TransformJQResponse[0].Filter",
		"APIDefinition.VersionData.Versions[0].ExtendedPaths.TransformJQResponse[0].Path",
		"APIDefinition.VersionData.Versions[0].ExtendedPaths.TransformJQResponse[0].Method",
		"APIDefinition.VersionData.Versions[0].ExtendedPaths.PersistGraphQL[0].Path",
		"APIDefinition.VersionData.Versions[0].ExtendedPaths.PersistGraphQL[0].Method",
		"APIDefinition.VersionData.Versions[0].ExtendedPaths.PersistGraphQL[0].Operation",
		"APIDefinition.VersionData.Versions[0].ExtendedPaths.PersistGraphQL[0].Variables[0]",
		"APIDefinition.AuthProvider.Name",
		"APIDefinition.AuthProvider.StorageEngine",
		"APIDefinition.AuthProvider.Meta[0]",
		"APIDefinition.SessionProvider.Name",
		"APIDefinition.SessionProvider.StorageEngine",
		"APIDefinition.SessionProvider.Meta[0]",
		"APIDefinition.EnableIpWhiteListing",
		"APIDefinition.EnableIpBlacklisting",
		"APIDefinition.ResponseProcessors[0].Name",
		"APIDefinition.ResponseProcessors[0].Options",
		"APIDefinition.GraphQL.Enabled",
		"APIDefinition.GraphQL.ExecutionMode",
		"APIDefinition.GraphQL.Version",
		"APIDefinition.GraphQL.Schema",
		"APIDefinition.GraphQL.TypeFieldConfigurations[0].TypeName",
		"APIDefinition.GraphQL.TypeFieldConfigurations[0].FieldName",
		"APIDefinition.GraphQL.TypeFieldConfigurations[0].Mapping.Disabled",
		"APIDefinition.GraphQL.TypeFieldConfigurations[0].Mapping.Path",
		"APIDefinition.GraphQL.TypeFieldConfigurations[0].DataSource.Name",
		"APIDefinition.GraphQL.TypeFieldConfigurations[0].DataSource.Config[0]",
		"APIDefinition.GraphQL.GraphQLPlayground.Enabled",
		"APIDefinition.GraphQL.GraphQLPlayground.Path",
		"APIDefinition.GraphQL.Engine.FieldConfigs[0].TypeName",
		"APIDefinition.GraphQL.Engine.FieldConfigs[0].FieldName",
		"APIDefinition.GraphQL.Engine.FieldConfigs[0].DisableDefaultMapping",
		"APIDefinition.GraphQL.Engine.FieldConfigs[0].Path[0]",
		"APIDefinition.GraphQL.Engine.DataSources[0].Kind",
		"APIDefinition.GraphQL.Engine.DataSources[0].Name",
		"APIDefinition.GraphQL.Engine.DataSources[0].Internal",
		"APIDefinition.GraphQL.Engine.DataSources[0].RootFields[0].Type",
		"APIDefinition.GraphQL.Engine.DataSources[0].RootFields[0].Fields[0]",
		"APIDefinition.GraphQL.Engine.DataSources[0].Config[0]",
		"APIDefinition.GraphQL.Engine.GlobalHeaders[0].Key",
		"APIDefinition.GraphQL.Engine.GlobalHeaders[0].Value",
		"APIDefinition.GraphQL.Proxy.Features.UseImmutableHeaders",
		"APIDefinition.GraphQL.Proxy.AuthHeaders[0]",
		"APIDefinition.GraphQL.Proxy.SubscriptionType",
		"APIDefinition.GraphQL.Proxy.RequestHeaders[0]",
		"APIDefinition.GraphQL.Proxy.UseResponseExtensions.OnErrorForwarding",
		"APIDefinition.GraphQL.Proxy.RequestHeadersRewrite[0].Value",
		"APIDefinition.GraphQL.Proxy.RequestHeadersRewrite[0].Remove",
		"APIDefinition.GraphQL.Subgraph.SDL",
		"APIDefinition.GraphQL.Supergraph.Subgraphs[0].APIID",
		"APIDefinition.GraphQL.Supergraph.Subgraphs[0].Name",
		"APIDefinition.GraphQL.Supergraph.Subgraphs[0].URL",
		"APIDefinition.GraphQL.Supergraph.Subgraphs[0].SDL",
		"APIDefinition.GraphQL.Supergraph.Subgraphs[0].Headers[0]",
		"APIDefinition.GraphQL.Supergraph.Subgraphs[0].SubscriptionType",
		"APIDefinition.GraphQL.Supergraph.MergedSDL",
		"APIDefinition.GraphQL.Supergraph.GlobalHeaders[0]",
		"APIDefinition.GraphQL.Supergraph.DisableQueryBatching",
		"APIDefinition.GraphQL.Introspection.Disabled",
		"APIDefinition.AnalyticsPlugin.Enabled",
		"APIDefinition.AnalyticsPlugin.PluginPath",
		"APIDefinition.AnalyticsPlugin.FuncName",
	}

	assert.Equal(t, expectedFields, noOASSupportFields)
}

func TestOAS_AddServers(t *testing.T) {
	t.Parallel()
	type fields struct {
		T openapi3.T
	}
	type args struct {
		apiURLs []string
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		expectedURLs []string
	}{
		{
			name:         "empty servers",
			fields:       fields{T: openapi3.T{}},
			args:         args{apiURLs: []string{"http://127.0.0.1:8080/api"}},
			expectedURLs: []string{"http://127.0.0.1:8080/api"},
		},
		{
			name:         "empty servers and named parameters",
			fields:       fields{T: openapi3.T{}},
			args:         args{apiURLs: []string{"http://{subdomain}/api"}},
			expectedURLs: nil,
		},
		{
			name: "non-empty servers",
			fields: fields{T: openapi3.T{
				Servers: openapi3.Servers{
					{
						URL: "http://example-upstream.org/api",
					},
				},
			}},
			args:         args{apiURLs: []string{"http://127.0.0.1:8080/api"}},
			expectedURLs: []string{"http://127.0.0.1:8080/api", "http://example-upstream.org/api"},
		},
		{
			name: "non-empty servers and mix on named parameters and normal urls",
			fields: fields{T: openapi3.T{
				Servers: openapi3.Servers{
					{
						URL: "http://example-upstream.org/api",
					},
				},
			}},
			args:         args{apiURLs: []string{"http://127.0.0.1:8080/api", "http://{subdomain}/api"}},
			expectedURLs: []string{"http://127.0.0.1:8080/api", "http://example-upstream.org/api"},
		},
		{
			name: "non-empty servers having same URL that of apiURL",
			fields: fields{T: openapi3.T{
				Servers: openapi3.Servers{
					{
						URL: "http://example-upstream.org/api",
					},
					{
						URL: "http://legacy-upstream.org/api",
					},
					{
						URL: "http://127.0.0.1:8080/api",
					},
				},
			}},
			args: args{apiURLs: []string{"http://127.0.0.1:8080/api"}},
			expectedURLs: []string{
				"http://127.0.0.1:8080/api",
				"http://example-upstream.org/api",
				"http://legacy-upstream.org/api",
			},
		},
		{
			name: "non-empty servers having same URL that of apiURL",
			fields: fields{T: openapi3.T{
				Servers: openapi3.Servers{
					{
						URL: "http://127.0.0.1:8080/api",
					},
					{
						URL: "http://example-upstream.org/api",
					},
				},
			}},
			args: args{apiURLs: []string{"http://127.0.0.1:8080/api"}},
			expectedURLs: []string{
				"http://127.0.0.1:8080/api",
				"http://example-upstream.org/api",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &OAS{
				T: tt.fields.T,
			}
			s.AddServers(tt.args.apiURLs...)
			if tt.expectedURLs == nil {
				assert.Empty(t, s.Servers)
				return
			}
			var serverURLs []string
			for _, server := range s.Servers {
				serverURLs = append(serverURLs, server.URL)
			}

			assert.ElementsMatch(t, tt.expectedURLs, serverURLs)
		})
	}
}

func TestOAS_UpdateServers(t *testing.T) {
	t.Parallel()
	type fields struct {
		S openapi3.Servers
	}
	type args struct {
		apiURL    string
		oldAPIURL string
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		expectedServers openapi3.Servers
	}{
		{
			name:   "empty servers",
			fields: fields{S: openapi3.Servers{}},
			args:   args{apiURL: "http://127.0.0.1:8080/api", oldAPIURL: ""},
			expectedServers: openapi3.Servers{
				{
					URL: "http://127.0.0.1:8080/api",
				},
			},
		},
		{
			name: "non-empty servers replace with new",
			fields: fields{
				S: openapi3.Servers{
					{
						URL: "http://example-upstream.org/api",
					},
				},
			},
			args: args{apiURL: "http://127.0.0.1:8080/api", oldAPIURL: "http://example-upstream.org/api"},
			expectedServers: openapi3.Servers{
				{
					URL: "http://127.0.0.1:8080/api",
				},
			},
		},
		{
			name: "non-empty servers not replace",
			fields: fields{
				S: openapi3.Servers{
					{
						URL: "http://example-upstream.org/api",
					},
				},
			},
			args: args{apiURL: "http://127.0.0.1:8080/api", oldAPIURL: "http://localhost/api"},
			expectedServers: openapi3.Servers{
				{
					URL: "http://example-upstream.org/api",
				},
			},
		},
		{
			name: "apiURL with named parameter, do not add to existing servers(not added by Tyk)",
			fields: fields{
				S: openapi3.Servers{
					{
						URL: "http://example-upstream.org/api",
					},
				},
			},
			args: args{apiURL: "http://{subdomain:[a-z]+}/api", oldAPIURL: "http://localhost/api"},
			expectedServers: openapi3.Servers{
				{
					URL: "http://example-upstream.org/api",
				},
			},
		},
		{
			name: "apiURL with named parameter, remove servers entry added by Tyk",
			fields: fields{
				S: openapi3.Servers{
					{
						URL: "http://example-upstream.org/api",
					},
					{
						URL: "http://other-upstream.org/api",
					},
				},
			},
			args: args{apiURL: "http://{subdomain:[a-z]+}/api", oldAPIURL: "http://example-upstream.org/api"},
			expectedServers: openapi3.Servers{
				{
					URL: "http://other-upstream.org/api",
				},
			},
		},
		{
			name: "apiURL with named parameter, remove only servers entry added by Tyk",
			fields: fields{
				S: openapi3.Servers{
					{
						URL: "http://example-upstream.org/api",
					},
				},
			},
			args:            args{apiURL: "http://{subdomain:[a-z]+}/api", oldAPIURL: "http://example-upstream.org/api"},
			expectedServers: openapi3.Servers{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &OAS{
				T: openapi3.T{Servers: tt.fields.S},
			}
			s.UpdateServers(tt.args.apiURL, tt.args.oldAPIURL)

			assert.Equal(t, tt.expectedServers, s.Servers)
		})
	}
}

func TestOAS_ReplaceServers(t *testing.T) {
	t.Parallel()
	type fields struct {
		T openapi3.T
	}

	type args struct {
		apiURLs    []string
		oldAPIURLs []string
	}

	tests := []struct {
		name               string
		fields             fields
		args               args
		expectedServerURls []string
	}{
		{
			name:               "empty servers",
			fields:             fields{T: openapi3.T{}},
			args:               args{apiURLs: []string{"http://127.0.0.1:8080/api"}, oldAPIURLs: nil},
			expectedServerURls: []string{"http://127.0.0.1:8080/api"},
		},
		{
			name: "non-empty servers - remove old and add new",
			fields: fields{T: openapi3.T{
				Servers: openapi3.Servers{
					{
						URL: "http://tyk.gateway-1.com/api",
					},
					{
						URL: "http://tyk.gateway-2.com/api",
					},
				},
			}},
			args: args{apiURLs: []string{"http://tyk.gateway-4.com/api", "http://tyk.gateway-2.com/api"},
				oldAPIURLs: []string{"http://tyk.gateway-1.com/api", "http://tyk.gateway-2.com/api"}},
			expectedServerURls: []string{"http://tyk.gateway-4.com/api", "http://tyk.gateway-2.com/api"},
		},
		{
			name: "non-empty servers - remove old and add new, retain userAdded ones",
			fields: fields{T: openapi3.T{
				Servers: openapi3.Servers{
					{
						URL: "http://tyk.gateway-1.com/api",
					},
					{
						URL: "http://tyk.gateway-2.com/api",
					},
					{
						URL: "http://upstream.org/api",
					},
				},
			}},
			args: args{apiURLs: []string{"http://tyk.gateway-4.com/api", "http://tyk.gateway-2.com/api"},
				oldAPIURLs: []string{"http://tyk.gateway-1.com/api", "http://tyk.gateway-2.com/api"}},
			expectedServerURls: []string{"http://tyk.gateway-4.com/api", "http://tyk.gateway-2.com/api", "http://upstream.org/api"},
		},
		{
			name: "retain user added servers",
			fields: fields{T: openapi3.T{
				Servers: openapi3.Servers{
					{
						URL: "http://upstream.org/api",
					},
				},
			}},
			args: args{apiURLs: []string{"http://tyk.gateway-4.com/api", "http://tyk.gateway-2.com/api"},
				oldAPIURLs: []string{"http://tyk.gateway-1.com/api", "http://tyk.gateway-2.com/api"}},
			expectedServerURls: []string{"http://tyk.gateway-4.com/api", "http://tyk.gateway-2.com/api", "http://upstream.org/api"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &OAS{
				T: tt.fields.T,
			}
			s.ReplaceServers(tt.args.apiURLs, tt.args.oldAPIURLs)
			var serverURLs []string
			for _, server := range s.Servers {
				serverURLs = append(serverURLs, server.URL)
			}
			assert.Equal(t, tt.expectedServerURls, serverURLs)
		})
	}
}

func TestOAS_GetSecuritySchemes(t *testing.T) {
	token := Token{}
	Fill(t, &token, 0)

	jwt := JWT{}
	Fill(t, &jwt, 0)

	oauth := OAuth{}
	Fill(t, &oauth, 0)

	basic := Basic{}
	Fill(t, &basic, 0)

	expectedSS := SecuritySchemes{
		"my_auth":  &token,
		"my_jwt":   &jwt,
		"my_oauth": &oauth,
		"my_basic": &basic,
	}

	oas := OAS{}
	xTykAPIGateway := XTykAPIGateway{
		Server: Server{
			Authentication: &Authentication{
				SecuritySchemes: expectedSS,
			},
		},
	}

	oas.SetTykExtension(&xTykAPIGateway)

	oasInBytes, err := json.Marshal(&oas)
	assert.NoError(t, err)

	var resOAS OAS
	err = json.Unmarshal(oasInBytes, &resOAS)
	assert.NoError(t, err)

	assert.Equal(t, &token, resOAS.getTykTokenAuth("my_auth"))
	assert.Equal(t, &jwt, resOAS.getTykJWTAuth("my_jwt"))
	assert.Equal(t, &basic, resOAS.getTykBasicAuth("my_basic"))
	assert.Equal(t, &oauth, resOAS.getTykOAuthAuth("my_oauth"))
}

func Test_toStructIfMap(t *testing.T) {
	token := &Token{}
	Fill(t, token, 0)

	resToken := &Token{}
	toStructIfMap(token, resToken)
	assert.Equal(t, &Token{}, resToken)

	tokenInBytes, _ := json.Marshal(token)

	var mapToken map[string]interface{}
	_ = json.Unmarshal(tokenInBytes, &mapToken)

	toStructIfMap(mapToken, resToken)

	assert.Equal(t, token, resToken)
}

func TestOAS_MarshalJSON(t *testing.T) {
	t.Run("nil license and extenalDocs", func(t *testing.T) {
		s := &OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					License: &openapi3.License{},
				},
				ExternalDocs: &openapi3.ExternalDocs{},
			},
		}

		inBytes, err := json.Marshal(s)
		assert.NoError(t, err)

		assert.NotContains(t, string(inBytes), "license")
		assert.NotContains(t, string(inBytes), "externalDocs")
	})

	t.Run("should not base64 encode extension values when it's slice of bytes", func(t *testing.T) {
		s := OAS{
			openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS Doc",
				},
				Extensions: map[string]interface{}{
					ExtensionTykAPIGateway: XTykAPIGateway{
						Info: Info{
							Name: "OAS API",
						},
					},
				},
			},
		}

		t.Run("int", func(t *testing.T) {
			copyOAS := s
			intVal := 9
			byteRep, _ := json.Marshal(intVal)
			copyOAS.Extensions["x-abcd"] = byteRep

			data, err := copyOAS.MarshalJSON()
			assert.NoError(t, err)
			assert.Contains(t, string(data), `"x-abcd":9`)
		})

		t.Run("float", func(t *testing.T) {
			copyOAS := s
			floatVal := 9.5
			byteRep, _ := json.Marshal(floatVal)
			copyOAS.Extensions["x-abcd"] = byteRep

			data, err := copyOAS.MarshalJSON()
			assert.NoError(t, err)
			assert.Contains(t, string(data), `"x-abcd":9.5`)
		})

		t.Run("bool", func(t *testing.T) {
			copyOAS := s
			boolVal := false
			byteRep, _ := json.Marshal(boolVal)
			copyOAS.Extensions["x-abcd"] = byteRep

			data, err := copyOAS.MarshalJSON()
			assert.NoError(t, err)
			assert.Contains(t, string(data), `"x-abcd":false`)
		})

		t.Run("nil", func(t *testing.T) {
			copyOAS := s
			copyOAS.Extensions["x-abcd"] = nil

			data, err := copyOAS.MarshalJSON()
			assert.NoError(t, err)
			assert.Contains(t, string(data), `"x-abcd":null`)
		})

		t.Run("string", func(t *testing.T) {
			copyOAS := s
			copyOAS.Extensions["x-abcd"] = []byte(`"hello"`)

			data, err := copyOAS.MarshalJSON()
			assert.NoError(t, err)
			assert.Contains(t, string(data), `"x-abcd":"hello"`)
		})

		t.Run("map", func(t *testing.T) {
			copyOAS := s
			copyOAS.Extensions["x-abcd"] = []byte(`{"key":"value"}`)

			data, err := copyOAS.MarshalJSON()
			assert.NoError(t, err)
			assert.Contains(t, string(data), `"x-abcd":{"key":"value"}`)
		})

		t.Run("array", func(t *testing.T) {
			copyOAS := s
			copyOAS.Extensions["x-abcd"] = []byte(`[{"key":"value"},{"key":"value"}]`)

			data, err := copyOAS.MarshalJSON()
			assert.NoError(t, err)
			assert.Contains(t, string(data), `"x-abcd":[{"key":"value"},{"key":"value"}]`)
		})
	})
}

func TestOAS_Clone(t *testing.T) {
	s := &OAS{}
	s.SetTykExtension(&XTykAPIGateway{Info: Info{
		Name: "my-api",
	}})

	clonedOAS, err := s.Clone()
	assert.NoError(t, err)
	assert.Equal(t, s, clonedOAS)

	s.GetTykExtension().Info.Name = "my-api-modified"
	assert.NotEqual(t, s, clonedOAS)

	t.Run("clone impossible to marshal value", func(t *testing.T) {
		s.Extensions["weird extension"] = make(chan int)

		result, err := s.Clone()
		assert.NoError(t, err)

		_, ok := result.Extensions["weird extension"]
		assert.True(t, ok)
	})
}

func BenchmarkOAS_Clone(b *testing.B) {
	oas := &OAS{
		T: openapi3.T{
			Info: &openapi3.Info{
				Title: "my-oas-doc",
			},
			Paths: func() *openapi3.Paths {
				paths := openapi3.NewPaths()
				paths.Set("/get", &openapi3.PathItem{
					Get: &openapi3.Operation{
						Responses: func() *openapi3.Responses {
							responses := openapi3.NewResponses()
							responses.Set("200", &openapi3.ResponseRef{
								Value: &openapi3.Response{
									Description: getStrPointer("some example endpoint"),
								},
							})
							return responses
						}(),
					},
				})
				return paths
			}(),
		},
	}

	for i := 0; i < b.N; i++ {
		_, err := oas.Clone()
		assert.NoError(b, err)
	}
}

func TestMigrateAndFillOAS(t *testing.T) {
	var api apidef.APIDefinition
	api.SetDisabledFlags()
	api.Name = "Furkan"
	api.Proxy.ListenPath = "/furkan"
	api.VersionDefinition.Key = apidef.DefaultAPIVersionKey
	api.VersionDefinition.Location = apidef.HeaderLocation
	api.VersionData.DefaultVersion = "Default"
	api.VersionData.Versions = map[string]apidef.VersionInfo{
		"Default": {},
		"v1":      {},
		"v2":      {},
	}

	baseAPIDef, versionAPIDefs, err := MigrateAndFillOAS(&api)
	assert.NoError(t, err)
	assert.Len(t, versionAPIDefs, 2)
	assert.True(t, baseAPIDef.Classic.IsOAS)
	assert.Equal(t, DefaultOpenAPI, baseAPIDef.OAS.OpenAPI)
	assert.Equal(t, "Furkan", baseAPIDef.OAS.Info.Title)
	assert.Equal(t, "Default", baseAPIDef.OAS.Info.Version)

	assert.True(t, versionAPIDefs[0].Classic.IsOAS)
	assert.Equal(t, DefaultOpenAPI, versionAPIDefs[0].OAS.OpenAPI)
	assert.Equal(t, "Furkan-v1", versionAPIDefs[0].OAS.Info.Title)
	assert.Equal(t, "v1", versionAPIDefs[0].OAS.Info.Version)

	assert.True(t, versionAPIDefs[1].Classic.IsOAS)
	assert.Equal(t, DefaultOpenAPI, versionAPIDefs[1].OAS.OpenAPI)
	assert.Equal(t, "Furkan-v2", versionAPIDefs[1].OAS.Info.Title)
	assert.Equal(t, "v2", versionAPIDefs[1].OAS.Info.Version)

	err = baseAPIDef.OAS.Validate(context.Background())
	assert.NoError(t, err)

	t.Run("migration fails", func(t *testing.T) {
		_, _, err = MigrateAndFillOAS(&api)
		assert.ErrorIs(t, err, apidef.ErrMigrationNewVersioningEnabled)
	})

	t.Run("migrated base API validation fails", func(t *testing.T) {
		api = apidef.APIDefinition{Name: "Furkan"}
		_, _, err = MigrateAndFillOAS(&api)
		assert.ErrorContains(t, err, "base API Furkan migrated OAS is not valid")
	})

	t.Run("migrate versionAPI validation fails", func(t *testing.T) {
		api = apidef.APIDefinition{}
		api.SetDisabledFlags()
		api.Name = "Furkan"
		api.Proxy.ListenPath = "/furkan"
		api.VersionDefinition.Key = apidef.DefaultAPIVersionKey
		api.VersionDefinition.Location = apidef.HeaderLocation
		api.VersionData.DefaultVersion = "Default"
		api.VersionData.Versions = map[string]apidef.VersionInfo{
			"Default": {},
			"v2": {
				UseExtendedPaths: true,
				ExtendedPaths: apidef.ExtendedPathsSet{
					WhiteList: []apidef.EndPointMeta{
						{
							Disabled: false,
							Path:     "123",
							MethodActions: map[string]apidef.EndpointMethodMeta{
								http.MethodGet: {},
							},
						},
					},
				}},
		}
		_, _, err = MigrateAndFillOAS(&api)
		assert.ErrorContains(t, err, "version API Furkan-v2 migrated OAS is not valid")
	})
}

func TestMigrateAndFillOAS_DropEmpties(t *testing.T) {
	api := apidef.APIDefinition{Name: "Furkan"}
	api.Proxy.ListenPath = "/furkan"

	api.VersionDefinition.Location = apidef.HeaderLocation
	api.VersionDefinition.Key = apidef.DefaultAPIVersionKey
	api.VersionData.NotVersioned = true
	api.VersionData.Versions = map[string]apidef.VersionInfo{
		"Default": {},
	}
	api.ConfigDataDisabled = true

	baseAPI, _, err := MigrateAndFillOAS(&api)
	assert.NoError(t, err)

	t.Run("versioning", func(t *testing.T) {
		assert.Nil(t, baseAPI.OAS.GetTykExtension().Info.Versioning)
	})

	t.Run("plugin bundle", func(t *testing.T) {
		assert.Equal(t, &Middleware{
			Global: &Global{
				TrafficLogs: &TrafficLogs{
					Enabled: true,
				},
			},
		}, baseAPI.OAS.GetTykExtension().Middleware)
	})

	t.Run("mutualTLS", func(t *testing.T) {
		assert.Nil(t, baseAPI.OAS.GetTykExtension().Upstream.MutualTLS)
	})

	t.Run("certificatePinning", func(t *testing.T) {
		assert.Nil(t, baseAPI.OAS.GetTykExtension().Upstream.CertificatePinning)
	})

	t.Run("gatewayTags", func(t *testing.T) {
		assert.Nil(t, baseAPI.OAS.GetTykExtension().Server.GatewayTags)
	})

	t.Run("customDomain", func(t *testing.T) {
		assert.Nil(t, baseAPI.OAS.GetTykExtension().Server.CustomDomain)
	})
}

func TestMigrateAndFillOAS_ValidateRequest(t *testing.T) {
	newValidateJSONAPI := func(schema map[string]interface{}) *apidef.APIDefinition {
		return &apidef.APIDefinition{
			Name:  "my-api",
			Proxy: apidef.ProxyConfig{ListenPath: "/listen"},
			VersionData: apidef.VersionData{
				NotVersioned: true,
				Versions: map[string]apidef.VersionInfo{
					"Default": {
						UseExtendedPaths: true,
						ExtendedPaths: apidef.ExtendedPathsSet{
							ValidateJSON: []apidef.ValidatePathMeta{
								{
									Method:            http.MethodPost,
									Path:              "/post",
									Schema:            schema,
									ErrorResponseCode: http.StatusTeapot,
								},
							},
						},
					},
				},
			},
			ConfigDataDisabled: true,
		}
	}

	migratedAPI, _, err := MigrateAndFillOAS(newValidateJSONAPI(map[string]interface{}{"title": "Furkan"}))
	assert.NoError(t, err)

	pathItem := migratedAPI.OAS.Paths.Find("/post")
	assert.NotNil(t, pathItem)
	operation := pathItem.GetOperation(http.MethodPost)
	assert.NotNil(t, operation)
	assert.Equal(t, operation.RequestBody.Value.Content.Get("application/json").Schema.Value.Title, "Furkan")

	expectedValidateRequest := &ValidateRequest{
		Enabled:           true,
		ErrorResponseCode: http.StatusTeapot,
	}
	assert.Equal(t, expectedValidateRequest, migratedAPI.OAS.GetTykExtension().Middleware.Operations[operation.OperationID].ValidateRequest)
	assert.Nil(t, migratedAPI.Classic.VersionData.Versions[Main].ExtendedPaths.ValidateJSON)

	t.Run("fail", func(t *testing.T) {
		migratedAPI, _, err = MigrateAndFillOAS(newValidateJSONAPI(map[string]interface{}{"minLength": -1}))
		assert.Error(t, err)
	})
}

func TestMigrateAndFillOAS_CustomPluginAuth(t *testing.T) {
	t.Run("goplugin", func(t *testing.T) {
		api := apidef.APIDefinition{
			Name: "Custom plugin Auth",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
			UseGoPluginAuth: true,
			CustomMiddleware: apidef.MiddlewareSection{
				Driver: apidef.GoPluginDriver,
				AuthCheck: apidef.MiddlewareDefinition{
					Name: "AuthFunc",
					Path: "/path/to/plugin",
				},
				IdExtractor: apidef.MiddlewareIdExtractor{Disabled: true},
			},
			VersionData: apidef.VersionData{
				NotVersioned: true,
				Versions:     map[string]apidef.VersionInfo{},
			},
			ConfigDataDisabled: true,
		}
		migratedAPI, _, err := MigrateAndFillOAS(&api)
		assert.NoError(t, err)

		expectedAuthentication := Authentication{
			Enabled: true,
			Custom: &CustomPluginAuthentication{
				Enabled: true,
				Config: &AuthenticationPlugin{
					Enabled:      true,
					FunctionName: "AuthFunc",
					Path:         "/path/to/plugin",
				},
			},
		}

		assert.Equal(t, expectedAuthentication, *migratedAPI.OAS.GetTykExtension().Server.Authentication)
		assert.Equal(t, apidef.GoPluginDriver, migratedAPI.OAS.GetTykExtension().Middleware.Global.PluginConfig.Driver)
	})
	t.Run("coprocess", func(t *testing.T) {
		api := apidef.APIDefinition{
			Name: "Custom plugin Auth",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
			EnableCoProcessAuth: true,
			CustomMiddleware: apidef.MiddlewareSection{
				Driver: apidef.PythonDriver,
				AuthCheck: apidef.MiddlewareDefinition{
					Name: "AuthFunc",
					Path: "/path/to/plugin",
				},
				IdExtractor: apidef.MiddlewareIdExtractor{Disabled: true},
			},
			VersionData: apidef.VersionData{
				NotVersioned: true,
				Versions:     map[string]apidef.VersionInfo{},
			},
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.CoprocessType: {
					AuthHeaderName: "Authorization",
				},
			},
			ConfigDataDisabled: true,
		}
		migratedAPI, _, err := MigrateAndFillOAS(&api)
		assert.NoError(t, err)

		expectedAuthentication := Authentication{
			Enabled: true,
			Custom: &CustomPluginAuthentication{
				Enabled: true,
				Config: &AuthenticationPlugin{
					Enabled:      true,
					FunctionName: "AuthFunc",
					Path:         "/path/to/plugin",
				},
				AuthSources: AuthSources{
					Header: &AuthSource{
						Enabled: true,
						Name:    "Authorization",
					},
				},
			},
		}

		assert.Equal(t, expectedAuthentication, *migratedAPI.OAS.GetTykExtension().Server.Authentication)
		assert.Equal(t, apidef.PythonDriver, migratedAPI.OAS.GetTykExtension().Middleware.Global.PluginConfig.Driver)
	})
}

func TestMigrateAndFillOAS_CustomPlugins(t *testing.T) {
	t.Parallel()
	t.Run("pre", func(t *testing.T) {
		t.Parallel()
		api := apidef.APIDefinition{
			Name: "Custom plugin-pre",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
			CustomMiddleware: apidef.MiddlewareSection{
				Driver: apidef.GoPluginDriver,
				Pre: []apidef.MiddlewareDefinition{
					{
						Name: "Pre",
						Path: "/path/to/plugin",
					},
				},
			},
			VersionData: apidef.VersionData{
				NotVersioned: true,
				Versions:     map[string]apidef.VersionInfo{},
			},
			ConfigDataDisabled: true,
		}
		migratedAPI, _, err := MigrateAndFillOAS(&api)
		assert.NoError(t, err)

		expectedPrePlugin := CustomPlugins{
			{
				Enabled:      true,
				FunctionName: "Pre",
				Path:         "/path/to/plugin",
			},
		}
		assert.Equal(t, expectedPrePlugin, migratedAPI.OAS.GetTykExtension().Middleware.Global.PrePlugins)
		assert.Nil(t, migratedAPI.OAS.GetTykExtension().Middleware.Global.PrePlugin)
		assert.Equal(t, apidef.GoPluginDriver, migratedAPI.OAS.GetTykExtension().Middleware.Global.PluginConfig.Driver)
	})

	t.Run("postAuth", func(t *testing.T) {
		t.Parallel()
		api := apidef.APIDefinition{
			Name: "Custom plugin - post auth",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
			CustomMiddleware: apidef.MiddlewareSection{
				Driver: apidef.GoPluginDriver,
				PostKeyAuth: []apidef.MiddlewareDefinition{
					{
						Name: "PostAuth",
						Path: "/path/to/plugin",
					},
				},
			},
			VersionData: apidef.VersionData{
				NotVersioned: true,
				Versions:     map[string]apidef.VersionInfo{},
			},
			ConfigDataDisabled: true,
		}
		migratedAPI, _, err := MigrateAndFillOAS(&api)
		assert.NoError(t, err)

		expectedPrePlugin := CustomPlugins{
			{
				Enabled:      true,
				FunctionName: "PostAuth",
				Path:         "/path/to/plugin",
			},
		}
		assert.Equal(t, expectedPrePlugin, migratedAPI.OAS.GetTykExtension().Middleware.Global.PostAuthenticationPlugins)
		assert.Nil(t, migratedAPI.OAS.GetTykExtension().Middleware.Global.PostAuthenticationPlugin)
		assert.Equal(t, apidef.GoPluginDriver, migratedAPI.OAS.GetTykExtension().Middleware.Global.PluginConfig.Driver)
	})

	t.Run("post", func(t *testing.T) {
		t.Parallel()
		api := apidef.APIDefinition{
			Name: "Custom plugin - post",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
			CustomMiddleware: apidef.MiddlewareSection{
				Driver: apidef.GoPluginDriver,
				Post: []apidef.MiddlewareDefinition{
					{
						Name: "Post",
						Path: "/path/to/plugin",
					},
				},
			},
			VersionData: apidef.VersionData{
				NotVersioned: true,
				Versions:     map[string]apidef.VersionInfo{},
			},
			ConfigDataDisabled: true,
		}
		migratedAPI, _, err := MigrateAndFillOAS(&api)
		assert.NoError(t, err)

		expectedPrePlugin := CustomPlugins{
			{
				Enabled:      true,
				FunctionName: "Post",
				Path:         "/path/to/plugin",
			},
		}
		assert.Equal(t, expectedPrePlugin, migratedAPI.OAS.GetTykExtension().Middleware.Global.PostPlugins)
		assert.Nil(t, migratedAPI.OAS.GetTykExtension().Middleware.Global.PostPlugin)
		assert.Equal(t, apidef.GoPluginDriver, migratedAPI.OAS.GetTykExtension().Middleware.Global.PluginConfig.Driver)
	})

	t.Run("response", func(t *testing.T) {
		t.Parallel()
		api := apidef.APIDefinition{
			Name: "Custom plugin - response",
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
			CustomMiddleware: apidef.MiddlewareSection{
				Driver: apidef.GoPluginDriver,
				Response: []apidef.MiddlewareDefinition{
					{
						Name: "Response",
						Path: "/path/to/plugin",
					},
				},
			},
			VersionData: apidef.VersionData{
				NotVersioned: true,
				Versions:     map[string]apidef.VersionInfo{},
			},
			ConfigDataDisabled: true,
		}
		migratedAPI, _, err := MigrateAndFillOAS(&api)
		assert.NoError(t, err)

		expectedPrePlugin := CustomPlugins{
			{
				Enabled:      true,
				FunctionName: "Response",
				Path:         "/path/to/plugin",
			},
		}
		assert.Equal(t, expectedPrePlugin, migratedAPI.OAS.GetTykExtension().Middleware.Global.ResponsePlugins)
		assert.Nil(t, migratedAPI.OAS.GetTykExtension().Middleware.Global.ResponsePlugin)
		assert.Equal(t, apidef.GoPluginDriver, migratedAPI.OAS.GetTykExtension().Middleware.Global.PluginConfig.Driver)
	})
}

func TestMigrateAndFillOAS_PluginConfigData(t *testing.T) {
	configData := map[string]interface{}{
		"key": "value",
	}

	api := apidef.APIDefinition{
		Name: "config data",
		Proxy: apidef.ProxyConfig{
			ListenPath: "/",
		},
		CustomMiddleware: apidef.MiddlewareSection{
			Driver: apidef.GoPluginDriver,
		},
		VersionData: apidef.VersionData{
			NotVersioned: true,
			Versions:     map[string]apidef.VersionInfo{},
		},
		ConfigData: configData,
	}
	migratedAPI, _, err := MigrateAndFillOAS(&api)
	assert.NoError(t, err)

	expectedPluginConfigData := &PluginConfigData{
		Enabled: true,
		Value:   configData,
	}
	assert.Equal(t, expectedPluginConfigData, migratedAPI.OAS.GetTykExtension().Middleware.Global.PluginConfig.Data)
}

func TestAPIContext_getValidationOptionsFromConfig(t *testing.T) {
	t.Parallel()

	t.Run("should return validation options", func(t *testing.T) {
		conf, err := config.New()
		assert.Nil(t, err)
		options := GetValidationOptionsFromConfig(conf.OAS)
		assert.Len(t, options, 2)
	})

	t.Run("should return default validation options", func(t *testing.T) {
		conf, err := config.New()
		assert.Nil(t, err)

		conf.OAS.ValidateSchemaDefaults = true
		conf.OAS.ValidateExamples = true

		options := GetValidationOptionsFromConfig(conf.OAS)

		assert.Len(t, options, 0)
	})
}

func TestYaml(t *testing.T) {
	oasDoc := OAS{}
	Fill(t, &oasDoc, 0)

	tykExt := XTykAPIGateway{}
	Fill(t, &tykExt, 0)
	// json unmarshal workarounds
	{
		tykExt.Info.DBID = model.NewObjectID()
		tykExt.Middleware.Global.PrePlugin = nil
		tykExt.Middleware.Global.PostPlugin = nil
		tykExt.Middleware.Global.PostAuthenticationPlugin = nil
		tykExt.Middleware.Global.ResponsePlugin = nil

		for k, v := range tykExt.Server.Authentication.SecuritySchemes {
			intVal, ok := v.(int)
			assert.True(t, ok)
			tykExt.Server.Authentication.SecuritySchemes[k] = float64(intVal)
		}

		for k, v := range tykExt.Middleware.Global.PluginConfig.Data.Value {
			intVal, ok := v.(int)
			assert.True(t, ok)
			tykExt.Middleware.Global.PluginConfig.Data.Value[k] = float64(intVal)
		}
	}

	oasDoc.SetTykExtension(&tykExt)

	jsonBody, err := json.Marshal(&oasDoc)
	assert.NoError(t, err)

	yamlBody, err := yaml.JSONToYAML(jsonBody)
	assert.NoError(t, err)

	yamlOAS, err := openapi3.NewLoader().LoadFromData(yamlBody)
	assert.NoError(t, err)

	yamlOASDoc := OAS{
		T: *yamlOAS,
	}

	yamlOASExt := yamlOASDoc.GetTykExtension()
	assert.Equal(t, tykExt, *yamlOASExt)

	yamlOASDoc.SetTykExtension(nil)
	oasDoc.SetTykExtension(nil)
	assert.Equal(t, oasDoc, yamlOASDoc)
}
