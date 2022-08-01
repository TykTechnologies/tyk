package oas

import (
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestOAS(t *testing.T) {
	t.Parallel()

	t.Run("empty paths", func(t *testing.T) {
		t.Parallel()

		var emptyOASPaths OAS
		emptyOASPaths.Paths = make(openapi3.Paths)
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
		nilOASPaths.SetTykExtension(&XTykAPIGateway{})

		var convertedAPI apidef.APIDefinition
		nilOASPaths.ExtractTo(&convertedAPI)

		var resultOAS OAS
		resultOAS.Fill(convertedAPI)

		// No paths in base OAS produce empty paths{} when converted back
		nilOASPaths.Paths = make(openapi3.Paths)
		nilOASPaths.Extensions = nil
		assert.Equal(t, nilOASPaths, resultOAS)
	})

	t.Run("extract paths", func(t *testing.T) {
		const operationID = "userGET"
		t.Parallel()

		var oasWithPaths OAS
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
		oasWithPaths.Paths = openapi3.Paths{
			"/user": {
				Get: &openapi3.Operation{
					OperationID: operationID,
				},
			},
		}

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

func TestOAS_AddServers(t *testing.T) {
	t.Parallel()
	type fields struct {
		T openapi3.T
	}
	type args struct {
		apiURL string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name:   "empty servers",
			fields: fields{T: openapi3.T{}},
			args:   args{apiURL: "http://127.0.0.1:8080/api"},
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
			args: args{apiURL: "http://127.0.0.1:8080/api"},
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
			args: args{apiURL: "http://127.0.0.1:8080/api"},
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
			args: args{apiURL: "http://127.0.0.1:8080/api"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &OAS{
				T: tt.fields.T,
			}
			s.AddServers(tt.args.apiURL)
			assert.Equal(t, tt.args.apiURL, s.Servers[0].URL)
		})
	}
}

func TestOAS_UpdateServers(t *testing.T) {
	t.Parallel()
	type fields struct {
		T openapi3.T
	}
	type args struct {
		apiURL    string
		oldAPIURL string
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		expectedURL string
	}{
		{
			name:        "empty servers",
			fields:      fields{T: openapi3.T{}},
			args:        args{apiURL: "http://127.0.0.1:8080/api", oldAPIURL: ""},
			expectedURL: "http://127.0.0.1:8080/api",
		},
		{
			name: "non-empty servers replace with new",
			fields: fields{T: openapi3.T{
				Servers: openapi3.Servers{
					{
						URL: "http://example-upstream.org/api",
					},
				},
			}},
			args:        args{apiURL: "http://127.0.0.1:8080/api", oldAPIURL: "http://example-upstream.org/api"},
			expectedURL: "http://127.0.0.1:8080/api",
		},
		{
			name: "non-empty servers not replace",
			fields: fields{T: openapi3.T{
				Servers: openapi3.Servers{
					{
						URL: "http://example-upstream.org/api",
					},
				},
			}},
			args:        args{apiURL: "http://127.0.0.1:8080/api", oldAPIURL: "http://localhost/api"},
			expectedURL: "http://example-upstream.org/api",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &OAS{
				T: tt.fields.T,
			}
			s.UpdateServers(tt.args.apiURL, tt.args.oldAPIURL)
			assert.Equal(t, tt.expectedURL, s.Servers[0].URL)
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
}
