package oas

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-088
// SW-REQ-088:nominal:nominal
// SW-REQ-088:boundary:nominal
// SW-REQ-088:boundary:boundary
// SW-REQ-088:error_handling:nominal
// SW-REQ-088:error_handling:negative
// SW-REQ-088:determinism:nominal
func TestDefaultReqProof_BuildDefaultsURLsAndQueryParams(t *testing.T) {
	t.Run("build default extension preserves import defaults and explicit overrides", func(t *testing.T) {
		spec := OAS{T: openapi3.T{
			Info: &openapi3.Info{Title: "ReqProof API"},
			Servers: openapi3.Servers{{
				URL: "https://{tenant}.example.com/{base}",
				Variables: map[string]*openapi3.ServerVariable{
					"tenant": {Default: "demo"},
					"base":   {Default: "api"},
				},
			}},
			Paths: openapi3.NewPaths(),
		}}

		err := spec.BuildDefaultTykExtension(TykExtensionConfigParams{
			ApiID:                  "api-id",
			ListenPath:             "/listen",
			CustomDomain:           "custom.example.com",
			SecurityProcessingMode: SecurityProcessingModeCompliant,
		}, true)
		require.NoError(t, err)

		ext := spec.GetTykExtension()
		require.NotNil(t, ext)
		assert.Equal(t, "ReqProof API", ext.Info.Name)
		assert.Equal(t, "api-id", ext.Info.ID)
		assert.True(t, ext.Info.State.Active)
		assert.False(t, ext.Info.State.Internal)
		assert.Equal(t, "/listen", ext.Server.ListenPath.Value)
		assert.True(t, ext.Server.ListenPath.Strip)
		assert.Equal(t, "https://demo.example.com/api", ext.Upstream.URL)
		require.NotNil(t, ext.Server.CustomDomain)
		assert.True(t, ext.Server.CustomDomain.Enabled)
		assert.Equal(t, "custom.example.com", ext.Server.CustomDomain.Name)
		require.NotNil(t, ext.Server.Authentication)
		assert.Equal(t, SecurityProcessingModeCompliant, ext.Server.Authentication.SecurityProcessingMode)
		require.NotNil(t, ext.Middleware)
		require.NotNil(t, ext.Middleware.Global)
		assert.True(t, ext.Middleware.Global.ContextVariables.Enabled)
		assert.True(t, ext.Middleware.Global.TrafficLogs.Enabled)
	})

	t.Run("non-import build does not enable import-only defaults", func(t *testing.T) {
		spec := OAS{T: openapi3.T{
			Info:    &openapi3.Info{Title: "ReqProof API"},
			Servers: openapi3.Servers{{URL: "https://upstream.example.com"}},
			Paths:   openapi3.NewPaths(),
		}}

		require.NoError(t, spec.BuildDefaultTykExtension(TykExtensionConfigParams{}, false))

		ext := spec.GetTykExtension()
		require.NotNil(t, ext)
		assert.False(t, ext.Info.State.Active)
		assert.False(t, ext.Server.ListenPath.Strip)
		assert.Nil(t, ext.Middleware)
	})

	t.Run("url helper boundaries return controlled errors", func(t *testing.T) {
		assert.True(t, isURLParametrized("https://{tenant}.example.com"))
		assert.False(t, isURLParametrized("https://tenant.example.com"))
		assert.Equal(t, "https://demo.example.com", replaceParameterWithValue("https://{tenant}.example.com", "tenant", "demo"))

		missingDefault := OAS{T: openapi3.T{Servers: openapi3.Servers{{
			URL:       "https://{tenant}.example.com",
			Variables: map[string]*openapi3.ServerVariable{"tenant": {}},
		}}}}
		_, err := generateUrlUsingDefaultVariableValues(&missingDefault, missingDefault.Servers[0].URL)
		require.EqualError(t, err, "server variable tenant does not have a default value")

		undefinedVariable := OAS{T: openapi3.T{Servers: openapi3.Servers{{
			URL:       "https://{tenant}.example.com/{missing}",
			Variables: map[string]*openapi3.ServerVariable{"tenant": {Default: "demo"}},
		}}}}
		_, err = generateUrlUsingDefaultVariableValues(&undefinedVariable, undefinedVariable.Servers[0].URL)
		require.EqualError(t, err, "server URL contains undefined variables")

		assert.ErrorIs(t, getURLFormatErr(true, "relative/path"), errInvalidUpstreamURL)
		assert.ErrorIs(t, getURLFormatErr(false, "relative/path"), errInvalidServerURL)

		emptyServers := OAS{T: openapi3.T{Info: &openapi3.Info{Title: "No Servers"}}}
		assert.ErrorIs(t, emptyServers.BuildDefaultTykExtension(TykExtensionConfigParams{}, true), errEmptyServersObject)
	})

	t.Run("query params trim values parse booleans and map compliant auth mode", func(t *testing.T) {
		endpoint := &url.URL{Path: "/"}
		query := endpoint.Query()
		query.Set("upstreamURL", " https://upstream.example.com ")
		query.Set("listenPath", " /listen ")
		query.Set("customDomain", " custom.example.com ")
		query.Set("apiID", " api-1 ")
		query.Set("authentication", "compliant")
		query.Set("validateRequest", "true")
		query.Set("allowList", "false")
		query.Set("mockResponse", "not-a-bool")
		endpoint.RawQuery = query.Encode()

		req, err := http.NewRequest(http.MethodPatch, endpoint.String(), nil)
		require.NoError(t, err)

		params := GetTykExtensionConfigParams(req)
		require.NotNil(t, params)
		assert.Equal(t, "https://upstream.example.com", params.UpstreamURL)
		assert.Equal(t, "/listen", params.ListenPath)
		assert.Equal(t, "custom.example.com", params.CustomDomain)
		assert.Equal(t, "api-1", params.ApiID)
		assert.Nil(t, params.Authentication)
		require.NotNil(t, params.ValidateRequest)
		assert.True(t, *params.ValidateRequest)
		require.NotNil(t, params.AllowList)
		assert.False(t, *params.AllowList)
		assert.Nil(t, params.MockResponse)
		assert.Equal(t, SecurityProcessingModeCompliant, params.SecurityProcessingMode)

		emptyReq, err := http.NewRequest(http.MethodPatch, "/", nil)
		require.NoError(t, err)
		assert.Nil(t, GetTykExtensionConfigParams(emptyReq))
		assert.Nil(t, getQueryValPtr("not-a-bool"))
	})
}

// Verifies: SYS-REQ-104, SW-REQ-088
// SW-REQ-088:nominal:nominal
// SW-REQ-088:boundary:boundary
// SW-REQ-088:error_handling:negative
// SW-REQ-088:determinism:nominal
func TestDefaultReqProof_AuthenticationSourcesAndMiddlewareCleanup(t *testing.T) {
	t.Run("authentication import processes distinct schemes and empty security errors", func(t *testing.T) {
		spec := OAS{T: openapi3.T{
			Security: openapi3.SecurityRequirements{
				{"token": []string{}},
				{"jwt": []string{}},
				{"token": []string{}},
			},
			Components: &openapi3.Components{SecuritySchemes: openapi3.SecuritySchemes{
				"token": {Value: &openapi3.SecurityScheme{Type: typeAPIKey, In: header, Name: "Authorization"}},
				"jwt":   {Value: &openapi3.SecurityScheme{Type: typeHTTP, Scheme: schemeBearer, BearerFormat: bearerFormatJWT}},
			}},
		}}
		spec.SetTykExtension(&XTykAPIGateway{})

		require.NoError(t, spec.importAuthentication(true))

		auth := spec.getTykAuthentication()
		require.NotNil(t, auth)
		assert.True(t, auth.Enabled)
		require.Len(t, auth.SecuritySchemes, 2)
		token, ok := auth.SecuritySchemes["token"].(*Token)
		require.True(t, ok)
		require.NotNil(t, token.Enabled)
		assert.True(t, *token.Enabled)
		jwt, ok := auth.SecuritySchemes["jwt"].(*JWT)
		require.True(t, ok)
		assert.True(t, jwt.Enabled)
		assert.Equal(t, apidef.AuthToken, auth.BaseIdentityProvider)

		empty := OAS{}
		empty.SetTykExtension(&XTykAPIGateway{})
		assert.ErrorIs(t, empty.importAuthentication(true), errEmptySecurityObject)
	})

	t.Run("auth source import maps known sources and ignores unknown sources", func(t *testing.T) {
		sources := AuthSources{}
		sources.Import(header)
		sources.Import(query)
		sources.Import(cookie)
		sources.Import("body")

		assert.Equal(t, &AuthSource{Enabled: true}, sources.Header)
		assert.Equal(t, &AuthSource{Enabled: true}, sources.Query)
		assert.Equal(t, &AuthSource{Enabled: true}, sources.Cookie)
	})

	t.Run("middleware import removes obsolete operations and drops empty operations", func(t *testing.T) {
		allow := true
		paths := openapi3.NewPaths()
		paths.Set("/pets", &openapi3.PathItem{
			Get: &openapi3.Operation{Responses: openapi3.NewResponses()},
		})
		spec := OAS{T: openapi3.T{
			Info:    &openapi3.Info{Title: "ReqProof API"},
			Servers: openapi3.Servers{{URL: "https://upstream.example.com"}},
			Paths:   paths,
		}}
		spec.SetTykExtension(&XTykAPIGateway{
			Middleware: &Middleware{
				Operations: Operations{
					"obsolete": {Allow: &Allowance{Enabled: true}},
				},
			},
		})

		require.NoError(t, spec.BuildDefaultTykExtension(TykExtensionConfigParams{AllowList: &allow}, true))

		operations := spec.getTykOperations()
		require.NotNil(t, operations)
		assert.NotContains(t, operations, "obsolete")
		opID := spec.getOperationID("/pets", http.MethodGet)
		require.Contains(t, operations, opID)
		require.NotNil(t, operations[opID].Allow)
		assert.True(t, operations[opID].Allow.Enabled)

		emptyPaths := openapi3.NewPaths()
		emptyPaths.Set("/empty", &openapi3.PathItem{
			Get: &openapi3.Operation{Responses: openapi3.NewResponses()},
		})
		emptySpec := OAS{T: openapi3.T{Paths: emptyPaths}}
		emptySpec.SetTykExtension(&XTykAPIGateway{})

		emptySpec.ImportMiddlewares(TykExtensionConfigParams{})

		assert.Nil(t, emptySpec.GetTykExtension().Middleware)
	})
}
