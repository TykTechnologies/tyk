package oas

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-091
// SW-REQ-091:nominal:nominal
// SW-REQ-091:boundary:nominal
// SW-REQ-091:error_handling:negative
// SW-REQ-091:determinism:nominal
func TestOperationDocumentHelpersPreserveSupportBehavior(t *testing.T) {
	t.Run("aggregate fill creates operations paths validation and mock support shapes", func(t *testing.T) {
		spec := &OAS{T: openapi3.T{Paths: openapi3.NewPaths()}}
		spec.SetTykExtension(&XTykAPIGateway{})

		spec.fillPathsAndOperations(apidef.ExtendedPathsSet{
			WhiteList: []apidef.EndPointMeta{
				{Path: "/pets/[0-9]+", Method: http.MethodGet, IgnoreCase: true},
				{
					Path:   "/mock",
					Method: http.MethodGet,
					MethodActions: map[string]apidef.EndpointMethodMeta{
						http.MethodGet: {Action: apidef.Reply},
					},
				},
			},
			BlackList: []apidef.EndPointMeta{
				{Path: "/blocked", Method: http.MethodPost},
			},
			Ignored: []apidef.EndPointMeta{
				{Path: "/ignored", Method: http.MethodDelete},
			},
			ValidateJSON: []apidef.ValidatePathMeta{{
				Path:              "/validate",
				Method:            http.MethodPost,
				Schema:            map[string]interface{}{"type": "object"},
				ErrorResponseCode: http.StatusTeapot,
			}},
			MockResponse: []apidef.MockResponseMeta{{
				Path:    "/mock",
				Method:  http.MethodGet,
				Code:    http.StatusAccepted,
				Body:    `{"ok":true}`,
				Headers: map[string]string{"content-type": "application/json"},
			}},
		})

		regexPath := spec.Paths.Value("/pets/{customRegex1}")
		require.NotNil(t, regexPath)
		require.Len(t, regexPath.Parameters, 1)
		assert.Equal(t, "[0-9]+", regexPath.Parameters[0].Value.Schema.Value.Pattern)

		allowOp := spec.GetTykExtension().getOperation("pets/[0-9]+GET")
		require.NotNil(t, allowOp.Allow)
		assert.True(t, allowOp.Allow.Enabled)
		assert.True(t, allowOp.Allow.IgnoreCase)

		blockOp := spec.GetTykExtension().getOperation("blockedPOST")
		require.NotNil(t, blockOp.Block)
		assert.True(t, blockOp.Block.Enabled)

		ignoredOp := spec.GetTykExtension().getOperation("ignoredDELETE")
		require.NotNil(t, ignoredOp.IgnoreAuthentication)
		assert.True(t, ignoredOp.IgnoreAuthentication.Enabled)

		validateOperation := spec.Paths.Find("/validate").GetOperation(http.MethodPost)
		require.NotNil(t, validateOperation.RequestBody)
		require.NotNil(t, validateOperation.RequestBody.Value.Content.Get(contentTypeJSON))
		validateOp := spec.GetTykExtension().getOperation("validatePOST")
		require.NotNil(t, validateOp.ValidateRequest)
		assert.Equal(t, http.StatusTeapot, validateOp.ValidateRequest.ErrorResponseCode)

		mockOperation := spec.Paths.Find("/mock").GetOperation(http.MethodGet)
		require.NotNil(t, mockOperation.Responses.Value("202"))
		mockOp := spec.GetTykExtension().getOperation("mockGET")
		require.NotNil(t, mockOp.MockResponse)
		assert.Equal(t, http.StatusAccepted, mockOp.MockResponse.Code)
		assert.Nil(t, mockOp.Allow, "reply method actions must not become allow-list middleware")
		require.NotNil(t, mockOp.IgnoreAuthentication)
		assert.True(t, mockOp.IgnoreAuthentication.Enabled)
	})

	t.Run("operation extraction appends only configured extended path entries", func(t *testing.T) {
		operation := &Operation{
			Allow:                &Allowance{Enabled: true, IgnoreCase: true},
			Block:                &Allowance{Enabled: false},
			IgnoreAuthentication: &Allowance{Enabled: true},
			ValidateRequest:      &ValidateRequest{Enabled: true, ErrorResponseCode: http.StatusBadRequest},
			MockResponse: &MockResponse{
				Enabled: true,
				Code:    http.StatusCreated,
				Body:    "created",
				Headers: Headers{{Name: "X-Created", Value: "yes"}},
			},
			Cache:            &CachePlugin{Enabled: true, CacheByRegex: `"id":[^,]*`, CacheResponseCodes: []int{200, 201}, Timeout: 30},
			EnforceTimeout:   &EnforceTimeout{Enabled: true, Value: 3},
			RequestSizeLimit: &RequestSizeLimit{Enabled: true, Value: 4096},
			CircuitBreaker:   &CircuitBreaker{Enabled: true, Threshold: 0.5, SampleSize: 10, CoolDownPeriod: 20, HalfOpenStateEnabled: true},
			TrackEndpoint:    &TrackEndpoint{Enabled: true},
			DoNotTrackEndpoint: &TrackEndpoint{
				Enabled: false,
			},
		}

		var ep apidef.ExtendedPathsSet
		operation.ExtractToExtendedPaths(&ep, "/pets", http.MethodPatch)
		operation.ExtractToExtendedPaths(nil, "/ignored", http.MethodGet)
		(*Operation)(nil).ExtractToExtendedPaths(&ep, "/ignored", http.MethodGet)

		require.Len(t, ep.WhiteList, 1)
		assert.Equal(t, apidef.EndPointMeta{Path: "/pets", Method: http.MethodPatch, IgnoreCase: true}, ep.WhiteList[0])
		require.Len(t, ep.BlackList, 1)
		assert.True(t, ep.BlackList[0].Disabled)
		require.Len(t, ep.Ignored, 1)
		assert.False(t, ep.Ignored[0].Disabled)
		require.Len(t, ep.ValidateRequest, 1)
		assert.Equal(t, http.StatusBadRequest, ep.ValidateRequest[0].ErrorResponseCode)
		require.Len(t, ep.MockResponse, 1)
		assert.Equal(t, map[string]string{"X-Created": "yes"}, ep.MockResponse[0].Headers)
		require.Len(t, ep.AdvanceCacheConfig, 1)
		assert.Equal(t, int64(30), ep.AdvanceCacheConfig[0].Timeout)
		require.Len(t, ep.HardTimeouts, 1)
		assert.Equal(t, 3, ep.HardTimeouts[0].TimeOut)
		require.Len(t, ep.SizeLimit, 1)
		assert.Equal(t, int64(4096), ep.SizeLimit[0].SizeLimit)
		require.Len(t, ep.CircuitBreaker, 1)
		assert.Equal(t, float64(0.5), ep.CircuitBreaker[0].ThresholdPercent)
		require.Len(t, ep.TrackEndpoints, 1)
		require.Len(t, ep.DoNotTrackEndpoints, 1)
		assert.True(t, ep.DoNotTrackEndpoints[0].Disabled)
	})

	t.Run("path parsing and operation ids preserve regex and existing parameter boundaries", func(t *testing.T) {
		tests := []struct {
			name         string
			path         string
			method       string
			expectedID   string
			expectedPath string
			paramNames   []string
			paramRegex   []string
		}{
			{name: "literal path", path: "/literal/path", method: http.MethodGet, expectedID: "literal/pathGET", expectedPath: "/literal/path"},
			{name: "raw regex segments", path: "/users/[a-z]+/[0-9]+$", method: http.MethodPost, expectedID: "users/[a-z]+/[0-9]+$POST", expectedPath: "/users/{customRegex1}/{customRegex2}", paramNames: []string{"customRegex1", "customRegex2"}, paramRegex: []string{"[a-z]+", "[0-9]+$"}},
			{name: "mux named regex", path: "/users/{userID:[0-9]+}/posts/{slug}", method: http.MethodPut, expectedID: "users/{userID:[0-9]+}/posts/{slug}PUT", expectedPath: "/users/{userID}/posts/{slug}", paramNames: []string{"userID", "slug"}, paramRegex: []string{"", ""}},
			{name: "trailing slash", path: "/trailing/.+/", method: http.MethodDelete, expectedID: "trailing/.+/DELETE", expectedPath: "/trailing/{customRegex1}/", paramNames: []string{"customRegex1"}, paramRegex: []string{".+"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				spec := &OAS{T: openapi3.T{Paths: openapi3.NewPaths()}}
				operationID := spec.getOperationID(tt.path, tt.method)
				assert.Equal(t, tt.expectedID, operationID)

				pathItem := spec.Paths.Value(tt.expectedPath)
				require.NotNil(t, pathItem)
				require.NotNil(t, pathItem.GetOperation(tt.method))
				assert.Equal(t, operationID, pathItem.GetOperation(tt.method).OperationID)
				require.Len(t, pathItem.Parameters, len(tt.paramNames))

				for i, name := range tt.paramNames {
					assert.Equal(t, name, pathItem.Parameters[i].Value.Name)
					assert.Equal(t, tt.paramRegex[i], pathItem.Parameters[i].Value.Schema.Value.Pattern)
				}
			})
		}

		spec := &OAS{T: openapi3.T{Paths: openapi3.NewPaths()}}
		spec.Paths.Set("/pets/{id}", &openapi3.PathItem{
			Parameters: []*openapi3.ParameterRef{{
				Value: &openapi3.Parameter{
					Name:     "id",
					In:       "path",
					Required: true,
					Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{
						Type:    &openapi3.Types{openapi3.TypeInteger},
						Pattern: "[0-9]+",
					}},
				},
			}},
		})
		assert.Equal(t, "pets/{id}GET", spec.getOperationID("/pets/{id}", http.MethodGet))
		require.Len(t, spec.Paths.Value("/pets/{id}").Parameters, 1)
		assert.Equal(t, "[0-9]+", spec.Paths.Value("/pets/{id}").Parameters[0].Value.Schema.Value.Pattern)
	})

	t.Run("import and validation helpers gate on local OAS evidence", func(t *testing.T) {
		validateCases := []struct {
			name      string
			operation *openapi3.Operation
			expected  bool
		}{
			{name: "path parameters", operation: &openapi3.Operation{Parameters: openapi3.Parameters{{Value: &openapi3.Parameter{Name: "id"}}}}, expected: true},
			{name: "json request body", operation: &openapi3.Operation{RequestBody: &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithJSONSchema(openapi3.NewStringSchema())}}, expected: true},
			{name: "missing request body", operation: &openapi3.Operation{}, expected: false},
			{name: "nil request body value", operation: &openapi3.Operation{RequestBody: &openapi3.RequestBodyRef{}}, expected: false},
		}
		for _, tt := range validateCases {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.expected, (&ValidateRequest{}).shouldImport(tt.operation))
			})
		}

		allow := true
		mock := true
		validate := true
		operation := &Operation{Block: &Allowance{Enabled: true}}
		operation.Import(&openapi3.Operation{
			Parameters: openapi3.Parameters{{Value: &openapi3.Parameter{Name: "id"}}},
			Responses: func() *openapi3.Responses {
				responses := openapi3.NewResponses()
				responses.Set("200", &openapi3.ResponseRef{Value: &openapi3.Response{
					Content: openapi3.Content{
						contentTypeJSON: &openapi3.MediaType{Example: map[string]interface{}{"ok": true}},
					},
				}})
				return responses
			}(),
		}, TykExtensionConfigParams{AllowList: &allow, ValidateRequest: &validate, MockResponse: &mock})

		require.NotNil(t, operation.Allow)
		assert.True(t, operation.Allow.Enabled)
		require.NotNil(t, operation.Block)
		assert.False(t, operation.Block.Enabled)
		require.NotNil(t, operation.ValidateRequest)
		assert.Equal(t, http.StatusUnprocessableEntity, operation.ValidateRequest.ErrorResponseCode)
		require.NotNil(t, operation.MockResponse)
		require.NotNil(t, operation.MockResponse.FromOASExamples)
		assert.True(t, operation.MockResponse.FromOASExamples.Enabled)

		_, err := convertSchema(map[string]interface{}{"type": "string", "minLength": -1})
		require.Error(t, err)
	})

	t.Run("mock response helpers are deterministic", func(t *testing.T) {
		contentTypeCases := []struct {
			name     string
			mock     apidef.MockResponseMeta
			expected string
		}{
			{name: "explicit header", mock: apidef.MockResponseMeta{Headers: map[string]string{"content-type": "application/problem+json"}, Body: "plain"}, expected: "application/problem+json"},
			{name: "json object body", mock: apidef.MockResponseMeta{Body: `{"ok":true}`}, expected: contentTypeJSON},
			{name: "json array body", mock: apidef.MockResponseMeta{Body: `[{"ok":true}]`}, expected: contentTypeJSON},
			{name: "plain body", mock: apidef.MockResponseMeta{Body: "ok"}, expected: "text/plain"},
			{name: "empty body", mock: apidef.MockResponseMeta{}, expected: "text/plain"},
		}
		for _, tt := range contentTypeCases {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.expected, detectMockResponseContentType(tt.mock))
			})
		}

		response := &MockResponse{}
		response.Fill(apidef.MockResponseMeta{
			Code: http.StatusAccepted,
			Headers: map[string]string{
				"x-zeta":  "z",
				"x-alpha": "a",
			},
		})
		assert.Equal(t, Headers{{Name: "X-Alpha", Value: "a"}, {Name: "X-Zeta", Value: "z"}}, response.Headers)

		ep := &apidef.ExtendedPathsSet{WhiteList: []apidef.EndPointMeta{
			{Path: "/b", Method: http.MethodGet, MethodActions: map[string]apidef.EndpointMethodMeta{http.MethodGet: {Code: 200}}},
			{Path: "/a", Method: http.MethodPost, MethodActions: map[string]apidef.EndpointMethodMeta{http.MethodPost: {Code: 201}}},
			{Path: "/a", Method: http.MethodGet, MethodActions: map[string]apidef.EndpointMethodMeta{http.MethodGet: {Code: 202}}},
			{Path: "/a", Method: http.MethodGet, MethodActions: map[string]apidef.EndpointMethodMeta{http.MethodGet: {Code: 200}}},
		}}
		sortMockResponseAllowList(ep)
		assert.Equal(t, []apidef.EndPointMeta{
			{Path: "/a", Method: http.MethodGet, MethodActions: map[string]apidef.EndpointMethodMeta{http.MethodGet: {Code: 200}}},
			{Path: "/a", Method: http.MethodGet, MethodActions: map[string]apidef.EndpointMethodMeta{http.MethodGet: {Code: 202}}},
			{Path: "/a", Method: http.MethodPost, MethodActions: map[string]apidef.EndpointMethodMeta{http.MethodPost: {Code: 201}}},
			{Path: "/b", Method: http.MethodGet, MethodActions: map[string]apidef.EndpointMethodMeta{http.MethodGet: {Code: 200}}},
		}, ep.WhiteList)
	})
}
