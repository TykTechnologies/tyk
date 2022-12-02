package oas

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestOAS_PathsAndOperations(t *testing.T) {
	t.Parallel()

	const operationId = "userGET"
	const existingOperationId = "userPOST"

	var oas OAS
	oas.Paths = openapi3.Paths{
		"/user": {
			Get: &openapi3.Operation{
				OperationID: operationId,
			},
		},
	}

	var operation Operation
	Fill(t, &operation, 0)
	operation.ValidateRequest = nil          // This one also fills native part, let's skip it for this test.
	operation.MockResponse = nil             // This one also fills native part, let's skip it for this test.
	operation.TransformRequestBody.Path = "" // if `path` and `body` are present, `body` would take precedence, detailed tests can be found in middleware_test.go

	xTykAPIGateway := &XTykAPIGateway{
		Middleware: &Middleware{
			Operations: Operations{
				operationId: &operation,
			},
		},
	}

	oas.SetTykExtension(xTykAPIGateway)

	var ep apidef.ExtendedPathsSet
	oas.extractPathsAndOperations(&ep)

	var convertedOAS OAS
	convertedOAS.Paths = openapi3.Paths{
		"/user": {
			Post: &openapi3.Operation{
				OperationID: existingOperationId,
			},
		},
	}
	convertedOAS.SetTykExtension(&XTykAPIGateway{Middleware: &Middleware{Operations: Operations{}}})
	convertedOAS.fillPathsAndOperations(ep)

	assert.Equal(t, oas.getTykOperations(), convertedOAS.getTykOperations())

	expCombinedPaths := openapi3.Paths{
		"/user": {
			Post: &openapi3.Operation{
				OperationID: existingOperationId,
			},
			Get: &openapi3.Operation{
				OperationID: operationId,
			},
		},
	}

	assert.Equal(t, expCombinedPaths, convertedOAS.Paths)
}

func TestOAS_PathsAndOperationsRegex(t *testing.T) {
	t.Parallel()

	expectedOperationID := "users/[a-z]+/[0-9]+$GET"
	expectedPath := "/users/{customRegex1}/{customRegex2}"

	var oas OAS
	oas.Paths = openapi3.Paths{}

	_ = oas.getOperationID("/users/[a-z]+/[0-9]+$", "GET")

	expectedPathItems := openapi3.Paths{
		expectedPath: &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: expectedOperationID,
			},
			Parameters: []*openapi3.ParameterRef{
				{
					Value: &openapi3.Parameter{
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:    "string",
								Pattern: "[a-z]+",
							},
						},
						Name:     "customRegex1",
						In:       "path",
						Required: true,
					},
				},
				{
					Value: &openapi3.Parameter{
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:    "string",
								Pattern: "[0-9]+$",
							},
						},
						Name:     "customRegex2",
						In:       "path",
						Required: true,
					},
				},
			},
		},
	}

	assert.Equal(t, expectedPathItems, oas.Paths, "expected path item differs")
}

func TestOAS_RegexOperationIDs(t *testing.T) {
	t.Parallel()

	type test struct {
		input  string
		method string
		want   string
	}

	tests := []test{
		{"/.+", "GET", ".+GET"},
		{"/.*", "GET", ".*GET"},
		{"/[^a]*", "GET", "[^a]*GET"},
		{"/foo$", "GET", "foo$GET"},
		{"/group/.+", "GET", "group/.+GET"},
		{"/group/.*", "GET", "group/.*GET"},
		{"/group/[^a]*", "GET", "group/[^a]*GET"},
		{"/group/foo$", "GET", "group/foo$GET"},
		{"/group/[^a]*/.*", "GET", "group/[^a]*/.*GET"},
	}

	for i, tc := range tests {
		var oas OAS
		oas.Paths = openapi3.Paths{
			tc.input: {
				Get: &openapi3.Operation{},
			},
		}
		got := oas.getOperationID(tc.input, tc.method)
		assert.Equalf(t, tc.want, got, "test %d: expected operationID %v, got %v", i, tc.want, got)
	}
}

func TestOAS_RegexPaths(t *testing.T) {
	t.Parallel()

	type test struct {
		input  string
		want   string
		params int
	}

	tests := []test{
		{"/.+", "/{customRegex1}", 1},
		{"/.*", "/{customRegex1}", 1},
		{"/[^a]*", "/{customRegex1}", 1},
		{"/foo$", "/{customRegex1}", 1},
		{"/group/.+", "/group/{customRegex1}", 1},
		{"/group/.*", "/group/{customRegex1}", 1},
		{"/group/[^a]*", "/group/{customRegex1}", 1},
		{"/group/foo$", "/group/{customRegex1}", 1},
		{"/group/[^a]*/.*", "/group/{customRegex1}/{customRegex2}", 2},
	}

	for i, tc := range tests {
		var oas OAS
		oas.Paths = openapi3.Paths{
			tc.input: {
				Get: &openapi3.Operation{},
			},
		}
		_ = oas.getOperationID(tc.input, "GET")

		p, ok := oas.Paths[tc.want]
		assert.Truef(t, ok, "test %d: path doesn't exist in OAS: %v", i, tc.want)
		assert.Lenf(t, p.Parameters, tc.params, "test %d: expected %d parameters, got %d", i, tc.params, len(p.Parameters))

		// rebuild original link
		got := tc.want
		for _, param := range p.Parameters {
			assert.NotNilf(t, param.Value, "test %d: missing value", i)
			assert.NotNilf(t, param.Value.Schema, "test %d: missing schema", i)
			assert.NotNilf(t, param.Value.Schema.Value, "test %d: missing schema value", i)

			assert.Truef(t, strings.HasPrefix(param.Value.Name, "customRegex"), "test %d: invalid name %v", i, param.Value.Name)

			got = strings.ReplaceAll(got, "{"+param.Value.Name+"}", param.Value.Schema.Value.Pattern)
		}

		assert.Equalf(t, tc.input, got, "test %d: rebuilt link, expected %v, got %v", i, tc.input, got)
	}
}

func TestValidateRequest(t *testing.T) {

}
