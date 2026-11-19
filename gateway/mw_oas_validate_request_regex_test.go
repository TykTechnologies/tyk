package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

// TestValidateRequest_customRegexEndpoints_schemaSelection pins whose body schema applies
// when two endpoints differ only by their regex: migrated endpoints follow the router and
// pass when any matching one accepts, hand-written ones keep committing to the first.
func TestValidateRequest_customRegexEndpoints_schemaSelection(t *testing.T) {
	const (
		withName = `{"name":"x"}`
		withAge  = `{"age":1}`

		ok       = http.StatusOK
		rejected = http.StatusUnprocessableEntity
	)

	type request struct {
		segment, body string
		code          int
	}

	emptyDescription := ""

	operation := func(id, required string) *openapi3.Operation {
		responses := openapi3.NewResponses()
		responses.Delete("default")
		responses.Set("200", &openapi3.ResponseRef{Value: &openapi3.Response{Description: &emptyDescription}})

		body := openapi3.NewObjectSchema()
		body.Required = []string{required}

		return &openapi3.Operation{
			OperationID: id,
			Responses:   responses,
			RequestBody: &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithJSONSchema(body)},
		}
	}

	pathParam := func(name, pattern string) openapi3.Parameters {
		return openapi3.Parameters{{Value: &openapi3.Parameter{
			Name: name, In: "path", Required: true,
			Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithPattern(pattern)},
		}}}
	}

	for _, tc := range []struct {
		name           string
		handWritten    bool
		prefix, suffix bool
		first, second  string
		requests       []request
	}{
		{
			name:  "migrated, disjoint, wildcard",
			first: "[a-z]+", second: "[0-9]+",
			requests: []request{
				{"abc", withName, ok},
				{"abc", withAge, rejected},
				{"123", withAge, ok},
				{"123", withName, rejected},
				{"abc123", withName, ok},
				{"abc123", withAge, rejected},
				{"123abc", withAge, ok},
				{"123abc", withName, rejected},
				{"ABC", withName, rejected},
				{"ABC", withAge, rejected},
			},
		},
		{
			name:   "migrated, disjoint, strict",
			prefix: true, suffix: true,
			first: "[a-z]+", second: "[0-9]+",
			requests: []request{
				{"abc", withName, ok},
				{"abc", withAge, rejected},
				{"123", withAge, ok},
				{"123", withName, rejected},
				{"abc123", withName, rejected},
				{"abc123", withAge, rejected},
				{"123abc", withName, rejected},
				{"123abc", withAge, rejected},
			},
		},
		{
			name:  "migrated, overlapping: any matching endpoint may accept",
			first: "[a-z0-9]+", second: "[0-9]+",
			requests: []request{
				{"123", withName, ok},
				{"123", withAge, ok},
				{"123", `{}`, rejected},
				{"abc", withName, ok},
				{"abc", withAge, rejected},
			},
		},
		{
			name:        "hand-written, overlapping: first candidate decides",
			handWritten: true,
			first:       "[a-z0-9]+", second: "[0-9]+",
			requests: []request{
				{"123", withName, ok},
				{"123", withAge, rejected},
				{"abc", withName, ok},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := StartTest(func(c *config.Config) {
				c.HttpServerOptions.EnablePathPrefixMatching = tc.prefix
				c.HttpServerOptions.EnablePathSuffixMatching = tc.suffix
			})
			defer g.Close()

			firstParam, secondParam := "customRegex1", "customRegex2"
			if tc.handWritten {
				firstParam, secondParam = "slug", "id"
			}

			item := func(opID, required, param, pattern string) *openapi3.PathItem {
				op := operation(opID, required)
				if tc.handWritten {
					op.Parameters = pathParam(param, pattern)
					return &openapi3.PathItem{Post: op}
				}

				return &openapi3.PathItem{Post: op, Parameters: pathParam(param, pattern)}
			}

			paths := openapi3.NewPaths()
			paths.Set("/users/{"+firstParam+"}", item("firstPOST", "name", firstParam, tc.first))
			paths.Set("/users/{"+secondParam+"}", item("secondPOST", "age", secondParam, tc.second))

			validated := func() *oas.Operation {
				return &oas.Operation{ValidateRequest: &oas.ValidateRequest{Enabled: true}}
			}

			doc := oas.OAS{}
			doc.OpenAPI = "3.0.3"
			doc.Info = &openapi3.Info{Version: "1", Title: "custom regex endpoints"}
			doc.Paths = paths
			doc.SetTykExtension(&oas.XTykAPIGateway{
				Middleware: &oas.Middleware{Operations: oas.Operations{
					"firstPOST":  validated(),
					"secondPOST": validated(),
				}},
			})

			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/regex/"
				spec.Proxy.StripListenPath = true
				spec.UseKeylessAccess = true
				spec.IsOAS = true
				spec.OAS = doc
			})

			for _, r := range tc.requests {
				_, _ = g.Run(t, test.TestCase{
					Method:  http.MethodPost,
					Path:    "/regex/users/" + r.segment,
					Data:    r.body,
					Headers: map[string]string{"Content-Type": "application/json"},
					Code:    r.code,
				})
			}
		})
	}
}

// TestValidateRequest_customRegexEndpoints pins what two endpoints told apart only by
// their regex do when both have request validation and a mock response enabled.
func TestValidateRequest_customRegexEndpoints(t *testing.T) {
	const (
		firstRejects  = http.StatusBadRequest
		secondRejects = http.StatusTeapot

		first  = `"endpoint":"first"`
		second = `"endpoint":"second"`
	)

	type request struct {
		segment string
		code    int
		body    string
	}

	emptyDescription := ""

	responses := func() *openapi3.Responses {
		r := openapi3.NewResponses()
		r.Delete("default")
		r.Set("200", &openapi3.ResponseRef{Value: &openapi3.Response{Description: &emptyDescription}})

		return r
	}

	pathParam := func(name, pattern string) openapi3.Parameters {
		return openapi3.Parameters{{Value: &openapi3.Parameter{
			Name: name, In: "path", Required: true,
			Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithPattern(pattern)},
		}}}
	}

	endpoint := func(body string, rejectCode int) *oas.Operation {
		return &oas.Operation{
			Allow:                &oas.Allowance{Enabled: true},
			IgnoreAuthentication: &oas.Allowance{Enabled: true},
			ValidateRequest:      &oas.ValidateRequest{Enabled: true, ErrorResponseCode: rejectCode},
			MockResponse: &oas.MockResponse{
				Enabled:         true,
				Code:            http.StatusOK,
				Body:            "{" + body + "}",
				FromOASExamples: &oas.FromOASExamples{},
			},
		}
	}

	for _, tc := range []struct {
		name          string
		onOperation   bool
		first, second string
		requests      []request
	}{
		{
			name:  "migrated shape, disjoint regexes",
			first: "[a-z]+", second: "[0-9]+",
			requests: []request{
				{"gogo", http.StatusOK, first},
				{"123", http.StatusOK, second},
				{"GO-GO", firstRejects, ""},
				{"go123", http.StatusOK, first},
				{"123go", http.StatusOK, second},
			},
		},
		{
			name:  "migrated shape, overlapping regexes",
			first: "[a-z0-9]+", second: "[0-9]+",
			requests: []request{
				{"gogo", http.StatusOK, first},
				{"123", http.StatusOK, second},
				{"GO-GO", firstRejects, ""},
				{"go123", http.StatusOK, first},
				{"123go", http.StatusOK, second},
			},
		},
		{
			name:        "parameters on the operation, disjoint regexes",
			onOperation: true,
			first:       "[a-z]+", second: "[0-9]+",
			requests: []request{
				{"gogo", http.StatusOK, first},
				{"123", http.StatusOK, second},
				{"GO-GO", firstRejects, ""},
				{"go123", http.StatusOK, first},
				{"123go", http.StatusOK, first},
			},
		},
		{
			name:        "parameters on the operation, overlapping regexes",
			onOperation: true,
			first:       "[a-z0-9]+", second: "[0-9]+",
			requests: []request{
				{"gogo", http.StatusOK, first},
				{"123", http.StatusOK, first},
				{"GO-GO", firstRejects, ""},
				{"go123", http.StatusOK, first},
				{"123go", http.StatusOK, first},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := StartTest(nil)
			defer g.Close()

			item := func(opID, param, pattern string) *openapi3.PathItem {
				op := &openapi3.Operation{OperationID: opID, Responses: responses()}
				if tc.onOperation {
					op.Parameters = pathParam(param, pattern)
					return &openapi3.PathItem{Get: op}
				}

				return &openapi3.PathItem{Get: op, Parameters: pathParam(param, pattern)}
			}

			paths := openapi3.NewPaths()
			paths.Set("/users/{customRegex1}", item("firstGET", "customRegex1", tc.first))
			paths.Set("/users/{customRegex2}", item("secondGET", "customRegex2", tc.second))

			doc := oas.OAS{}
			doc.OpenAPI = "3.0.3"
			doc.Info = &openapi3.Info{Version: "1", Title: "custom regex endpoints"}
			doc.Paths = paths
			doc.SetTykExtension(&oas.XTykAPIGateway{
				Middleware: &oas.Middleware{Operations: oas.Operations{
					"firstGET":  endpoint(first, firstRejects),
					"secondGET": endpoint(second, secondRejects),
				}},
			})

			g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/regex/"
				spec.Proxy.StripListenPath = true
				spec.UseKeylessAccess = true
				spec.IsOAS = true
				spec.OAS = doc
			})

			for _, r := range tc.requests {
				_, _ = g.Run(t, test.TestCase{Path: "/regex/users/" + r.segment, Code: r.code, BodyMatch: r.body})
			}
		})
	}
}
