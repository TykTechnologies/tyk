package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

var testJsonSchema = `{
    "title": "Person",
    "type": "object",
    "properties": {
        "firstName": {
            "type": "string"
        },
        "lastName": {
            "type": "string"
        },
        "age": {
            "description": "Age in years",
            "type": "integer",
            "minimum": 0
        },
		"objs":{
			"enum":["a","b","c"],
			"type":"string"
		}
    },
    "required": ["firstName", "lastName"]
}`

func (ts *Test) testPrepareValidateJSONSchema(enabled bool) {

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			json.Unmarshal([]byte(`[
				{
					"disabled": `+fmt.Sprintf("%v,", !enabled)+`
					"path": "/v",
					"method": "POST",
					"schema": `+testJsonSchema+`
				}
			]`), &v.ExtendedPaths.ValidateJSON)
		})

		spec.Proxy.ListenPath = "/"
	})
}

func TestValidateJSONSchema(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.testPrepareValidateJSONSchema(true)

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/without_validation", Data: "{not_valid}", Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/v", Data: `{"age":23}`, BodyMatchFunc: func(b []byte) bool {
			var body = string(b)
			var result = true
			result = result && strings.Contains(body, "firstName is required")
			result = result && strings.Contains(body, "lastName is required")
			result = result && strings.Contains(body, `"error":`)
			return result
		}, Code: http.StatusUnprocessableEntity},
		{Method: http.MethodPost, Path: "/v", Data: `[]`, BodyMatch: `Expected: object, given: array`, Code: http.StatusUnprocessableEntity},
		{Method: http.MethodPost, Path: "/v", Data: `not_json`, Code: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/v", Data: `{"age":23, "firstName": "Harry", "lastName": "Potter"}`, Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/v", Data: `{"age":23, "firstName": "Harry", "lastName": "Potter", "objs": "d"}`, Code: http.StatusUnprocessableEntity, BodyMatch: `objs: objs must be one of the following: \\"a\\", \\"b\\", \\"c\\"`},
	}...)

	t.Run("disabled", func(t *testing.T) {
		ts.testPrepareValidateJSONSchema(false)

		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodPost, Path: "/without_validation", Data: "{not_valid}", Code: http.StatusOK},
			{Method: http.MethodPost, Path: "/v", Data: `{"age":23}`, Code: http.StatusOK}, // failed above
		}...)
	})

}

func BenchmarkValidateJSONSchema(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest(nil)
	defer ts.Close()

	ts.testPrepareValidateJSONSchema(true)

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			{Method: "POST", Path: "/without_validation", Data: "{not_valid}", Code: http.StatusOK},
			{Method: "POST", Path: "/v", Data: `{"age":23}`, BodyMatch: `firstName: firstName is required; lastName: lastName is required`, Code: http.StatusUnprocessableEntity},
			{Method: "POST", Path: "/v", Data: `[]`, BodyMatch: `Expected: object, given: array`, Code: http.StatusUnprocessableEntity},
			{Method: "POST", Path: "/v", Data: `not_json`, Code: http.StatusBadRequest},
			{Method: "POST", Path: "/v", Data: `{"age":23, "firstName": "Harry", "lastName": "Potter"}`, Code: http.StatusOK},
		}...)
	}
}

func (ts *Test) prepareValidateJSONWithOverride(t *testing.T) {
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			require.NoError(t,
				json.Unmarshal([]byte(`[{"path": "/v", "method": "POST", "schema": `+testJsonSchema+`}]`), &v.ExtendedPaths.ValidateJSON),
			)
		})
		spec.Proxy.ListenPath = "/"
	})
}

func TestValidateJSONSchemaTemplateData(t *testing.T) {
	t.Run("InvalidParams rendered in override template on schema failure", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ErrorOverrides = apidef.ErrorOverridesMap{
				"422": []apidef.ErrorOverride{{
					Response: apidef.ErrorResponse{
						StatusCode: http.StatusUnprocessableEntity,
						Body:       `{"detail": "{{.InvalidParams}}"}`,
					},
				}},
			}
		})
		defer ts.Close()

		ts.prepareValidateJSONWithOverride(t)

		_, _ = ts.Run(t, test.TestCase{
			Method: http.MethodPost,
			Path:   "/v",
			Data:   `{"age": 23}`,
			Code:   http.StatusUnprocessableEntity,
			BodyMatchFunc: func(b []byte) bool {
				body := string(b)
				return strings.Contains(body, `"detail"`) &&
					strings.Contains(body, "firstName is required") &&
					strings.Contains(body, "lastName is required")
			},
		})
	})

	t.Run("InvalidParams rendered in override template on JSON parse failure", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ErrorOverrides = apidef.ErrorOverridesMap{
				"400": []apidef.ErrorOverride{{
					Response: apidef.ErrorResponse{
						StatusCode: http.StatusBadRequest,
						Body:       `{"detail": "{{.InvalidParams}}"}`,
					},
				}},
			}
		})
		defer ts.Close()

		ts.prepareValidateJSONWithOverride(t)

		_, _ = ts.Run(t, test.TestCase{
			Method: http.MethodPost,
			Path:   "/v",
			Data:   `not_json`,
			Code:   http.StatusBadRequest,
			BodyMatchFunc: func(b []byte) bool {
				body := string(b)
				return strings.Contains(body, `"detail"`) && !strings.Contains(body, "{{.InvalidParams}}")
			},
		})
	})

	t.Run("backward compatibility - override using only Message still works when TemplateData is set", func(t *testing.T) {
		// {{.Message}} comes from Response.Message in the override config.
		// This test verifies that switching from *APIErrorWithContext to map[string]any
		// does not break templates that only reference {{.Message}} and {{.StatusCode}}.
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ErrorOverrides = apidef.ErrorOverridesMap{
				"422": []apidef.ErrorOverride{{
					Response: apidef.ErrorResponse{
						StatusCode: http.StatusUnprocessableEntity,
						Message:    "schema validation failed",
						Body:       `{"error": "{{.Message}}", "code": {{.StatusCode}}}`,
					},
				}},
			}
		})
		defer ts.Close()

		ts.prepareValidateJSONWithOverride(t)

		_, _ = ts.Run(t, test.TestCase{
			Method: http.MethodPost,
			Path:   "/v",
			Data:   `{"age": 23}`,
			Code:   http.StatusUnprocessableEntity,
			BodyMatchFunc: func(b []byte) bool {
				body := string(b)
				// Both {{.Message}} and {{.StatusCode}} must be rendered (no literal template syntax)
				return strings.Contains(body, "schema validation failed") &&
					strings.Contains(body, "422") &&
					!strings.Contains(body, "{{")
			},
		})
	})
}
