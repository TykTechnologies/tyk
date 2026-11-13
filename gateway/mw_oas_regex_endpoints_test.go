package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// TestClassicSideMiddleware_customRegexEndpoints pins which of two endpoints told apart
// only by their regex is picked by middleware that matches on the extracted Classic paths.
func TestClassicSideMiddleware_customRegexEndpoints(t *testing.T) {
	const (
		reqHeader  = "X-Req-Endpoint"
		respHeader = "X-Resp-Endpoint"
	)

	emptyDescription := ""

	responses := func() *openapi3.Responses {
		r := openapi3.NewResponses()
		r.Delete("default")
		r.Set("200", &openapi3.ResponseRef{Value: &openapi3.Response{Description: &emptyDescription}})

		return r
	}

	item := func(opID, param, pattern string) *openapi3.PathItem {
		return &openapi3.PathItem{
			Get: &openapi3.Operation{OperationID: opID, Responses: responses()},
			Parameters: openapi3.Parameters{{Value: &openapi3.Parameter{
				Name: param, In: "path", Required: true,
				Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema().WithPattern(pattern)},
			}}},
		}
	}

	endpoint := func(name, toMethod string) *oas.Operation {
		return &oas.Operation{
			Allow:                    &oas.Allowance{Enabled: true},
			TransformRequestMethod:   &oas.TransformRequestMethod{Enabled: true, ToMethod: toMethod},
			TransformRequestHeaders:  &oas.TransformHeaders{Enabled: true, Add: oas.Headers{{Name: reqHeader, Value: name}}},
			TransformResponseHeaders: &oas.TransformHeaders{Enabled: true, Add: oas.Headers{{Name: respHeader, Value: name}}},
		}
	}

	handledBy := func(segment, name, method string) test.TestCase {
		return test.TestCase{
			Path:         "/oas-api/users/" + segment,
			Code:         http.StatusOK,
			BodyMatch:    `"Method":"` + method + `".*"` + reqHeader + `":"` + name + `"`,
			HeadersMatch: map[string]string{respHeader: name},
		}
	}

	first := func(segment string) test.TestCase { return handledBy(segment, "first", http.MethodPut) }
	second := func(segment string) test.TestCase { return handledBy(segment, "second", http.MethodDelete) }
	notAllowed := func(segment string) test.TestCase {
		return test.TestCase{Path: "/oas-api/users/" + segment, Code: http.StatusForbidden}
	}

	for _, tc := range []struct {
		name          string
		first, second string
		requests      []test.TestCase
	}{
		{
			name:  "disjoint regexes",
			first: "[a-z]+", second: "[0-9]+",
			requests: []test.TestCase{first("gogo"), second("123"), notAllowed("GO-GO"), first("go123"), second("123go")},
		},
		{
			name:  "overlapping regexes",
			first: "[a-z0-9]+", second: "[0-9]+",
			requests: []test.TestCase{first("gogo"), second("123"), notAllowed("GO-GO"), first("go123"), second("123go")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := StartTest(nil)
			defer g.Close()

			g.Gw.LoadAPI(BuildOASAPI(func(doc *oas.OAS) {
				doc.Paths.Set("/users/{customRegex1}", item("firstGET", "customRegex1", tc.first))
				doc.Paths.Set("/users/{customRegex2}", item("secondGET", "customRegex2", tc.second))
				doc.GetTykExtension().Middleware = &oas.Middleware{Operations: oas.Operations{
					"firstGET":  endpoint("first", http.MethodPut),
					"secondGET": endpoint("second", http.MethodDelete),
				}}
			})...)

			_, _ = g.Run(t, tc.requests...)
		})
	}
}
