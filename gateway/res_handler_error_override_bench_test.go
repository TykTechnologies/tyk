package gateway

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/errors"
)

// Benchmark helpers

func createBenchmarkGateway(overrides apidef.ErrorOverridesMap) *Gateway {
	gw := &Gateway{}
	compiled := CompileErrorOverrides(overrides)
	if compiled != nil {
		gw.SetCompiledErrorOverrides(compiled)
	}
	return gw
}

func createBenchmarkMiddleware(overrides apidef.ErrorOverridesMap) *ResponseErrorOverrideMiddleware {
	gw := createBenchmarkGateway(overrides)
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "bench-api",
		},
		GlobalConfig: config.Config{
			ErrorOverrides: overrides,
		},
	}
	return &ResponseErrorOverrideMiddleware{
		BaseTykResponseHandler: BaseTykResponseHandler{
			Spec: spec,
			Gw:   gw,
		},
	}
}

func createBenchmarkResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
}

// Benchmark: Lazy body reader

func BenchmarkLazyBodyReader_NoRead(b *testing.B) {
	logger := logrus.NewEntry(logrus.New())
	bodyContent := []byte("test error response body")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := newLazyBodyReader(io.NopCloser(bytes.NewReader(bodyContent)), logger)
		_ = reader
	}
}

func BenchmarkLazyBodyReader_SmallBody(b *testing.B) {
	logger := logrus.NewEntry(logrus.New())
	bodyContent := []byte(`{"error": "Internal server error", "code": "ERR_500"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := newLazyBodyReader(io.NopCloser(bytes.NewReader(bodyContent)), logger)
		_ = reader.Read()
	}
}

func BenchmarkLazyBodyReader_LargeBody(b *testing.B) {
	logger := logrus.NewEntry(logrus.New())
	// Simulate large upstream error response (HTML error page, stack trace, etc.)
	bodyContent := make([]byte, maxBodySizeForMatching)
	for i := range bodyContent {
		bodyContent[i] = 'x'
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := newLazyBodyReader(io.NopCloser(bytes.NewReader(bodyContent)), logger)
		_ = reader.Read()
	}
}

func BenchmarkLazyBodyReader_CachedRead(b *testing.B) {
	logger := logrus.NewEntry(logrus.New())
	bodyContent := []byte(`{"error": "Internal server error"}`)
	reader := newLazyBodyReader(io.NopCloser(bytes.NewReader(bodyContent)), logger)

	// Pre-read to cache
	reader.Read()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reader.Read()
	}
}

func BenchmarkLazyBodyReader_RestoreBody(b *testing.B) {
	logger := logrus.NewEntry(logrus.New())
	bodyContent := []byte(`{"error": "server error"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := newLazyBodyReader(io.NopCloser(bytes.NewReader(bodyContent)), logger)
		reader.Read()
		res := &http.Response{}
		reader.RestoreIfRead(res)
	}
}

// Benchmark: ApplyUpstreamOverride - core matching logic

func BenchmarkApplyUpstreamOverride_NoMatch(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"404": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 404, Body: `{"error":"not_found"}`}},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return nil })
	}
}

func BenchmarkApplyUpstreamOverride_ExactMatch_NoBody(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"503": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 500, Message: "Service unavailable"}},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(503, func() []byte { return nil })
	}
}

func BenchmarkApplyUpstreamOverride_PatternMatch_5xx(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"5xx": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 503, Message: "Server error"}},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(502, func() []byte { return nil })
	}
}

func BenchmarkApplyUpstreamOverride_URSFlag(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"5xx": []apidef.ErrorOverride{
			{
				Match:    &apidef.ErrorMatcher{Flag: errors.URS},
				Response: apidef.ErrorResponse{StatusCode: 503, Body: `{"error":"upstream_error"}`},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return nil })
	}
}

func BenchmarkApplyUpstreamOverride_BodyFieldMatch(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"5xx": []apidef.ErrorOverride{
			{
				Match: &apidef.ErrorMatcher{
					BodyField: "error.type",
					BodyValue: "timeout",
				},
				Response: apidef.ErrorResponse{StatusCode: 504, Body: `{"error":"timeout"}`},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)
	body := []byte(`{"error": {"type": "timeout", "message": "request timed out"}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return body })
	}
}

func BenchmarkApplyUpstreamOverride_MessagePatternMatch(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"5xx": []apidef.ErrorOverride{
			{
				Match: &apidef.ErrorMatcher{
					MessagePattern: "database.*unavailable",
				},
				Response: apidef.ErrorResponse{StatusCode: 503, Message: "DB down"},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)
	body := []byte("database connection unavailable")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return body })
	}
}

func BenchmarkApplyUpstreamOverride_MultipleRules_FirstMatch(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"500": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 503, Message: "First"}},
			{Response: apidef.ErrorResponse{StatusCode: 503, Message: "Second"}},
			{Response: apidef.ErrorResponse{StatusCode: 503, Message: "Third"}},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return nil })
	}
}

func BenchmarkApplyUpstreamOverride_MultipleRules_LastMatch(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"500": []apidef.ErrorOverride{
			{
				Match:    &apidef.ErrorMatcher{Flag: errors.AKI},
				Response: apidef.ErrorResponse{Message: "Skip 1"},
			},
			{
				Match:    &apidef.ErrorMatcher{Flag: errors.RLT},
				Response: apidef.ErrorResponse{Message: "Skip 2"},
			},
			{
				Response: apidef.ErrorResponse{StatusCode: 503, Message: "Match"},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return nil })
	}
}

// Benchmark: Full middleware HandleResponse

func BenchmarkHandleResponse_NoOverride_Passthrough(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"404": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{Message: "Not found"}},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := createBenchmarkResponse(500, `{"error": "internal server error"}`)
		err := middleware.HandleResponse(rw, res, req, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandleResponse_SuccessResponse_Skip(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"500": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{Message: "Error"}},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := createBenchmarkResponse(200, `{"success": true}`)
		err := middleware.HandleResponse(rw, res, req, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandleResponse_ExactMatch_StatusOnly(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"503": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 500, Body: "Service unavailable"}},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := createBenchmarkResponse(503, "Service unavailable")
		err := middleware.HandleResponse(rw, res, req, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandleResponse_ExactMatch_WithBody(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"503": []apidef.ErrorOverride{
			{
				Response: apidef.ErrorResponse{
					StatusCode: 500,
					Body:       "Custom error message",
					Headers:    map[string]string{"Retry-After": "60"},
				},
			},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := createBenchmarkResponse(503, "Service unavailable")
		err := middleware.HandleResponse(rw, res, req, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandleResponse_PatternMatch_SmallBody(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"5xx": []apidef.ErrorOverride{
			{
				Match: &apidef.ErrorMatcher{
					BodyField: "error.code",
					BodyValue: "TIMEOUT",
				},
				Response: apidef.ErrorResponse{StatusCode: 504, Body: `{"error": "timeout"}`},
			},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := createBenchmarkResponse(500, `{"error": {"code": "TIMEOUT"}}`)
		err := middleware.HandleResponse(rw, res, req, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandleResponse_PatternMatch_LargeBody(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"5xx": []apidef.ErrorOverride{
			{
				Match: &apidef.ErrorMatcher{
					MessagePattern: "database.*error",
				},
				Response: apidef.ErrorResponse{StatusCode: 503, Body: `{"error": "db_error"}`},
			},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	// Create large body with match near the end
	largeBody := make([]byte, 10*1024)
	for i := range largeBody {
		largeBody[i] = 'x'
	}
	bodyStr := string(largeBody) + " database connection error"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := createBenchmarkResponse(500, bodyStr)
		err := middleware.HandleResponse(rw, res, req, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark: Rule matching with varying rule counts

func BenchmarkFindMatchingRuleGeneric_10Rules(b *testing.B) {
	benchmarkFindMatchingRuleGeneric(b, 10)
}

func BenchmarkFindMatchingRuleGeneric_50Rules(b *testing.B) {
	benchmarkFindMatchingRuleGeneric(b, 50)
}

func BenchmarkFindMatchingRuleGeneric_100Rules(b *testing.B) {
	benchmarkFindMatchingRuleGeneric(b, 100)
}

func benchmarkFindMatchingRuleGeneric(b *testing.B, ruleCount int) {
	b.Helper()
	overrides := apidef.ErrorOverridesMap{}

	// Create many rules for status 500
	rules := make([]apidef.ErrorOverride, ruleCount)
	for i := 0; i < ruleCount; i++ {
		rules[i] = apidef.ErrorOverride{
			Response: apidef.ErrorResponse{
				StatusCode: 500,
				Message:    fmt.Sprintf("Rule %d", i),
			},
		}
	}
	overrides["500"] = rules

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)
	compiled := gw.GetCompiledErrorOverrides()

	// Match last rule to test worst-case
	matchCount := 0

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchCount = 0
		_ = eo.findMatchingRuleGeneric(compiled, 500, func(_ *apidef.ErrorOverride) bool {
			matchCount++
			return matchCount == ruleCount // Match last rule
		})
	}
}

// Benchmark: Direct map lookup in CompiledErrorOverrides

func BenchmarkCompiledErrorOverrides_ExactCodeLookup(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"500": []apidef.ErrorOverride{{Response: apidef.ErrorResponse{Message: "Error"}}},
		"503": []apidef.ErrorOverride{{Response: apidef.ErrorResponse{Message: "Error"}}},
		"504": []apidef.ErrorOverride{{Response: apidef.ErrorResponse{Message: "Error"}}},
	}

	compiled := CompileErrorOverrides(overrides)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = compiled.ByExactCode[500]
	}
}

func BenchmarkCompiledErrorOverrides_PrefixLookup(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"5xx": []apidef.ErrorOverride{{Response: apidef.ErrorResponse{Message: "Error"}}},
	}

	compiled := CompileErrorOverrides(overrides)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = compiled.ByPrefix[5]
	}
}

func BenchmarkCompiledErrorOverrides_NoMatch(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"404": []apidef.ErrorOverride{{Response: apidef.ErrorResponse{Message: "Error"}}},
	}

	compiled := CompileErrorOverrides(overrides)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = compiled.ByExactCode[500]
	}
}

// Benchmark: matchesUpstreamCriteria variations

func BenchmarkMatchesUpstreamCriteria_NoCriteria(b *testing.B) {
	gw := createBenchmarkGateway(apidef.ErrorOverridesMap{})
	eo := NewErrorOverrides(&APISpec{}, gw)
	rule := &apidef.ErrorOverride{Match: nil}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.matchesUpstreamCriteria(rule, nil, 500)
	}
}

func BenchmarkMatchesUpstreamCriteria_URSFlag(b *testing.B) {
	gw := createBenchmarkGateway(apidef.ErrorOverridesMap{})
	eo := NewErrorOverrides(&APISpec{}, gw)
	rule := &apidef.ErrorOverride{
		Match: &apidef.ErrorMatcher{Flag: errors.URS},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.matchesUpstreamCriteria(rule, nil, 500)
	}
}

func BenchmarkMatchesUpstreamCriteria_BodyField_SmallJSON(b *testing.B) {
	gw := createBenchmarkGateway(apidef.ErrorOverridesMap{})
	eo := NewErrorOverrides(&APISpec{}, gw)
	rule := &apidef.ErrorOverride{
		Match: &apidef.ErrorMatcher{
			BodyField: "error.type",
			BodyValue: "timeout",
		},
	}
	body := []byte(`{"error": {"type": "timeout"}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.matchesUpstreamCriteria(rule, body, 500)
	}
}

func BenchmarkMatchesUpstreamCriteria_BodyField_LargeJSON(b *testing.B) {
	gw := createBenchmarkGateway(apidef.ErrorOverridesMap{})
	eo := NewErrorOverrides(&APISpec{}, gw)
	rule := &apidef.ErrorOverride{
		Match: &apidef.ErrorMatcher{
			BodyField: "deep.nested.field",
			BodyValue: "value",
		},
	}

	// Create large JSON with deeply nested target
	body := []byte(`{
		"error": "server error",
		"timestamp": "2024-01-01T00:00:00Z",
		"details": {
			"message": "Internal error",
			"stack": "` + string(make([]byte, 1000)) + `"
		},
		"deep": {
			"nested": {
				"field": "value"
			}
		}
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.matchesUpstreamCriteria(rule, body, 500)
	}
}

func BenchmarkMatchesUpstreamCriteria_MessagePattern_SimpleRegex(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"500": []apidef.ErrorOverride{
			{
				Match: &apidef.ErrorMatcher{
					MessagePattern: "timeout",
				},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)
	compiled := gw.GetCompiledErrorOverrides()
	rule := compiled.ByExactCode[500][0]
	body := []byte("connection timeout error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.matchesUpstreamCriteria(rule, body, 500)
	}
}

func BenchmarkMatchesUpstreamCriteria_MessagePattern_ComplexRegex(b *testing.B) {
	overrides := apidef.ErrorOverridesMap{
		"500": []apidef.ErrorOverride{
			{
				Match: &apidef.ErrorMatcher{
					MessagePattern: `(database|db|mysql|postgres).*?(connection|timeout|unavailable|error)`,
				},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(&APISpec{}, gw)
	compiled := gw.GetCompiledErrorOverrides()
	rule := compiled.ByExactCode[500][0]
	body := []byte("database connection unavailable - unable to connect to mysql server")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.matchesUpstreamCriteria(rule, body, 500)
	}
}

// Benchmark: Comparison scenarios - with vs without optimization

func BenchmarkShouldProcessResponse_FastPath_Success(b *testing.B) {
	middleware := createBenchmarkMiddleware(apidef.ErrorOverridesMap{
		"500": []apidef.ErrorOverride{{}},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := &http.Response{StatusCode: 200}
		_ = middleware.shouldProcessResponse(res)
	}
}

func BenchmarkShouldProcessResponse_FastPath_NoConfig(b *testing.B) {
	middleware := createBenchmarkMiddleware(apidef.ErrorOverridesMap{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := &http.Response{StatusCode: 500}
		_ = middleware.shouldProcessResponse(res)
	}
}

func BenchmarkShouldProcessResponse_Error(b *testing.B) {
	middleware := createBenchmarkMiddleware(apidef.ErrorOverridesMap{
		"500": []apidef.ErrorOverride{{}},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := &http.Response{StatusCode: 500}
		_ = middleware.shouldProcessResponse(res)
	}
}

// Benchmark: Memory allocations

func BenchmarkCreateOverrideResult(b *testing.B) {
	gw := createBenchmarkGateway(apidef.ErrorOverridesMap{})
	eo := NewErrorOverrides(&APISpec{}, gw)
	rule := &apidef.ErrorOverride{
		Response: apidef.ErrorResponse{
			StatusCode: 503,
			Message:    "Service unavailable",
			Headers: map[string]string{
				"Retry-After":  "60",
				"X-Error-Code": "SERVICE_DOWN",
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.createOverrideResult(rule, 500)
	}
}

func BenchmarkNeedsBodyForMatch(b *testing.B) {
	gw := createBenchmarkGateway(apidef.ErrorOverridesMap{})
	eo := NewErrorOverrides(&APISpec{}, gw)
	rule := &apidef.ErrorOverride{
		Match: &apidef.ErrorMatcher{
			BodyField: "error.code",
			BodyValue: "timeout",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.needsBodyForMatch(rule)
	}
}

// Benchmark: Real-world scenarios

func BenchmarkRealWorld_HighTraffic_NoOverride(b *testing.B) {
	// Simulate high traffic scenario where most requests don't match
	overrides := apidef.ErrorOverridesMap{
		"503": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 500, Message: "Unavailable"}},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/api/users", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Mix of success and errors, but mostly success
		statusCode := 200
		if i%100 == 0 {
			statusCode = 500 // 1% errors, different from override rule
		}
		res := createBenchmarkResponse(statusCode, "response")
		err := middleware.HandleResponse(rw, res, req, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRealWorld_HighTraffic_WithOverride(b *testing.B) {
	// Simulate scenario with occasional overrides
	overrides := apidef.ErrorOverridesMap{
		"5xx": []apidef.ErrorOverride{
			{
				Match:    &apidef.ErrorMatcher{Flag: errors.URS},
				Response: apidef.ErrorResponse{StatusCode: 503, Body: `{"error":"upstream_error"}`},
			},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/api/users", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Mix of success and errors
		statusCode := 200
		if i%50 == 0 {
			statusCode = 500 // 2% errors that match override
		}
		res := createBenchmarkResponse(statusCode, "response")
		err := middleware.HandleResponse(rw, res, req, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRealWorld_ComplexRuleset(b *testing.B) {
	// Simulate complex production configuration
	overrides := apidef.ErrorOverridesMap{
		"400": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 400, Body: `{"error":"bad_request"}`}},
		},
		"401": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 401, Body: `{"error":"unauthorized"}`}},
		},
		"403": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 403, Body: `{"error":"forbidden"}`}},
		},
		"404": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 404, Body: `{"error":"not_found"}`}},
		},
		"429": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 429, Body: `{"error":"rate_limited"}`}},
		},
		"500": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 500, Body: `{"error":"internal_error"}`}},
		},
		"502": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 502, Body: `{"error":"bad_gateway"}`}},
		},
		"503": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 503, Body: `{"error":"unavailable"}`}},
		},
		"504": []apidef.ErrorOverride{
			{Response: apidef.ErrorResponse{StatusCode: 504, Body: `{"error":"timeout"}`}},
		},
		"5xx": []apidef.ErrorOverride{
			{
				Match:    &apidef.ErrorMatcher{Flag: errors.URS},
				Response: apidef.ErrorResponse{StatusCode: 503, Body: `{"error":"upstream_error"}`},
			},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/api/data", nil)
	rw := httptest.NewRecorder()

	// Test various error codes
	errorCodes := []int{400, 401, 403, 404, 429, 500, 502, 503, 504, 505}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statusCode := errorCodes[i%len(errorCodes)]
		res := createBenchmarkResponse(statusCode, "error")
		err := middleware.HandleResponse(rw, res, req, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
