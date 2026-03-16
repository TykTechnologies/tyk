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

func createBenchmarkGateway(overrides config.ErrorOverridesMap) *Gateway {
	gw := &Gateway{}
	compiled := CompileErrorOverrides(overrides)
	if compiled != nil {
		gw.SetCompiledErrorOverrides(compiled)
	}
	return gw
}

func createBenchmarkMiddleware(overrides config.ErrorOverridesMap) *ResponseErrorOverrideMiddleware {
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
	overrides := config.ErrorOverridesMap{
		"404": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 404, Message: "Not found"}},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return nil })
	}
}

func BenchmarkApplyUpstreamOverride_ExactMatch_NoBody(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"503": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 500, Message: "Service unavailable"}},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(503, func() []byte { return nil })
	}
}

func BenchmarkApplyUpstreamOverride_PatternMatch_5xx(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"5xx": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 503, Message: "Server error"}},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(502, func() []byte { return nil })
	}
}

func BenchmarkApplyUpstreamOverride_URSFlag(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"5xx": []config.ErrorOverride{
			{
				Match:    &config.ErrorMatcher{Flag: errors.URS},
				Response: config.ErrorResponse{Code: 503, Message: "Upstream error"},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return nil })
	}
}

func BenchmarkApplyUpstreamOverride_BodyFieldMatch(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"5xx": []config.ErrorOverride{
			{
				Match: &config.ErrorMatcher{
					BodyField: "error.type",
					BodyValue: "timeout",
				},
				Response: config.ErrorResponse{Code: 504, Message: "Timeout"},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)
	body := []byte(`{"error": {"type": "timeout", "message": "request timed out"}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return body })
	}
}

func BenchmarkApplyUpstreamOverride_MessagePatternMatch(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"5xx": []config.ErrorOverride{
			{
				Match: &config.ErrorMatcher{
					MessagePattern: "database.*unavailable",
				},
				Response: config.ErrorResponse{Code: 503, Message: "DB down"},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)
	body := []byte("database connection unavailable")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return body })
	}
}

func BenchmarkApplyUpstreamOverride_MultipleRules_FirstMatch(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"500": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 503, Message: "First"}},
			{Response: config.ErrorResponse{Code: 503, Message: "Second"}},
			{Response: config.ErrorResponse{Code: 503, Message: "Third"}},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return nil })
	}
}

func BenchmarkApplyUpstreamOverride_MultipleRules_LastMatch(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"500": []config.ErrorOverride{
			{
				Match:    &config.ErrorMatcher{Flag: errors.AKI},
				Response: config.ErrorResponse{Message: "Skip 1"},
			},
			{
				Match:    &config.ErrorMatcher{Flag: errors.RLT},
				Response: config.ErrorResponse{Message: "Skip 2"},
			},
			{
				Response: config.ErrorResponse{Code: 503, Message: "Match"},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.ApplyUpstreamOverride(500, func() []byte { return nil })
	}
}

// Benchmark: Full middleware HandleResponse

func BenchmarkHandleResponse_NoOverride_Passthrough(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"404": []config.ErrorOverride{
			{Response: config.ErrorResponse{Message: "Not found"}},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := createBenchmarkResponse(500, `{"error": "internal server error"}`)
		_ = middleware.HandleResponse(rw, res, req, nil)
	}
}

func BenchmarkHandleResponse_SuccessResponse_Skip(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"500": []config.ErrorOverride{
			{Response: config.ErrorResponse{Message: "Error"}},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := createBenchmarkResponse(200, `{"success": true}`)
		_ = middleware.HandleResponse(rw, res, req, nil)
	}
}

func BenchmarkHandleResponse_ExactMatch_StatusOnly(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"503": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 500, Message: "Unavailable"}},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := createBenchmarkResponse(503, "Service unavailable")
		_ = middleware.HandleResponse(rw, res, req, nil)
	}
}

func BenchmarkHandleResponse_ExactMatch_WithBody(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"503": []config.ErrorOverride{
			{
				Response: config.ErrorResponse{
					Code:    500,
					Body:    "Custom error message",
					Headers: map[string]string{"Retry-After": "60"},
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
		_ = middleware.HandleResponse(rw, res, req, nil)
	}
}

func BenchmarkHandleResponse_PatternMatch_SmallBody(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"5xx": []config.ErrorOverride{
			{
				Match: &config.ErrorMatcher{
					BodyField: "error.code",
					BodyValue: "TIMEOUT",
				},
				Response: config.ErrorResponse{Code: 504, Message: "Timeout"},
			},
		},
	}

	middleware := createBenchmarkMiddleware(overrides)
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := createBenchmarkResponse(500, `{"error": {"code": "TIMEOUT"}}`)
		_ = middleware.HandleResponse(rw, res, req, nil)
	}
}

func BenchmarkHandleResponse_PatternMatch_LargeBody(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"5xx": []config.ErrorOverride{
			{
				Match: &config.ErrorMatcher{
					MessagePattern: "database.*error",
				},
				Response: config.ErrorResponse{Code: 503, Message: "DB error"},
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
		_ = middleware.HandleResponse(rw, res, req, nil)
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
	overrides := config.ErrorOverridesMap{}

	// Create many rules for status 500
	rules := make([]config.ErrorOverride, ruleCount)
	for i := 0; i < ruleCount; i++ {
		rules[i] = config.ErrorOverride{
			Response: config.ErrorResponse{
				Code:    500,
				Message: fmt.Sprintf("Rule %d", i),
			},
		}
	}
	overrides["500"] = rules

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)
	compiled := gw.GetCompiledErrorOverrides()

	// Match last rule to test worst-case
	matchCount := 0

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchCount = 0
		_ = eo.findMatchingRuleGeneric(compiled, 500, func(rule *config.ErrorOverride) bool {
			matchCount++
			return matchCount == ruleCount // Match last rule
		})
	}
}

// Benchmark: HasRulesForStatus optimization

func BenchmarkHasRulesForStatus_ExactMatch(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"500": []config.ErrorOverride{{Response: config.ErrorResponse{Message: "Error"}}},
		"503": []config.ErrorOverride{{Response: config.ErrorResponse{Message: "Error"}}},
		"504": []config.ErrorOverride{{Response: config.ErrorResponse{Message: "Error"}}},
	}

	compiled := CompileErrorOverrides(overrides)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = compiled.HasRulesForStatus(500)
	}
}

func BenchmarkHasRulesForStatus_PatternMatch(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"5xx": []config.ErrorOverride{{Response: config.ErrorResponse{Message: "Error"}}},
	}

	compiled := CompileErrorOverrides(overrides)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = compiled.HasRulesForStatus(502)
	}
}

func BenchmarkHasRulesForStatus_NoMatch(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"404": []config.ErrorOverride{{Response: config.ErrorResponse{Message: "Error"}}},
	}

	compiled := CompileErrorOverrides(overrides)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = compiled.HasRulesForStatus(500)
	}
}

// Benchmark: matchesUpstreamCriteria variations

func BenchmarkMatchesUpstreamCriteria_NoCriteria(b *testing.B) {
	gw := createBenchmarkGateway(config.ErrorOverridesMap{})
	eo := NewErrorOverrides(nil, gw)
	rule := &config.ErrorOverride{Match: nil}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.matchesUpstreamCriteria(rule, nil, 500)
	}
}

func BenchmarkMatchesUpstreamCriteria_URSFlag(b *testing.B) {
	gw := createBenchmarkGateway(config.ErrorOverridesMap{})
	eo := NewErrorOverrides(nil, gw)
	rule := &config.ErrorOverride{
		Match: &config.ErrorMatcher{Flag: errors.URS},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.matchesUpstreamCriteria(rule, nil, 500)
	}
}

func BenchmarkMatchesUpstreamCriteria_BodyField_SmallJSON(b *testing.B) {
	gw := createBenchmarkGateway(config.ErrorOverridesMap{})
	eo := NewErrorOverrides(nil, gw)
	rule := &config.ErrorOverride{
		Match: &config.ErrorMatcher{
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
	gw := createBenchmarkGateway(config.ErrorOverridesMap{})
	eo := NewErrorOverrides(nil, gw)
	rule := &config.ErrorOverride{
		Match: &config.ErrorMatcher{
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
	overrides := config.ErrorOverridesMap{
		"500": []config.ErrorOverride{
			{
				Match: &config.ErrorMatcher{
					MessagePattern: "timeout",
				},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)
	compiled := gw.GetCompiledErrorOverrides()
	rule := compiled.ByExactCode[500][0]
	body := []byte("connection timeout error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eo.matchesUpstreamCriteria(rule, body, 500)
	}
}

func BenchmarkMatchesUpstreamCriteria_MessagePattern_ComplexRegex(b *testing.B) {
	overrides := config.ErrorOverridesMap{
		"500": []config.ErrorOverride{
			{
				Match: &config.ErrorMatcher{
					MessagePattern: `(database|db|mysql|postgres).*?(connection|timeout|unavailable|error)`,
				},
			},
		},
	}

	gw := createBenchmarkGateway(overrides)
	eo := NewErrorOverrides(nil, gw)
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
	middleware := createBenchmarkMiddleware(config.ErrorOverridesMap{
		"500": []config.ErrorOverride{{}},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := &http.Response{StatusCode: 200}
		_ = middleware.shouldProcessResponse(res)
	}
}

func BenchmarkShouldProcessResponse_FastPath_NoConfig(b *testing.B) {
	middleware := createBenchmarkMiddleware(config.ErrorOverridesMap{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := &http.Response{StatusCode: 500}
		_ = middleware.shouldProcessResponse(res)
	}
}

func BenchmarkShouldProcessResponse_Error(b *testing.B) {
	middleware := createBenchmarkMiddleware(config.ErrorOverridesMap{
		"500": []config.ErrorOverride{{}},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := &http.Response{StatusCode: 500}
		_ = middleware.shouldProcessResponse(res)
	}
}

// Benchmark: Memory allocations

func BenchmarkCreateOverrideResult(b *testing.B) {
	gw := createBenchmarkGateway(config.ErrorOverridesMap{})
	eo := NewErrorOverrides(nil, gw)
	rule := &config.ErrorOverride{
		Response: config.ErrorResponse{
			Code:    503,
			Message: "Service unavailable",
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
	gw := createBenchmarkGateway(config.ErrorOverridesMap{})
	eo := NewErrorOverrides(nil, gw)
	rule := &config.ErrorOverride{
		Match: &config.ErrorMatcher{
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
	overrides := config.ErrorOverridesMap{
		"503": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 500, Message: "Unavailable"}},
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
		_ = middleware.HandleResponse(rw, res, req, nil)
	}
}

func BenchmarkRealWorld_HighTraffic_WithOverride(b *testing.B) {
	// Simulate scenario with occasional overrides
	overrides := config.ErrorOverridesMap{
		"5xx": []config.ErrorOverride{
			{
				Match:    &config.ErrorMatcher{Flag: errors.URS},
				Response: config.ErrorResponse{Code: 503, Message: "Upstream error"},
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
		_ = middleware.HandleResponse(rw, res, req, nil)
	}
}

func BenchmarkRealWorld_ComplexRuleset(b *testing.B) {
	// Simulate complex production configuration
	overrides := config.ErrorOverridesMap{
		"400": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 400, Message: "Bad request"}},
		},
		"401": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 401, Message: "Unauthorized"}},
		},
		"403": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 403, Message: "Forbidden"}},
		},
		"404": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 404, Message: "Not found"}},
		},
		"429": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 429, Message: "Rate limited"}},
		},
		"500": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 500, Message: "Internal error"}},
		},
		"502": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 502, Message: "Bad gateway"}},
		},
		"503": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 503, Message: "Unavailable"}},
		},
		"504": []config.ErrorOverride{
			{Response: config.ErrorResponse{Code: 504, Message: "Timeout"}},
		},
		"5xx": []config.ErrorOverride{
			{
				Match:    &config.ErrorMatcher{Flag: errors.URS},
				Response: config.ErrorResponse{Code: 503, Message: "Upstream error"},
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
		_ = middleware.HandleResponse(rw, res, req, nil)
	}
}
