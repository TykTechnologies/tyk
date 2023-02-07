package gateway

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
)

const (
	extractorValueInput = "testkey"

	extractorRegexExpr       = "prefix-(.*)"
	extractorRegexInput      = "prefix-testkey123"
	extractorRegexMatchIndex = 0

	extractorXPathExpr  = "//object/key"
	extractorXPathInput = "<object><key>thevalue</key></object>"

	extractorHeaderName = "testheader"
	extractorParamName  = "testparam"
)

func (ts *Test) createSpecTestFrom(tb testing.TB, def *apidef.APIDefinition) *APISpec {
	tb.Helper()
	loader := APIDefinitionLoader{Gw: ts.Gw}
	spec := loader.MakeSpec(&nestedApiDefinition{APIDefinition: def}, nil)
	tname := tb.Name()
	redisStore := &storage.RedisCluster{KeyPrefix: tname + "-apikey.", RedisController: ts.Gw.RedisController}
	healthStore := &storage.RedisCluster{KeyPrefix: tname + "-apihealth.", RedisController: ts.Gw.RedisController}
	orgStore := &storage.RedisCluster{KeyPrefix: tname + "-orgKey.", RedisController: ts.Gw.RedisController}
	spec.Init(redisStore, redisStore, healthStore, orgStore)
	return spec
}

func (ts *Test) prepareExtractor(tb testing.TB, extractorSource apidef.IdExtractorSource, extractorType apidef.IdExtractorType,
	config map[string]interface{}, disabled bool) (IdExtractor, *APISpec) {
	tb.Helper()
	def := &apidef.APIDefinition{
		OrgID: MockOrgID,
		CustomMiddleware: apidef.MiddlewareSection{
			IdExtractor: apidef.MiddlewareIdExtractor{
				Disabled:        disabled,
				ExtractFrom:     extractorSource,
				ExtractWith:     extractorType,
				ExtractorConfig: config,
			},
		},
	}

	spec := ts.createSpecTestFrom(tb, def)
	mw := BaseMiddleware{Spec: spec, Gw: ts.Gw}
	newExtractor(spec, mw)

	extractor, ok := spec.CustomMiddleware.IdExtractor.Extractor.(IdExtractor)
	if !ok {
		return nil, spec
	}

	return extractor, spec
}

func prepareHeaderExtractorRequest(headers map[string]string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	if headers == nil {
		return r
	}
	for k, v := range headers {
		r.Header.Add(k, v)
	}
	return r
}

func prepareBodyExtractorRequest(input string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(input))
	return r
}

func prepareExtractorFormRequest(values map[string]string) *http.Request {
	formData := url.Values{}
	if values != nil {
		for k, v := range values {
			formData.Set(k, v)
		}
	}
	r, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(formData.Encode()))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func (s *Test) GenerateSessionID(input string) string {
	data := []byte(input)
	tokenID := fmt.Sprintf("%x", md5.Sum(data))
	return s.Gw.generateToken(MockOrgID, tokenID)
}

func TestValueExtractor(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testSessionID := ts.GenerateSessionID(extractorValueInput)

	t.Run("HeaderSource", func(t *testing.T) {
		extractor, spec := ts.prepareExtractor(t, apidef.HeaderSource, apidef.ValueExtractor, map[string]interface{}{
			"header_name": extractorHeaderName,
		}, false)

		r := prepareHeaderExtractorRequest(nil)
		sessionID, overrides := extractor.ExtractAndCheck(r)
		if sessionID != "" {
			t.Fatalf("should return an empty session ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 400 {
			t.Fatalf("should return 400, got %d", overrides.ResponseCode)
		}

		r = prepareHeaderExtractorRequest(map[string]string{extractorHeaderName: extractorValueInput})
		sessionID, overrides = extractor.ExtractAndCheck(r)
		if sessionID != testSessionID {
			t.Fatalf("session ID doesn't match, expected %s, got %s", testSessionID, sessionID)
		}
		if storage.TokenOrg(sessionID) != spec.OrgID {
			t.Fatalf("session ID doesn't contain the org ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 0 {
			t.Fatalf("response code should be 0, got %d", overrides.ResponseCode)
		}
	})

	t.Run("FormSource", func(t *testing.T) {
		extractor, spec := ts.prepareExtractor(t, apidef.FormSource, apidef.ValueExtractor, map[string]interface{}{
			"param_name": extractorParamName,
		}, false)

		r := prepareExtractorFormRequest(nil)
		sessionID, overrides := extractor.ExtractAndCheck(r)
		if sessionID != "" {
			t.Fatalf("should return an empty session ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 400 {
			t.Fatalf("should return 400, got %d", overrides.ResponseCode)
		}

		r = prepareExtractorFormRequest(map[string]string{extractorParamName: extractorValueInput})
		sessionID, overrides = extractor.ExtractAndCheck(r)
		if sessionID != testSessionID {
			t.Fatalf("session ID doesn't match, expected %s, got %s", testSessionID, sessionID)
		}
		if storage.TokenOrg(sessionID) != spec.OrgID {
			t.Fatalf("session ID doesn't contain the org ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 0 {
			t.Fatalf("response code should be 0, got %d", overrides.ResponseCode)
		}
	})
}

func TestRegexExtractor(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testSessionID := ts.GenerateSessionID(extractorRegexInput)

	t.Run("HeaderSource", func(t *testing.T) {
		extractor, spec := ts.prepareExtractor(t, apidef.HeaderSource, apidef.RegexExtractor,
			map[string]interface{}{
				"regex_expression":  extractorRegexExpr,
				"regex_match_index": extractorRegexMatchIndex,
				"header_name":       extractorHeaderName,
			}, false)

		r := prepareHeaderExtractorRequest(nil)
		sessionID, overrides := extractor.ExtractAndCheck(r)
		if sessionID != "" {
			t.Fatalf("should return an empty session ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 400 {
			t.Fatalf("should return 400, got %d", overrides.ResponseCode)
		}

		r = prepareHeaderExtractorRequest(map[string]string{extractorHeaderName: extractorRegexInput})
		sessionID, overrides = extractor.ExtractAndCheck(r)
		if sessionID != testSessionID {
			t.Fatalf("session ID doesn't match, expected %s, got %s", testSessionID, sessionID)
		}
		if storage.TokenOrg(sessionID) != spec.OrgID {
			t.Fatalf("session ID doesn't contain the org ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 0 {
			t.Fatalf("response code should be 0, got %d", overrides.ResponseCode)
		}
	})

	t.Run("BodySource", func(t *testing.T) {
		extractor, spec := ts.prepareExtractor(t, apidef.BodySource, apidef.RegexExtractor,
			map[string]interface{}{
				"regex_expression":  extractorRegexExpr,
				"regex_match_index": extractorRegexMatchIndex,
			}, false)

		r := prepareBodyExtractorRequest("")
		sessionID, overrides := extractor.ExtractAndCheck(r)
		if sessionID != "" {
			t.Fatalf("should return an empty session ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 400 {
			t.Fatalf("should return 400, got %d", overrides.ResponseCode)
		}

		r = prepareBodyExtractorRequest(extractorRegexInput)
		sessionID, overrides = extractor.ExtractAndCheck(r)
		if sessionID != testSessionID {
			t.Fatalf("session ID doesn't match, expected %s, got %s", testSessionID, sessionID)
		}
		if storage.TokenOrg(sessionID) != spec.OrgID {
			t.Fatalf("session ID doesn't contain the org ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 0 {
			t.Fatalf("response code should be 0, got %d", overrides.ResponseCode)
		}
	})

	t.Run("FormSource", func(t *testing.T) {
		extractor, spec := ts.prepareExtractor(t, apidef.FormSource, apidef.RegexExtractor,
			map[string]interface{}{
				"regex_expression":  extractorRegexExpr,
				"regex_match_index": extractorRegexMatchIndex,
				"param_name":        extractorParamName,
			}, false)

		r := prepareExtractorFormRequest(nil)
		sessionID, overrides := extractor.ExtractAndCheck(r)
		if sessionID != "" {
			t.Fatalf("should return an empty session ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 400 {
			t.Fatalf("should return 400, got %d", overrides.ResponseCode)
		}

		r = prepareExtractorFormRequest(map[string]string{extractorParamName: extractorRegexInput})
		sessionID, overrides = extractor.ExtractAndCheck(r)
		if sessionID != testSessionID {
			t.Fatalf("session ID doesn't match, expected %s, got %s", testSessionID, sessionID)
		}
		if storage.TokenOrg(sessionID) != spec.OrgID {
			t.Fatalf("session ID doesn't contain the org ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 0 {
			t.Fatalf("response code should be 0, got %d", overrides.ResponseCode)
		}
	})
}

func TestXPathExtractor(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testSessionID := ts.GenerateSessionID("thevalue")

	t.Run("HeaderSource", func(t *testing.T) {
		extractor, spec := ts.prepareExtractor(t, apidef.HeaderSource, apidef.XPathExtractor,
			map[string]interface{}{
				"xpath_expression": extractorXPathExpr,
				"header_name":      extractorHeaderName,
			}, false)

		r := prepareHeaderExtractorRequest(nil)
		sessionID, overrides := extractor.ExtractAndCheck(r)
		if sessionID != "" {
			t.Fatalf("should return an empty session ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 400 {
			t.Fatalf("should return 400, got %d", overrides.ResponseCode)
		}

		r = prepareHeaderExtractorRequest(map[string]string{extractorHeaderName: extractorXPathInput})
		sessionID, overrides = extractor.ExtractAndCheck(r)
		if sessionID != testSessionID {
			t.Fatalf("session ID doesn't match, expected %s, got %s", testSessionID, sessionID)
		}
		if storage.TokenOrg(sessionID) != spec.OrgID {
			t.Fatalf("session ID doesn't contain the org ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 0 {
			t.Fatalf("response code should be 0, got %d", overrides.ResponseCode)
		}
	})

	t.Run("BodySource", func(t *testing.T) {
		extractor, spec := ts.prepareExtractor(t, apidef.BodySource, apidef.XPathExtractor,
			map[string]interface{}{
				"xpath_expression": extractorXPathExpr,
			}, false)

		r := prepareBodyExtractorRequest("")
		sessionID, overrides := extractor.ExtractAndCheck(r)
		if sessionID != "" {
			t.Fatalf("should return an empty session ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 400 {
			t.Fatalf("should return 400, got %d", overrides.ResponseCode)
		}

		r = prepareBodyExtractorRequest(extractorXPathInput)
		sessionID, overrides = extractor.ExtractAndCheck(r)
		if sessionID != testSessionID {
			t.Fatalf("session ID doesn't match, expected %s, got %s", testSessionID, sessionID)
		}
		if storage.TokenOrg(sessionID) != spec.OrgID {
			t.Fatalf("session ID doesn't contain the org ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 0 {
			t.Fatalf("response code should be 0, got %d", overrides.ResponseCode)
		}
	})

	t.Run("FormSource", func(t *testing.T) {
		extractor, spec := ts.prepareExtractor(t, apidef.FormSource, apidef.XPathExtractor,
			map[string]interface{}{
				"xpath_expression": extractorXPathExpr,
				"param_name":       extractorParamName,
			}, false)

		r := prepareExtractorFormRequest(nil)
		sessionID, overrides := extractor.ExtractAndCheck(r)
		if sessionID != "" {
			t.Fatalf("should return an empty session ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 400 {
			t.Fatalf("should return 400, got %d", overrides.ResponseCode)
		}

		r = prepareExtractorFormRequest(map[string]string{extractorParamName: extractorXPathInput})
		sessionID, overrides = extractor.ExtractAndCheck(r)
		if sessionID != testSessionID {
			t.Fatalf("session ID doesn't match, expected %s, got %s", testSessionID, sessionID)
		}
		if storage.TokenOrg(sessionID) != spec.OrgID {
			t.Fatalf("session ID doesn't contain the org ID, got %s", sessionID)
		}
		if overrides.ResponseCode != 0 {
			t.Fatalf("response code should be 0, got %d", overrides.ResponseCode)
		}
	})
}

func BenchmarkValueExtractor(b *testing.B) {
	b.Run("HeaderSource", func(b *testing.B) {
		b.ReportAllocs()

		ts := StartTest(nil)
		defer ts.Close()
		extractor, _ := ts.prepareExtractor(b, apidef.HeaderSource, apidef.ValueExtractor,
			map[string]interface{}{
				"header_name": extractorHeaderName,
			}, false)
		headers := map[string]string{extractorHeaderName: extractorValueInput}
		for i := 0; i < b.N; i++ {
			r := prepareHeaderExtractorRequest(headers)
			extractor.ExtractAndCheck(r)
		}
	})
	b.Run("FormSource", func(b *testing.B) {
		b.ReportAllocs()

		ts := StartTest(nil)
		defer ts.Close()
		extractor, _ := ts.prepareExtractor(b, apidef.FormSource, apidef.ValueExtractor,
			map[string]interface{}{
				"param_name": extractorParamName,
			}, false)
		params := map[string]string{extractorParamName: extractorValueInput}
		for i := 0; i < b.N; i++ {
			r := prepareExtractorFormRequest(params)
			extractor.ExtractAndCheck(r)
		}
	})
}

func BenchmarkRegexExtractor(b *testing.B) {
	b.Run("HeaderSource", func(b *testing.B) {
		b.ReportAllocs()
		ts := StartTest(nil)
		defer ts.Close()

		headerName := "testheader"
		extractor, _ := ts.prepareExtractor(b, apidef.HeaderSource, apidef.RegexExtractor,
			map[string]interface{}{
				"regex_expression":  extractorRegexExpr,
				"regex_match_index": extractorRegexMatchIndex,
				"header_name":       headerName,
			}, false)
		headers := map[string]string{extractorHeaderName: extractorRegexInput}
		for i := 0; i < b.N; i++ {
			r := prepareHeaderExtractorRequest(headers)
			extractor.ExtractAndCheck(r)
		}
	})
	b.Run("BodySource", func(b *testing.B) {
		b.ReportAllocs()
		ts := StartTest(nil)
		defer ts.Close()

		extractor, _ := ts.prepareExtractor(b, apidef.BodySource, apidef.RegexExtractor,
			map[string]interface{}{
				"regex_expression":  extractorRegexExpr,
				"regex_match_index": extractorRegexMatchIndex,
			}, false)
		for i := 0; i < b.N; i++ {
			r := prepareBodyExtractorRequest(extractorRegexInput)
			extractor.ExtractAndCheck(r)
		}
	})
	b.Run("FormSource", func(b *testing.B) {
		b.ReportAllocs()
		ts := StartTest(nil)
		defer ts.Close()

		extractor, _ := ts.prepareExtractor(b, apidef.FormSource, apidef.RegexExtractor,
			map[string]interface{}{
				"regex_expression":  extractorRegexExpr,
				"regex_match_index": extractorRegexMatchIndex,
				"param_name":        extractorParamName,
			}, false)
		params := map[string]string{extractorParamName: extractorRegexInput}
		for i := 0; i < b.N; i++ {
			r := prepareExtractorFormRequest(params)
			extractor.ExtractAndCheck(r)
		}
	})
}

func BenchmarkXPathExtractor(b *testing.B) {
	b.Run("HeaderSource", func(b *testing.B) {
		b.ReportAllocs()
		ts := StartTest(nil)
		defer ts.Close()

		extractor, _ := ts.prepareExtractor(b, apidef.HeaderSource, apidef.XPathExtractor, map[string]interface{}{
			"xpath_expression": extractorXPathExpr,
			"header_name":      extractorHeaderName,
		}, false)
		headers := map[string]string{extractorHeaderName: extractorXPathInput}
		for i := 0; i < b.N; i++ {
			r := prepareHeaderExtractorRequest(headers)
			extractor.ExtractAndCheck(r)
		}
	})
	b.Run("BodySource", func(b *testing.B) {
		b.ReportAllocs()
		ts := StartTest(nil)
		defer ts.Close()

		extractor, _ := ts.prepareExtractor(b, apidef.BodySource, apidef.XPathExtractor, map[string]interface{}{
			"xpath_expression": extractorXPathExpr,
		}, false)
		for i := 0; i < b.N; i++ {
			r := prepareBodyExtractorRequest(extractorXPathInput)
			extractor.ExtractAndCheck(r)
		}
	})
	b.Run("FormSource", func(b *testing.B) {
		b.ReportAllocs()
		ts := StartTest(nil)
		defer ts.Close()

		extractor, _ := ts.prepareExtractor(b, apidef.FormSource, apidef.XPathExtractor, map[string]interface{}{
			"xpath_expression": extractorXPathExpr,
			"param_name":       extractorParamName,
		}, false)
		params := map[string]string{extractorParamName: extractorXPathInput}
		for i := 0; i < b.N; i++ {
			r := prepareExtractorFormRequest(params)
			extractor.ExtractAndCheck(r)
		}
	})
}

func TestIDExtractorDisabled(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	extractor, _ := ts.prepareExtractor(t, apidef.HeaderSource, apidef.ValueExtractor, map[string]interface{}{
		"header_name": extractorHeaderName,
	}, true)
	assert.Nil(t, extractor)
}
