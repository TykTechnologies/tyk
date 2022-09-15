package gateway

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

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

func (ts *Test) createSpecTestFrom(t testing.TB, def *apidef.APIDefinition) *APISpec {
	loader := APIDefinitionLoader{Gw: ts.Gw}
	spec := loader.MakeSpec(&nestedApiDefinition{APIDefinition: def}, nil)
	tname := t.Name()
	redisStore := &storage.RedisCluster{KeyPrefix: tname + "-apikey.", RedisController: ts.Gw.RedisController}
	healthStore := &storage.RedisCluster{KeyPrefix: tname + "-apihealth.", RedisController: ts.Gw.RedisController}
	orgStore := &storage.RedisCluster{KeyPrefix: tname + "-orgKey.", RedisController: ts.Gw.RedisController}
	spec.Init(redisStore, redisStore, healthStore, orgStore)
	return spec
}

func (ts *Test) prepareExtractor(t testing.TB, extractorSource apidef.IdExtractorSource, extractorType apidef.IdExtractorType, config map[string]interface{}) (IdExtractor, *APISpec) {

	def := &apidef.APIDefinition{
		OrgID: MockOrgID,
		CustomMiddleware: apidef.MiddlewareSection{
			IdExtractor: apidef.MiddlewareIdExtractor{
				ExtractFrom:     extractorSource,
				ExtractWith:     extractorType,
				ExtractorConfig: config,
			},
		},
	}

	spec := ts.createSpecTestFrom(t, def)
	mw := BaseMiddleware{Spec: spec, Gw: ts.Gw}
	newExtractor(spec, mw)
	return spec.CustomMiddleware.IdExtractor.Extractor.(IdExtractor), spec
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
		})

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
		})

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
		extractor, spec := ts.prepareExtractor(t, apidef.HeaderSource, apidef.RegexExtractor, map[string]interface{}{
			"regex_expression":  extractorRegexExpr,
			"regex_match_index": extractorRegexMatchIndex,
			"header_name":       extractorHeaderName,
		})

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
		extractor, spec := ts.prepareExtractor(t, apidef.BodySource, apidef.RegexExtractor, map[string]interface{}{
			"regex_expression":  extractorRegexExpr,
			"regex_match_index": extractorRegexMatchIndex,
		})

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
		extractor, spec := ts.prepareExtractor(t, apidef.FormSource, apidef.RegexExtractor, map[string]interface{}{
			"regex_expression":  extractorRegexExpr,
			"regex_match_index": extractorRegexMatchIndex,
			"param_name":        extractorParamName,
		})

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
		extractor, spec := ts.prepareExtractor(t, apidef.HeaderSource, apidef.XPathExtractor, map[string]interface{}{
			"xpath_expression": extractorXPathExpr,
			"header_name":      extractorHeaderName,
		})

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
		extractor, spec := ts.prepareExtractor(t, apidef.BodySource, apidef.XPathExtractor, map[string]interface{}{
			"xpath_expression": extractorXPathExpr,
		})

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
		extractor, spec := ts.prepareExtractor(t, apidef.FormSource, apidef.XPathExtractor, map[string]interface{}{
			"xpath_expression": extractorXPathExpr,
			"param_name":       extractorParamName,
		})

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
		extractor, _ := ts.prepareExtractor(b, apidef.HeaderSource, apidef.ValueExtractor, map[string]interface{}{
			"header_name": extractorHeaderName,
		})
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
		extractor, _ := ts.prepareExtractor(b, apidef.FormSource, apidef.ValueExtractor, map[string]interface{}{
			"param_name": extractorParamName,
		})
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
		extractor, _ := ts.prepareExtractor(b, apidef.HeaderSource, apidef.RegexExtractor, map[string]interface{}{
			"regex_expression":  extractorRegexExpr,
			"regex_match_index": extractorRegexMatchIndex,
			"header_name":       headerName,
		})
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

		extractor, _ := ts.prepareExtractor(b, apidef.BodySource, apidef.RegexExtractor, map[string]interface{}{
			"regex_expression":  extractorRegexExpr,
			"regex_match_index": extractorRegexMatchIndex,
		})
		for i := 0; i < b.N; i++ {
			r := prepareBodyExtractorRequest(extractorRegexInput)
			extractor.ExtractAndCheck(r)
		}
	})
	b.Run("FormSource", func(b *testing.B) {
		b.ReportAllocs()
		ts := StartTest(nil)
		defer ts.Close()

		extractor, _ := ts.prepareExtractor(b, apidef.FormSource, apidef.RegexExtractor, map[string]interface{}{
			"regex_expression":  extractorRegexExpr,
			"regex_match_index": extractorRegexMatchIndex,
			"param_name":        extractorParamName,
		})
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
		})
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
		})
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
		})
		params := map[string]string{extractorParamName: extractorXPathInput}
		for i := 0; i < b.N; i++ {
			r := prepareExtractorFormRequest(params)
			extractor.ExtractAndCheck(r)
		}
	})
}
