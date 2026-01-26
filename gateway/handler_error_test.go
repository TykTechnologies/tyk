package gateway

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
	"github.com/TykTechnologies/tyk-pump/analytics"
)

func (s *Test) TestHandleError_text_xml(t *testing.T) {
	file := filepath.Join(s.Gw.GetConfig().TemplatePath, "error_500.xml")
	xml := `<?xml version = "1.0" encoding = "UTF-8"?>
<error>
	<code>500</code>
	<message>{{.Message}}</message>
</error>`
	err := ioutil.WriteFile(file, []byte(xml), 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file)
	expect := `<?xml version = "1.0" encoding = "UTF-8"?>
<error>
	<code>500</code>
	<message>There was a problem proxying the request</message>
</error>`

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})
	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML + "; charset=UTF-8",
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})
}

func TestHandleDefaultErrorXml(t *testing.T) {

	expect := `<?xml version = "1.0" encoding = "UTF-8"?>
<error>There was a problem proxying the request</error>`
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})
	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML + "; charset=UTF-8",
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})
}

func TestHandleDefaultErrorJSON(t *testing.T) {

	expect := `
{
    "error": "There was a problem proxying the request"
}
`

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})
	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.ApplicationJSON,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

}

type responseChainErrorHandler struct {
	BaseTykResponseHandler
	base          *BaseMiddleware
	responseCalls int
	errorCalls    int
}

func (h *responseChainErrorHandler) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (h *responseChainErrorHandler) Name() string {
	return "CustomMiddlewareResponseHook"
}

func (h *responseChainErrorHandler) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	h.responseCalls++
	return errors.New("response hook error")
}

func (h *responseChainErrorHandler) HandleError(rw http.ResponseWriter, req *http.Request) {
	h.errorCalls++
	handler := ErrorHandler{h.base.Copy()}
	handler.HandleError(rw, req, "Middleware error", http.StatusInternalServerError, true)
}

type responseChainModifier struct {
	BaseTykResponseHandler
	newStatus int
	newBody   string
}

func (h *responseChainModifier) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (h *responseChainModifier) Name() string {
	return "ResponseModifier"
}

func (h *responseChainModifier) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	if h.newStatus != 0 {
		res.StatusCode = h.newStatus
	}
	if h.newBody != "" {
		res.Body = ioutil.NopCloser(strings.NewReader(h.newBody))
	}
	return nil
}

func (h *responseChainModifier) HandleError(rw http.ResponseWriter, req *http.Request) {}

func TestHandleError_ResponseChainHeaders(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.GlobalResponseHeaders = map[string]string{
				"X-Test": "1",
			}
			v.GlobalResponseHeadersRemove = []string{header.XGenerator}
		})
	})
	spec := specs[0]

	handler := ErrorHandler{&BaseMiddleware{Spec: spec, Gw: ts.Gw}}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	recorder := httptest.NewRecorder()

	handler.HandleError(recorder, req, MsgAuthFieldMissing, http.StatusUnauthorized, true)

	resp := recorder.Result()
	if got := resp.Header.Get("X-Test"); got != "1" {
		t.Fatalf("expected X-Test header to be set, got %q", got)
	}
	if got := resp.Header.Get(header.XGenerator); got != "" {
		t.Fatalf("expected %s header to be removed, got %q", header.XGenerator, got)
	}
}

func TestHandleError_ResponseChainGuard(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})
	spec := specs[0]

	base := NewBaseMiddleware(ts.Gw, spec, nil, nil)
	handler := &responseChainErrorHandler{
		BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: ts.Gw},
		base:                   base,
	}
	spec.ResponseChain = []TykResponseHandler{handler}

	errHandler := ErrorHandler{base}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	recorder := httptest.NewRecorder()

	errHandler.HandleError(recorder, req, "Initial error", http.StatusBadRequest, true)

	if handler.responseCalls != 1 {
		t.Fatalf("expected response chain to run once, got %d", handler.responseCalls)
	}
	if handler.errorCalls != 1 {
		t.Fatalf("expected response hook error to be handled once, got %d", handler.errorCalls)
	}
}

type responseChainWriterHeaderHandler struct {
	BaseTykResponseHandler
}

func (h *responseChainWriterHeaderHandler) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (h *responseChainWriterHeaderHandler) Name() string {
	return "ResponseWriterHeaderHandler"
}

func (h *responseChainWriterHeaderHandler) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	rw.Header().Set("X-Writer", "1")
	return nil
}

type responseChainCountHandler struct {
	BaseTykResponseHandler
	responseCalls int
}

func (h *responseChainCountHandler) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (h *responseChainCountHandler) Name() string {
	return "ResponseCountHandler"
}

func (h *responseChainCountHandler) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	h.responseCalls++
	return nil
}

func (h *responseChainCountHandler) HandleError(rw http.ResponseWriter, req *http.Request) {}

func TestHandleError_ResponseChainWriterHeaders(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})
	spec := specs[0]

	handler := &responseChainWriterHeaderHandler{
		BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: ts.Gw},
	}
	spec.ResponseChain = []TykResponseHandler{handler}

	errHandler := ErrorHandler{NewBaseMiddleware(ts.Gw, spec, nil, nil)}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	recorder := httptest.NewRecorder()

	errHandler.HandleError(recorder, req, "Initial error", http.StatusBadRequest, true)

	resp := recorder.Result()
	if got := resp.Header.Get("X-Writer"); got != "1" {
		t.Fatalf("expected X-Writer header to be preserved, got %q", got)
	}
}

func TestHandleError_CustomBodyResponseSkipsResponseChain(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})
	spec := specs[0]

	handler := &responseChainCountHandler{
		BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: ts.Gw},
	}
	spec.ResponseChain = []TykResponseHandler{handler}

	errHandler := ErrorHandler{NewBaseMiddleware(ts.Gw, spec, nil, nil)}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	recorder := httptest.NewRecorder()

	recorder.WriteHeader(http.StatusTeapot)
	_, _ = recorder.WriteString("custom body")

	errHandler.HandleError(recorder, req, errCustomBodyResponse.Error(), http.StatusBadRequest, true)

	if handler.responseCalls != 0 {
		t.Fatalf("expected response chain to be skipped, got %d", handler.responseCalls)
	}

	resp := recorder.Result()
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("expected status %d, got %d", http.StatusTeapot, resp.StatusCode)
	}
	if string(bodyBytes) != "custom body" {
		t.Fatalf("expected body %q, got %q", "custom body", string(bodyBytes))
	}
}

type responseChainNoopHandler struct {
	BaseTykResponseHandler
}

func (h *responseChainNoopHandler) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (h *responseChainNoopHandler) Name() string {
	return "NoopResponseHandler"
}

func (h *responseChainNoopHandler) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	return nil
}

type responseChainMutatingHandler struct {
	BaseTykResponseHandler
}

func (h *responseChainMutatingHandler) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (h *responseChainMutatingHandler) Name() string {
	return "MutatingResponseHandler"
}

func (h *responseChainMutatingHandler) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	overrideBody := `{"override":"1"}`
	res.StatusCode = http.StatusTeapot
	res.Body = ioutil.NopCloser(strings.NewReader(overrideBody))
	return nil
}

func TestHandleError_ResponseChainNoopPreservesBodyAndStatus(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})
	spec := specs[0]

	handler := &responseChainNoopHandler{
		BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: ts.Gw},
	}
	spec.ResponseChain = []TykResponseHandler{handler}

	errHandler := ErrorHandler{NewBaseMiddleware(ts.Gw, spec, nil, nil)}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	recorder := httptest.NewRecorder()

	errHandler.HandleError(recorder, req, "Initial error", http.StatusBadRequest, true)

	resp := recorder.Result()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
	if !strings.Contains(body, "Initial error") {
		t.Fatalf("expected response body to contain error message, got %q", body)
	}
}

func TestHandleError_ResponseChainMutatesBodyAndStatus(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})
	spec := specs[0]

	handler := &responseChainMutatingHandler{
		BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: ts.Gw},
	}
	spec.ResponseChain = []TykResponseHandler{handler}

	errHandler := ErrorHandler{NewBaseMiddleware(ts.Gw, spec, nil, nil)}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	recorder := httptest.NewRecorder()

	errHandler.HandleError(recorder, req, "Initial error", http.StatusBadRequest, true)

	resp := recorder.Result()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("expected status %d, got %d", http.StatusTeapot, resp.StatusCode)
	}
	if !strings.Contains(body, `"override":"1"`) {
		t.Fatalf("expected response body override, got %q", body)
	}
}

func TestHandleError_ResponseChainGuardRecordsAnalytics(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})
	spec := specs[0]

	base := NewBaseMiddleware(ts.Gw, spec, nil, nil)
	handler := &responseChainErrorHandler{
		BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: ts.Gw},
		base:                   base,
	}
	spec.ResponseChain = []TykResponseHandler{handler}

	var (
		recordCount int
		recordCode  int
	)
	ts.Gw.Analytics.mockEnabled = true
	ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
		recordCount++
		recordCode = record.ResponseCode
	}

	errHandler := ErrorHandler{base}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	recorder := httptest.NewRecorder()

	errHandler.HandleError(recorder, req, "Initial error", http.StatusBadRequest, true)

	if recordCount != 1 {
		t.Fatalf("expected 1 analytics record, got %d", recordCount)
	}
	if recordCode != http.StatusInternalServerError {
		t.Fatalf("expected analytics status %d, got %d", http.StatusInternalServerError, recordCode)
	}
}

func TestHandleError_ResponseChainModifiesStatusCode(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})
	spec := specs[0]

	modifier := &responseChainModifier{
		BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: ts.Gw},
		newStatus:              http.StatusTeapot, // 418
	}
	spec.ResponseChain = []TykResponseHandler{modifier}

	base := NewBaseMiddleware(ts.Gw, spec, nil, nil)
	errHandler := ErrorHandler{base}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	recorder := httptest.NewRecorder()

	errHandler.HandleError(recorder, req, MsgAuthFieldMissing, http.StatusUnauthorized, true)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("expected status %d, got %d", http.StatusTeapot, resp.StatusCode)
	}
}

func TestHandleError_ResponseChainModifiesBody(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})
	spec := specs[0]

	customBody := `{"error":"custom error","request_id":"abc123"}`
	modifier := &responseChainModifier{
		BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: ts.Gw},
		newBody:                customBody,
	}
	spec.ResponseChain = []TykResponseHandler{modifier}

	base := NewBaseMiddleware(ts.Gw, spec, nil, nil)
	errHandler := ErrorHandler{base}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	recorder := httptest.NewRecorder()

	errHandler.HandleError(recorder, req, MsgAuthFieldMissing, http.StatusUnauthorized, true)

	resp := recorder.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	if string(body) != customBody {
		t.Fatalf("expected body %q, got %q", customBody, string(body))
	}
}

func TestHandleError_ResponseChainModifiesStatusAndBody(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})
	spec := specs[0]

	customBody := `{"error":"forbidden","code":403}`
	modifier := &responseChainModifier{
		BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: ts.Gw},
		newStatus:              http.StatusForbidden,
		newBody:                customBody,
	}
	spec.ResponseChain = []TykResponseHandler{modifier}

	base := NewBaseMiddleware(ts.Gw, spec, nil, nil)
	errHandler := ErrorHandler{base}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	recorder := httptest.NewRecorder()

	errHandler.HandleError(recorder, req, MsgAuthFieldMissing, http.StatusUnauthorized, true)

	resp := recorder.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, resp.StatusCode)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	if string(body) != customBody {
		t.Fatalf("expected body %q, got %q", customBody, string(body))
	}
}
