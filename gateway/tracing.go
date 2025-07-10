package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	reqHeader    = "====== Request ======"
	respHeader   = "====== Response ======"
	reqSeparator = "\n"
)

type traceHttpRequest struct {
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Body    string      `json:"body"`
	Headers http.Header `json:"headers"`
}

// TraceRequest is for tracing an HTTP request
// swagger:model TraceRequest
type traceRequest struct {
	Request *traceHttpRequest     `json:"request"`
	Spec    *apidef.APIDefinition `json:"spec"`
	OAS     *oas.OAS              `json:"oas"`
}

// TraceResponse is for tracing an HTTP response
// swagger:model TraceResponse
type traceResponse struct {
	Message  string `json:"message"`
	Response string `json:"response"`
	Logs     string `json:"logs"`
}

type traceLogEntry struct {
	ApiId   string       `json:"api_id,omitempty"`
	ApiName string       `json:"api_name,omitempty"`
	Level   string       `json:"level,omitempty"`
	Msg     string       `json:"msg,omitempty"`
	Mw      string       `json:"mw,omitempty"`
	OrgId   string       `json:"org_id,omitempty"`
	Ts      *time.Time   `json:"time,omitempty"`
	Code    int          `json:"code,omitempty"`
	Type    traceLogType `json:"type"`
}

type traceLogType string

func (s traceLogType) String() string {
	return string(s)
}

const (
	traceLogRequest  traceLogType = "request"
	traceLogResponse traceLogType = "response"
)

func (tr *traceResponse) parseTrace() (*http.Request, *http.Response, error) {
	return parseTrace(tr.Response)
}

// logs extract logs for unit test cases
func (tr *traceResponse) logs() ([]traceLogEntry, error) {
	var res []traceLogEntry
	scanner := bufio.NewScanner(bytes.NewReader([]byte(tr.Logs)))

	for scanner.Scan() {
		lineBytes := scanner.Bytes()

		if len(strings.TrimSpace(string(lineBytes))) == 0 {
			continue
		}

		var msg traceLogEntry
		if err := json.Unmarshal(lineBytes, &msg); err != nil {
			return nil, err
		}

		res = append(res, msg)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input: %w", err)
	}

	return res, nil
}

func (tr *traceRequest) toRequest(
	ctx context.Context,
	ignoreCanonicalMIMEHeaderKey bool,
) (*http.Request, error) {

	path, err := url.JoinPath(
		tr.Spec.Proxy.ListenPath,
		tr.Request.Path,
	)

	if err != nil {
		return nil, err
	}

	r, err := http.NewRequestWithContext(ctx, tr.Request.Method, path, strings.NewReader(tr.Request.Body))

	if err != nil {
		return nil, err
	}

	for key, values := range tr.Request.Headers {
		addCustomHeader(r.Header, key, values, ignoreCanonicalMIMEHeaderKey)
	}

	return r, nil
}

// Tracing request
// Used to test API definition by sending sample request,
// and analysisng output of both response and logs
//
// ---
// requestBody:
//
//	content:
//	  application/json:
//	    schema:
//	      "$ref": "#/definitions/traceRequest"
//	    examples:
//	      request:
//	        method: GET
//	        path: /get
//	        headers:
//	           Authorization: key
//	      spec:
//	        api_name: "Test"
//
// responses:
//
//	200:
//	  description: Success tracing request
//	  schema:
//	    "$ref": "#/definitions/traceResponse"
//	  examples:
//	    message: "ok"
//	    response:
//	      code: 200
//	      headers:
//	        Header: value
//	      body: body-value
//	    logs: {...}\n{...}
func (gw *Gateway) traceHandler(w http.ResponseWriter, r *http.Request) {
	var traceReq traceRequest
	if err := json.NewDecoder(r.Body).Decode(&traceReq); err != nil {
		log.Error("Couldn't decode trace request: ", err)
		doJSONWrite(w, http.StatusBadRequest, apiError("Request malformed"))
		return
	}

	if traceReq.OAS != nil {
		var newDef apidef.APIDefinition

		if err := traceReq.OAS.ExtractTo(&newDef); err != nil {
			log.Error("Failed to extract OAS")
			doJSONWrite(w, http.StatusBadRequest, apiError("Failed to extract OAS: "+err.Error()))
		}

		traceReq.Spec = &newDef
	}

	if traceReq.Spec == nil {
		log.Error("Spec field is missing")
		doJSONWrite(w, http.StatusBadRequest, apiError("Spec field is missing"))
		return
	}

	if traceReq.Request == nil {
		log.Error("Request field is missing")
		doJSONWrite(w, http.StatusBadRequest, apiError("Request field is missing"))
		return
	}

	var logStorage bytes.Buffer
	logger := logrus.New()
	logger.Formatter = &logrus.JSONFormatter{}
	logger.Level = logrus.DebugLevel
	logger.Out = &logStorage

	gs := gw.prepareStorage()

	loader := &APIDefinitionLoader{Gw: gw}
	traceReq.Spec.IsOAS = true

	spec, err := loader.MakeSpec(
		&model.MergedAPI{APIDefinition: traceReq.Spec, OAS: traceReq.OAS},
		logrus.NewEntry(logger),
	)

	if err != nil {
		doJSONWrite(w, http.StatusBadRequest, traceResponse{Message: "error", Logs: logStorage.String()})
		return
	}

	chainObj := gw.processSpec(
		spec,
		nil,
		&gs,
		logrus.NewEntry(logger),
		WithQuotaKey(spec.Checksum),
	)
	gw.generateSubRoutes(spec, mux.NewRouter())

	if chainObj.ThisHandler == nil {
		doJSONWrite(w, http.StatusBadRequest, traceResponse{Message: "error", Logs: logStorage.String()})
		return
	}

	wr := httptest.NewRecorder()
	tr, err := traceReq.toRequest(r.Context(), gw.GetConfig().IgnoreCanonicalMIMEHeaderKey)
	if err != nil {
		doJSONWrite(w, http.StatusInternalServerError, apiError("Unexpected failure: "+err.Error()))
		return
	}

	nopCloseRequestBody(tr)
	chainObj.ThisHandler.ServeHTTP(wr, tr)

	var response string
	if dump, err := httputil.DumpResponse(wr.Result(), true); err == nil {
		response = string(dump)
	} else {
		response = err.Error()
	}

	var request string
	if dump, err := httputil.DumpRequest(tr, true); err == nil {
		request = string(dump)
	} else {
		request = err.Error()
	}

	doJSONWrite(w, http.StatusOK, traceResponse{
		Message:  "ok",
		Response: makeTraceDump(request, response),
		Logs:     logStorage.String(),
	})
}

func makeTraceDump(request, response string) string {
	var sb strings.Builder
	sb.WriteString(reqHeader + reqSeparator)
	sb.WriteString(request)
	sb.WriteString(reqSeparator + respHeader + reqSeparator)
	sb.WriteString(response)
	return sb.String()
}

func parseTrace(tracedReqRes string) (req *http.Request, res *http.Response, err error) {
	tracedReqRes = strings.TrimPrefix(tracedReqRes, reqHeader+reqSeparator)
	parts := strings.Split(tracedReqRes, reqSeparator+respHeader+reqSeparator)

	if len(parts) != 2 {
		err = errors.New("invalid traced request response format")
		return
	}

	reqBuf := bufio.NewReader(strings.NewReader(parts[0]))
	if req, err = http.ReadRequest(reqBuf); err != nil {
		return
	}

	respBuf := bufio.NewReader(strings.NewReader(parts[1]))
	res, err = http.ReadResponse(respBuf, req)

	return
}
