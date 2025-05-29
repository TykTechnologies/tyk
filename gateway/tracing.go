package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/model"
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

	ctxSetTrace(r)

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
		traceReq.OAS.ExtractTo(&newDef)
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
	subrouter := mux.NewRouter()

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

	chainObj := gw.processSpec(spec, nil, &gs, logrus.NewEntry(logger))
	gw.generateSubRoutes(spec, subrouter, logrus.NewEntry(logger))

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

	spec.SetupMockOperation(tr)
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

	requestDump := "====== Request ======\n" + request + "\n====== Response ======\n" + response

	doJSONWrite(w, http.StatusOK, traceResponse{Message: "ok", Response: requestDump, Logs: logStorage.String()})
}
