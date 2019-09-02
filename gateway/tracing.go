package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
)

type traceHttpRequest struct {
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Body    string      `json:"body"`
	Headers http.Header `json:"headers"`
}

func (tr *traceHttpRequest) toRequest() *http.Request {
	r := httptest.NewRequest(tr.Method, tr.Path, strings.NewReader(tr.Body))
	r.Header = tr.Headers
	ctxSetTrace(r)

	return r
}

// TraceRequest is for tracing an HTTP request
// swagger:model TraceRequest
type traceRequest struct {
	Request *traceHttpRequest     `json:"request"`
	Spec    *apidef.APIDefinition `json:"spec"`
}

// TraceResponse is for tracing an HTTP response
// swagger:model TraceResponse
type traceResponse struct {
	Message  string `json:"message"`
	Response string `json:"response"`
	Logs     string `json:"logs"`
}

// Tracing request
// Used to test API definition by sending sample request,
// and analysisng output of both response and logs
//
//---
// requestBody:
//   content:
//     application/json:
//       schema:
//         "$ref": "#/definitions/traceRequest"
//       examples:
//         request:
//           method: GET
//           path: /get
//           headers:
//              Authorization: key
//         spec:
//           api_name: "Test"
// responses:
//   200:
//     description: Success tracing request
//     schema:
//       "$ref": "#/definitions/traceResponse"
//     examples:
//       message: "ok"
//       response:
//         code: 200
//         headers:
//           Header: value
//         body: body-value
//       logs: {...}\n{...}
func traceHandler(w http.ResponseWriter, r *http.Request) {
	var traceReq traceRequest
	if err := json.NewDecoder(r.Body).Decode(&traceReq); err != nil {
		log.Error("Couldn't decode trace request: ", err)

		doJSONWrite(w, http.StatusBadRequest, apiError("Request malformed"))
		return
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

	gs := prepareStorage()
	subrouter := mux.NewRouter()

	loader := &APIDefinitionLoader{}
	spec := loader.MakeSpec(traceReq.Spec, logrus.NewEntry(logger))

	chainObj := processSpec(spec, nil, &gs, subrouter, logrus.NewEntry(logger))
	spec.middlewareChain = chainObj

	if chainObj.ThisHandler == nil {
		doJSONWrite(w, http.StatusBadRequest, traceResponse{Message: "error", Logs: logStorage.String()})
		return
	}

	wr := httptest.NewRecorder()
	chainObj.ThisHandler.ServeHTTP(wr, traceReq.Request.toRequest())

	var response string
	if dump, err := httputil.DumpResponse(wr.Result(), true); err == nil {
		response = string(dump)
	} else {
		response = err.Error()
	}

	doJSONWrite(w, http.StatusOK, traceResponse{Message: "ok", Response: response, Logs: logStorage.String()})
}
