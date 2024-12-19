package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
)

const debugTag = "Debug"

func DebugApi(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/debug",
		OperationID: "debugApiDefinition",
		Tag:         debugTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.StatusBadRequest("Request malformed")
	op.AddReqWithSeparateExample(new(traceRequest), map[string]interface{}{"spec": minimalApis[0], "request": traceHttpRequest{
		Method: "GET",
		Path:   "/update-listen-path",
	}})
	oc.SetSummary("Test an an API definition.")
	oc.SetDescription("Used to test API definition by sending sample request and analysing output of both response and logs.")
	op.StatusInternalServerError("Unexpected failure:")
	op.AddRespWithExample(traceResponse{
		Message:  "ok",
		Response: "====== Request ======\nGET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n\n====== Response...",
		Logs:     "{\"level\":\"warning\",\"msg\":\"Legacy path detected! Upgrade to extended....",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Success tracing request."
	})

	return op.AddOperation()
}

type traceRequest struct {
	Request *traceHttpRequest     `json:"request"`
	Spec    *apidef.APIDefinition `json:"spec"`
}

type traceHttpRequest struct {
	Method  string      `json:"method" example:"GET"`
	Path    string      `json:"path" example:"/keyless-test/"`
	Body    string      `json:"body,omitempty"`
	Headers http.Header `json:"headers,omitempty"`
}

type traceResponse struct {
	Message  string `json:"message" example:"ok"`
	Response string `json:"response" example:"====== Request ======\nGET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n\n====== Response..."`
	Logs     string `json:"logs" example:"{\"level\":\"warning\",\"msg\":\"Legacy path detected! Upgrade to extended...."`
}
