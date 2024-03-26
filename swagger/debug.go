package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
)

const debugTag = "Debug"

func DebugApi(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/debug")
	if err != nil {
		return err
	}
	oc.SetTags(debugTag)
	forbidden(oc)
	statusBadRequest(oc, "Request malformed , missing spec field or missing request field")
	oc.AddReqStructure(new(traceRequest), func(cu *openapi.ContentUnit) {
	})
	oc.SetSummary("Tracing request")
	oc.SetDescription("Used to test API definition by sending sample request and analysing output of both response and logs")
	statusInternalServerError(oc, "Unexpected failure")
	oc.AddRespStructure(new(traceResponse), func(cu *openapi.ContentUnit) {
		cu.Description = "Success tracing request"
	})
	return r.AddOperation(oc)
}

type traceRequest struct {
	Request *traceHttpRequest     `json:"request"`
	Spec    *apidef.APIDefinition `json:"spec"`
}

type traceHttpRequest struct {
	Method  string      `json:"method" example:"GET"`
	Path    string      `json:"path" example:"/keyless-test/"`
	Body    string      `json:"body"`
	Headers http.Header `json:"headers"`
}

type traceResponse struct {
	Message  string `json:"message" example:"ok"`
	Response string `json:"response" example:"====== Request ======\nGET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n\n====== Response..."`
	Logs     string `json:"logs" example:"{\"level\":\"warning\",\"msg\":\"Legacy path detected! Upgrade to extended...."`
}
