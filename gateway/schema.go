package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

type OASSchemaResponse struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Schema  json.RawMessage `json:"schema,omitempty"`
}

func (gw *Gateway) schemaHandler(w http.ResponseWriter, r *http.Request) {
	oasVersion := r.URL.Query().Get("oasVersion")

	var resp OASSchemaResponse
	var code = http.StatusOK

	switch r.Method {
	case http.MethodGet:

		data := oas.GetOASSchema(oasVersion)
		if data == nil {
			resp.Message = fmt.Sprintf("Schema not found for version %q", oasVersion)
			resp.Status = "Failed"
			code = http.StatusNotFound
			break
		}

		resp = OASSchemaResponse{
			Status: "Success",
			Schema: data,
		}

	}

	doJSONWrite(w, code, resp)
}
