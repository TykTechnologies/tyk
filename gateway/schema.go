package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

type OASSchemaResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Schema  *openapi3.T `json:"schema,omitempty"`
}

func (gw *Gateway) schemaHandler(w http.ResponseWriter, r *http.Request) {
	oasVersion := r.URL.Query().Get("oasVersion")

	if oasVersion == "" {
		doJSONWrite(w, http.StatusBadRequest, OASSchemaResponse{Message: "Should provide a value for parameter oasVersion", Status: "Failed"})
		return
	}

	var resp OASSchemaResponse
	var code = http.StatusOK

	switch r.Method {
	case http.MethodGet:

		data := oas.GetOASSchema(oasVersion)
		if data == nil {
			resp.Message = fmt.Sprintf("Schema not found for version %s", oasVersion)
			resp.Status = "Failed"
			code = http.StatusNotFound
			break
		}

		schema := openapi3.T{}
		_ = json.Unmarshal(data, &schema)

		resp = OASSchemaResponse{
			Status: "Success",
			Schema: &schema,
		}

	}

	doJSONWrite(w, code, resp)
}
