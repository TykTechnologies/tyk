package gateway

import (
	"encoding/json"
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

		data, err := oas.GetOASSchema(oasVersion)
		if err != nil {
			resp.Message = err.Error()
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
