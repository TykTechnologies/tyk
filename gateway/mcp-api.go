package gateway

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/mcp"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/getkin/kin-openapi/openapi3"
)

// extractMCPObjFromReq extracts and parses MCP API definition from request body.
// MCP APIs are OAS-based, so we reuse the oas.OAS structure.
func extractMCPObjFromReq(reqBody io.Reader) ([]byte, *oas.OAS, error) {
	var mcpObj oas.OAS
	reqBodyInBytes, err := ioutil.ReadAll(reqBody)
	if err != nil {
		return nil, nil, ErrRequestMalformed
	}

	loader := openapi3.NewLoader()
	t, err := loader.LoadFromData(reqBodyInBytes)
	if err != nil {
		return nil, nil, ErrRequestMalformed
	}

	mcpObj.T = *t

	return reqBodyInBytes, &mcpObj, nil
}

// validateMCP validates MCP API definitions.
// Similar to validateOAS but with stricter MCP-specific validation:
// - No import endpoint support (MCP APIs must be fully specified)
// - Uses mcp.ValidateMCPObject for MCP protocol validation
// - MCP-specific Tyk extension fields are validated
func (gw *Gateway) validateMCP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqBodyInBytes, mcpObj, err := extractMCPObjFromReq(r.Body)

		if err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		// MCP APIs MUST have Tyk extension (no import mode)
		if (r.Method == http.MethodPost || r.Method == http.MethodPut) && mcpObj.GetTykExtension() == nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(apidef.ErrPayloadWithoutTykExtension.Error()))
			return
		}

		// Validate against MCP-specific schema
		if err = mcp.ValidateMCPObject(reqBodyInBytes, mcpObj.OpenAPI); err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		// Additional business logic validation
		if err = mcpObj.Validate(r.Context(), oas.GetValidationOptionsFromConfig(gw.GetConfig().OAS)...); err != nil {
			doJSONWrite(w, http.StatusBadRequest, apiError(err.Error()))
			return
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(reqBodyInBytes))
		next.ServeHTTP(w, r)
	}
}
