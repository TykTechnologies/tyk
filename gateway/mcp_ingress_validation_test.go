package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/stretchr/testify/require"
)

func TestMCPIngressNativeAndSyntheticSupport(t *testing.T) {
	for _, synthetic := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "synthetic"}[synthetic], func(t *testing.T) {
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.MarkAsMCP()
			spec.JSONRPCRouter = mcp.NewRouter()
			if synthetic {
				spec = buildSyntheticAdapterForRuntimeTest(t)
			}
			mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
			req.Header.Set(mcp.HeaderMethod, "tools/list")
			req.Header.Set(mcp.HeaderSessionID, "ignored")
			req.Header.Set("Last-Event-ID", "ignored")
			rec := httptest.NewRecorder()
			err, status := mw.ProcessRequest(rec, req, nil)
			require.NoError(t, err)
			if synthetic {
				require.Equal(t, middleware.StatusRespond, status)
				require.Equal(t, http.StatusBadRequest, rec.Code)
				var response struct {
					ID    json.RawMessage
					Error struct {
						Code int
						Data struct{ Supported []string }
					}
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
				require.Equal(t, mcp.CodeUnsupportedProtocolVersion, response.Error.Code)
				require.Equal(t, mcp.LegacyProtocolVersions(), response.Error.Data.Supported)
				require.Equal(t, "9007199254740993", string(response.ID))
			} else {
				require.Equal(t, http.StatusOK, status)
				require.Empty(t, req.Header.Get(mcp.HeaderSessionID))
				require.Empty(t, req.Header.Get("Last-Event-ID"))
				require.NotNil(t, httpctx.GetJSONRPCRoutingState(req))
			}
		})
	}
}
