package gateway

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

func testRESTAsMCPIngressMiddleware() *JSONRPCMiddleware {
	tool := oas.DerivedTool{
		Name: "calculate",
		InputSchema: map[string]any{
			"properties": map[string]any{
				"count": map[string]any{"type": "integer", "x-mcp-header": "Count"},
				"ratio": map[string]any{"type": "number", "x-mcp-header": "Ratio"},
				"options": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"label": map[string]any{"type": "string", "x-mcp-header": "Label"},
					},
				},
			},
		},
	}
	return &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: &APISpec{
		MCPAdapter: MCPAdapterRuntime{
			Synthetic:            true,
			UnionTools:           []oas.DerivedTool{tool},
			IngressToolsByCaller: buildMCPIngressToolIndex(nil, []oas.DerivedTool{tool}),
		},
	}}}
}

func TestValidateRESTAsMCPParamHeaders(t *testing.T) {
	t.Parallel()

	newEnvelope := func(arguments string) *mcp.RequestEnvelope {
		return &mcp.RequestEnvelope{
			Method: mcp.MethodToolsCall,
			Params: json.RawMessage(`{"name":"calculate","arguments":` + arguments + `}`),
		}
	}
	encodedLabel := "=?base64?" + base64.StdEncoding.EncodeToString([]byte("café")) + "?="

	tests := []struct {
		name      string
		arguments string
		headers   map[string]string
		wantError bool
	}{
		{
			name:      "integer float nested and Base64 values match",
			arguments: `{"count":7,"ratio":1.25,"options":{"label":"café"}}`,
			headers:   map[string]string{"Mcp-Param-Count": "7", "Mcp-Param-Ratio": "1.25", "Mcp-Param-Label": encodedLabel},
		},
		{
			name:      "equivalent exponent number matches",
			arguments: `{"ratio":1e6}`,
			headers:   map[string]string{"Mcp-Param-Ratio": "1000000"},
		},
		{
			name:      "missing required mirror",
			arguments: `{"count":7}`,
			headers:   map[string]string{},
			wantError: true,
		},
		{
			name:      "float mismatch",
			arguments: `{"ratio":1.25}`,
			headers:   map[string]string{"Mcp-Param-Ratio": "1.5"},
			wantError: true,
		},
		{
			name:      "unexpected mirror",
			arguments: `{}`,
			headers:   map[string]string{"Mcp-Param-Other": "value"},
			wantError: true,
		},
		{
			name:      "null argument needs no mirror",
			arguments: `{"count":null,"ratio":null,"options":{"label":null}}`,
			headers:   map[string]string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			middleware := testRESTAsMCPIngressMiddleware()
			req := httptest.NewRequest("POST", "http://gateway.example/mcp", nil)
			for key, value := range test.headers {
				req.Header.Set(key, value)
			}
			ingressErr := middleware.validateRESTAsMCPParamHeaders(req, newEnvelope(test.arguments))
			if test.wantError {
				require.NotNil(t, ingressErr)
				assert.Equal(t, mcp.CodeHeaderMismatch, ingressErr.Code)
				assert.NotContains(t, ingressErr.Message, "count")
				assert.NotContains(t, ingressErr.Message, "ratio")
				return
			}
			assert.Nil(t, ingressErr)
		})
	}
}

func TestMCPPrimitiveStringNumbers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  string
		ok    bool
	}{
		{value: "7", want: "7", ok: true},
		{value: "1.25", want: "1.25", ok: true},
		{value: "1e3", want: "1000", ok: true},
		{value: "9007199254740992", ok: false},
	}
	for _, test := range tests {
		got, ok := mcpPrimitiveString(json.Number(test.value))
		assert.Equal(t, test.ok, ok)
		assert.Equal(t, test.want, got)
	}
}
