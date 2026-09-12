package errors

import (
	"testing"

	sdkjsonrpc "github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/mcp"
)

func TestModernErrorAllocation(t *testing.T) {
	allocated := map[string]int{
		"server": CodeModernServerError, "authentication": CodeModernAuthRequired,
		"access": CodeModernAccessDenied, "quota": CodeModernQuotaExceeded,
		"rate limit": CodeModernRateLimitExceeded, "IP": CodeModernIPBlocked,
		"upstream": CodeModernUpstreamError,
	}
	reserved := map[string]int{
		"gateway parse": mcp.JSONRPCParseError, "gateway invalid request": mcp.JSONRPCInvalidRequest,
		"gateway method not found": mcp.JSONRPCMethodNotFound, "gateway invalid params": mcp.JSONRPCInvalidParams,
		"gateway internal": mcp.JSONRPCInternalError,
		"SDK parse":        sdkjsonrpc.CodeParseError, "SDK invalid request": sdkjsonrpc.CodeInvalidRequest,
		"SDK method not found": sdkjsonrpc.CodeMethodNotFound, "SDK invalid params": sdkjsonrpc.CodeInvalidParams,
		"SDK internal": sdkjsonrpc.CodeInternalError, "SDK header mismatch": sdkmcp.CodeHeaderMismatch,
		"SDK resource not found": sdkmcp.CodeResourceNotFound, "SDK URL elicitation required": sdkmcp.CodeURLElicitationRequired,
		"legacy server": CodeServerError, "legacy auth": CodeAuthRequired,
		"legacy access": CodeAccessDenied, "legacy quota": CodeQuotaExceeded,
		"legacy rate limit": CodeRateLimitExceeded, "legacy IP": CodeIPBlocked,
		"legacy upstream":            CodeUpstreamError,
		"protocol session not found": -32020, "protocol session expired": -32021,
		"protocol invalid session": -32022,
	}
	expected := map[string]int{
		"server": -33000, "authentication": -33001, "access": -33002,
		"quota": -33003, "rate limit": -33004, "IP": -33005, "upstream": -33006,
	}
	seen := make(map[int]string, len(allocated))
	for name, code := range allocated {
		require.Equal(t, expected[name], code, "%s allocation changed", name)
		require.True(t, code < -32768 || code > -32000, "%s enters the JSON-RPC reserved server range", name)
		if previous, exists := seen[code]; exists {
			t.Fatalf("modern allocations %q and %q both use %d", previous, name, code)
		}
		seen[code] = name
		for reservedName, reservedCode := range reserved {
			require.NotEqual(t, reservedCode, code, "%s collides with %s", name, reservedName)
		}
	}
}

func TestLegacyAllocationDocumentsPinnedSDKCollisions(t *testing.T) {
	require.Equal(t, sdkmcp.CodeHeaderMismatch, CodeAuthRequired)
	require.Equal(t, sdkmcp.CodeResourceNotFound, CodeAccessDenied)
}
