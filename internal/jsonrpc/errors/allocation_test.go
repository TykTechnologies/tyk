package errors

import (
	"testing"

	sdkjsonrpc "github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/mcp"
)

func TestModernErrorAllocation(t *testing.T) {
	allocated := []int{CodeModernServerError, CodeModernAuthRequired, CodeModernAccessDenied, CodeModernQuotaExceeded, CodeModernRateLimitExceeded, CodeModernIPBlocked, CodeModernUpstreamError}
	reserved := []int{
		mcp.JSONRPCParseError, mcp.JSONRPCInvalidRequest, mcp.JSONRPCMethodNotFound, mcp.JSONRPCInvalidParams, mcp.JSONRPCInternalError,
		sdkjsonrpc.CodeParseError, sdkjsonrpc.CodeInvalidRequest, sdkjsonrpc.CodeMethodNotFound, sdkjsonrpc.CodeInvalidParams, sdkjsonrpc.CodeInternalError,
		CodeServerError, CodeAuthRequired, CodeAccessDenied, CodeQuotaExceeded, CodeRateLimitExceeded, CodeIPBlocked, CodeUpstreamError,
		-32020, -32021, -32022,
	}
	for index, code := range allocated {
		require.Equal(t, -33000-index, code, "public allocation must not follow legacy offsets")
		require.NotContains(t, reserved, code, "collision with Gateway or pinned SDK protocol errors")
	}
}
