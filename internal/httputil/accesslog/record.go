package accesslog

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/request"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

// Record is a representation of a transaction log in the Gateway.
type Record struct {
	fields logrus.Fields
}

// NewRecord returns a Record object.
func NewRecord() *Record {
	fields := logrus.Fields{
		"prefix": "access-log",
	}
	return &Record{
		fields: fields,
	}
}

// WithApiKey sets the access token from the request under APIKey.
// The access token is obfuscated, or hashed depending on passed arguments.
func (a *Record) WithApiKey(req *http.Request, hashKeys bool, obfuscate func(string) string) *Record {
	token := ctx.GetAuthToken(req)
	if !hashKeys {
		a.fields["api_key"] = obfuscate(token)
	} else {
		a.fields["api_key"] = crypto.HashKey(token, hashKeys)
	}
	return a
}

// WithRequest fills fields from the http request.
func (a *Record) WithRequest(req *http.Request, latency analytics.Latency) *Record {
	upstreamAddress := &url.URL{
		Scheme: req.URL.Scheme,
		Host:   req.URL.Host,
		Path:   req.URL.Path,
	}

	// Keep the sort in sync with config.AccessLog.Template godoc.
	a.fields["client_ip"] = request.RealIP(req)
	a.fields["host"] = req.Host
	a.fields["latency_total"] = latency.Total
	a.fields["latency_gateway"] = latency.Gateway
	a.fields["method"] = req.Method
	a.fields["path"] = req.URL.Path
	a.fields["protocol"] = req.Proto
	a.fields["remote_addr"] = req.RemoteAddr
	a.fields["upstream_addr"] = upstreamAddress.String()
	a.fields["upstream_latency"] = latency.Upstream
	a.fields["user_agent"] = req.UserAgent()
	return a
}

// WithResponse fills response details into the log fields.
func (a *Record) WithResponse(resp *http.Response) *Record {
	a.fields["status"] = resp.StatusCode
	return a
}

// WithTraceID adds the OpenTelemetry trace ID to the access log record.
// The trace ID is only added if a trace context exists in the request.
func (a *Record) WithTraceID(req *http.Request) *Record {
	traceID := otel.ExtractTraceID(req.Context())
	if traceID != "" {
		a.fields["trace_id"] = traceID
	}
	return a
}

// WithAPIID adds API identification fields to the access log record.
func (a *Record) WithAPIID(apiID, apiName, orgID string) *Record {
	if apiID != "" {
		a.fields["api_id"] = apiID
	}
	if apiName != "" {
		a.fields["api_name"] = apiName
	}
	if orgID != "" {
		a.fields["org_id"] = orgID
	}
	return a
}

// WithErrorClassification adds structured error classification fields to the access log record.
// Fields are only added when the classification is non-nil and individual fields are non-empty/non-zero.
// This enables operators to distinguish between error types (TLS expired, connection refused, timeout, etc.)
// directly in access logs.
func (a *Record) WithErrorClassification(ec *errors.ErrorClassification) *Record {
	if ec == nil {
		return a
	}

	// Always add the core classification fields
	a.fields["response_flag"] = ec.Flag.String()
	a.fields["response_code_details"] = ec.Details

	// Add optional fields only when non-empty
	if ec.Source != "" {
		a.fields["error_source"] = ec.Source
	}
	if ec.Target != "" {
		a.fields["error_target"] = ec.Target
	}

	// Add upstream status only for non-zero values
	if ec.UpstreamStatus != 0 {
		a.fields["upstream_status"] = ec.UpstreamStatus
	}

	// Add TLS cert info only when present
	if !ec.TLSCertExpiry.IsZero() {
		a.fields["tls_cert_expiry"] = ec.TLSCertExpiry.Format("2006-01-02T15:04:05Z07:00")
	}
	if ec.TLSCertSubject != "" {
		a.fields["tls_cert_subject"] = ec.TLSCertSubject
	}

	// Add circuit breaker state only when present
	if ec.CircuitBreakerState != "" {
		a.fields["circuit_breaker_state"] = ec.CircuitBreakerState
	}

	return a
}

// WithJSONRPC adds JSON-RPC/MCP specific fields to the access log record.
// Fields are only added when JSON-RPC request data is present in the request context.
// This enables operators to track MCP API calls with method, tool, resource, and session info.
func (a *Record) WithJSONRPC(req *http.Request) *Record {
	rpcData := httpctx.GetJSONRPCRequest(req)
	if rpcData == nil {
		return a
	}

	if rpcData.Method != "" {
		a.fields["jsonrpc_method"] = rpcData.Method
	}

	if rpcData.ID != nil {
		switch id := rpcData.ID.(type) {
		case string:
			a.fields["jsonrpc_id"] = id
		case float64:
			a.fields["jsonrpc_id"] = fmt.Sprintf("%.0f", id)
		default:
			a.fields["jsonrpc_id"] = fmt.Sprintf("%v", id)
		}
	}

	if rpcData.Primitive != "" {
		switch rpcData.Method {
		case mcp.MethodToolsCall:
			a.fields["mcp_tool"] = rpcData.Primitive
		case mcp.MethodResourcesRead:
			a.fields["mcp_resource"] = rpcData.Primitive
		case mcp.MethodPromptsGet:
			a.fields["mcp_prompt"] = rpcData.Primitive
		}
	}

	if sessionID := req.Header.Get("Mcp-Session-Id"); sessionID != "" {
		a.fields["mcp_session_id"] = sessionID
	}

	return a
}

// WithJSONRPCError adds JSON-RPC error fields to the access log record.
// Fields are only added when JSON-RPC error data is present in the request context
// and the error code is non-zero (indicating an actual error occurred).
// This enables operators to see the JSON-RPC error code and message when MCP requests fail.
func (a *Record) WithJSONRPCError(req *http.Request) *Record {
	errData := httpctx.GetJSONRPCError(req)
	if errData == nil || errData.Code == 0 {
		return a
	}

	a.fields["jsonrpc_error_code"] = errData.Code

	// Add message only when non-empty
	if errData.Message != "" {
		a.fields["jsonrpc_error_message"] = errData.Message
	}

	return a
}

// Fields returns a logrus.Fields intended for logging.
func (a *Record) Fields(allowedKeys []string) logrus.Fields {
	return Filter(a.fields, allowedKeys)
}
