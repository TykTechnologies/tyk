package otel

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/propagation"

	tyktrace "github.com/TykTechnologies/opentelemetry/trace"

	"github.com/TykTechnologies/tyk/internal/mcp"
)

// MCP trace span attribute keys, per the OpenTelemetry GenAI/MCP semantic
// conventions, so the trace is self-explaining in any standard dashboard. The
// primitive name is keyed by its type — tools, resources and prompts each get
// their own attribute rather than all being labelled as tools.
const (
	attrMCPMethod      = "mcp.method.name"
	attrMCPTool        = "mcp.tool.name"
	attrMCPResource    = "mcp.resource.name"
	attrMCPPrompt      = "mcp.prompt.name"
	attrMCPTraceSource = "mcp.trace_source"
)

// primitiveNameAttrKey returns the span-attribute key for a primitive name given
// its type, or "" for an unrecognised type (the name is then not stamped).
func primitiveNameAttrKey(primitiveType string) string {
	switch primitiveType {
	case mcp.PrimitiveTypeTool:
		return attrMCPTool
	case mcp.PrimitiveTypeResource:
		return attrMCPResource
	case mcp.PrimitiveTypePrompt:
		return attrMCPPrompt
	default:
		return ""
	}
}

// MCPSpanAttributes returns the MCP attributes to stamp on the request span: the
// method (always), the primitive name keyed by its type (tool/resource/prompt,
// only when one resolved), and where the trace context was found. No identities
// or token values — only the bounded method/primitive names and the source label.
func MCPSpanAttributes(method, primitiveType, primitiveName string, source mcp.TraceSource) []SpanAttribute {
	attrs := []SpanAttribute{
		tyktrace.NewAttribute(attrMCPMethod, method),
		tyktrace.NewAttribute(attrMCPTraceSource, string(source)),
	}
	if key := primitiveNameAttrKey(primitiveType); key != "" && primitiveName != "" {
		attrs = append(attrs, tyktrace.NewAttribute(key, primitiveName))
	}
	return attrs
}

// w3cTraceParentHeader / w3cTraceStateHeader are the fixed W3C carrier keys.
// Only the location an MCP request carries them in is configurable, not the names.
const (
	w3cTraceParentHeader = "traceparent"
	w3cTraceStateHeader  = "tracestate"
)

// Channels an MCP trace-context read source can name.
const (
	// MCPTraceChannelHeader reads the W3C trace context from the HTTP request
	// headers (the standard traceparent/tracestate header names).
	MCPTraceChannelHeader = "header"
	// MCPTraceChannelBody reads it from a JSON path into the request body.
	MCPTraceChannelBody = "body"
)

// MCPTraceSource names one place to look for an inbound request's W3C trace
// context. The reserved key names (traceparent/tracestate) are fixed; only the
// location is configurable — Path is the SEP-414 future-proofing knob for the
// body channel.
type MCPTraceSource struct {
	// Channel is "header" or "body".
	Channel string `json:"channel"`
	// Path is the dotted JSON object path for a body channel (e.g.
	// "params._meta"). Ignored for the header channel.
	Path string `json:"path,omitempty"`
}

// MCPTraceContextConfig configures where Tyk reads the MCP trace context from.
// It lives at opentelemetry.mcp_trace_context, alongside the traces/metrics
// extensions on the gateway's OpenTelemetry wrapper.
type MCPTraceContextConfig struct {
	// ReadSources is an ordered, first-match-wins list of places to look for
	// the inbound trace context. When omitted, it defaults to
	// [{header}, {body, path: params._meta}].
	ReadSources []MCPTraceSource `json:"read_sources,omitempty"`
}

// DefaultMCPReadSources is the spec-canonical default: the HTTP header first
// (preserving today's header-wins behaviour), then the MCP body location
// params._meta.
func DefaultMCPReadSources() []MCPTraceSource {
	return []MCPTraceSource{
		{Channel: MCPTraceChannelHeader},
		{Channel: MCPTraceChannelBody, Path: mcp.DefaultMetaPath},
	}
}

// SetDefaults fills an omitted read-source list with the canonical default. An
// operator-configured list is left untouched.
func (c *MCPTraceContextConfig) SetDefaults() {
	if len(c.ReadSources) == 0 {
		c.ReadSources = DefaultMCPReadSources()
	}
}

// MCPTraceResolution is the outcome of resolving an MCP request's trace context
// against the configured read sources.
type MCPTraceResolution struct {
	// Context is the trace context read from the body (zero when no body source
	// matched). Carried for the join.
	Context mcp.TraceContext
	// Source records which channel(s) carried a traceparent, for the
	// trace_source label.
	Source mcp.TraceSource
	// JoinFromBody is true when the caller must install Context into the request
	// context — i.e. the HTTP header carried nothing and a body source matched.
	// When the header is present, Tyk's inbound extraction already established
	// the trace, so the caller reconciles to it rather than forking a second one.
	JoinFromBody bool
}

// ResolveMCPTraceContext walks the ordered read sources and decides how Tyk
// should join an MCP request's trace. Body sources are tried in list order
// (first match wins). The header channel is authoritative when present: Tyk's
// inbound extraction already used it, so a body context is joined only when the
// header carried nothing — guaranteeing one consistent trace_id and never a
// second, parallel trace.
func ResolveMCPTraceContext(sources []MCPTraceSource, headerTraceParent string, body []byte) MCPTraceResolution {
	hasHeader := headerTraceParent != ""

	var bodyTC mcp.TraceContext
	bodyFound := false
	for _, s := range sources {
		if s.Channel != MCPTraceChannelBody {
			continue
		}
		if tc, ok := mcp.ReadBodyTraceContext(body, s.Path); ok {
			bodyTC, bodyFound = tc, true
			break
		}
	}

	return MCPTraceResolution{
		Context:      bodyTC,
		Source:       mcp.ClassifyTraceSource(headerTraceParent, bodyFound),
		JoinFromBody: bodyFound && !hasHeader,
	}
}

// JoinMCPTraceContext resolves an MCP request's trace context against the
// configured read sources and, when the body carried it and the HTTP header did
// not, installs it into the request context so that every span, access-log line,
// structured log, and audit event Tyk emits later in the request inherits the
// agent's trace_id (they all read it from r.Context()). It returns where the
// context was found, for the trace_source label.
//
// Note: the inbound otelhttp server span is created from the HTTP header before
// the body is parsed, so it cannot be re-parented here — the join governs every
// emission from this point onward, which is what the trace_id readers observe.
func JoinMCPTraceContext(r *http.Request, sources []MCPTraceSource, body []byte) mcp.TraceSource {
	res := ResolveMCPTraceContext(sources, r.Header.Get(w3cTraceParentHeader), body)
	if res.JoinFromBody {
		ctx := extractTraceContext(r.Context(), res.Context)
		*r = *r.WithContext(ctx)
	}
	return res.Source
}

// extractTraceContext returns ctx with tc installed as the active (remote) span
// context via the W3C propagator — the same propagator Tyk uses for inbound
// header extraction, so the joined trace is byte-identical to a header-carried one.
func extractTraceContext(ctx context.Context, tc mcp.TraceContext) context.Context {
	carrier := propagation.MapCarrier{w3cTraceParentHeader: tc.TraceParent}
	if tc.TraceState != "" {
		carrier[w3cTraceStateHeader] = tc.TraceState
	}
	return propagation.TraceContext{}.Extract(ctx, carrier)
}

// CurrentTraceContext serialises the active span context in ctx to a W3C trace
// context (traceparent + tracestate), or the zero value when no span is active.
// Used by the write path to inject Tyk's context into the outbound MCP body.
func CurrentTraceContext(ctx context.Context) mcp.TraceContext {
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, carrier)
	return mcp.TraceContext{
		TraceParent: carrier[w3cTraceParentHeader],
		TraceState:  carrier[w3cTraceStateHeader],
	}
}
