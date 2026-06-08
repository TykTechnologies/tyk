package mcp

import (
	"encoding/json"
	"strings"
)

// MCP trace-context bridge (SEP-414). For ordinary HTTP the W3C trace context
// rides in the `traceparent` request header; MCP servers instead read it from
// the JSON-RPC body at `params._meta`. This seam reads (and, on the write path,
// injects) that body field, isolating the SEP-414 key handling — which is
// "likely to change" — to one place.
const (
	// MetaKey is the JSON-RPC params field carrying request metadata.
	MetaKey = "_meta"
	// TraceParentKey is the W3C traceparent entry within the trace-context object.
	TraceParentKey = "traceparent"
	// TraceStateKey is the optional W3C tracestate entry within the trace-context object.
	TraceStateKey = "tracestate"
	// DefaultMetaPath is the MCP-spec body location of the trace-context object.
	DefaultMetaPath = "params._meta"
)

// TraceContext is the W3C trace context carried in an MCP request.
type TraceContext struct {
	TraceParent string
	TraceState  string
}

// Valid reports whether a usable traceparent is present.
func (tc TraceContext) Valid() bool { return tc.TraceParent != "" }

// TraceSource names where an inbound request's trace context was found, so an
// operator (and the read path) can tell header-only from MCP-native from both.
type TraceSource string

const (
	// TraceSourceNone: no trace context in either channel.
	TraceSourceNone TraceSource = "none"
	// TraceSourceHeader: only the HTTP traceparent header carried it.
	TraceSourceHeader TraceSource = "header"
	// TraceSourceMeta: only the JSON-RPC body params._meta carried it (MCP-native).
	TraceSourceMeta TraceSource = "meta"
	// TraceSourceBoth: present in both channels.
	TraceSourceBoth TraceSource = "both"
)

// ClassifyTraceSource reports which channel(s) carried a traceparent, given the
// HTTP header value and whether the body carried one.
func ClassifyTraceSource(headerTraceParent string, bodyHasTraceParent bool) TraceSource {
	hasHeader := headerTraceParent != ""
	switch {
	case hasHeader && bodyHasTraceParent:
		return TraceSourceBoth
	case hasHeader:
		return TraceSourceHeader
	case bodyHasTraceParent:
		return TraceSourceMeta
	default:
		return TraceSourceNone
	}
}

// ReadMetaTraceContext parses a JSON-RPC request body and returns the W3C trace
// context found at the MCP-spec location params._meta. It never mutates the
// input and is a no-op (zero value, ok=false) on non-JSON, non-MCP, or
// malformed bodies.
func ReadMetaTraceContext(body []byte) (TraceContext, bool) {
	return ReadBodyTraceContext(body, DefaultMetaPath)
}

// ReadBodyTraceContext reads the W3C trace context from the JSON body at the
// given dotted object path (e.g. "params._meta"). The reserved W3C key names
// (traceparent/tracestate) are fixed; only the object location is configurable,
// which is the SEP-414 future-proofing seam. No-op (ok=false) on non-JSON, an
// empty path, or a path that does not resolve to an object carrying a
// traceparent.
func ReadBodyTraceContext(body []byte, path string) (TraceContext, bool) {
	if len(body) == 0 || path == "" {
		return TraceContext{}, false
	}
	var node map[string]json.RawMessage
	if err := json.Unmarshal(body, &node); err != nil {
		return TraceContext{}, false
	}
	segments := strings.Split(path, ".")
	for _, seg := range segments {
		raw, ok := node[seg]
		if !ok {
			return TraceContext{}, false
		}
		node = nil
		if err := json.Unmarshal(raw, &node); err != nil {
			return TraceContext{}, false
		}
	}
	return traceContextFromObject(node)
}

// traceContextFromObject reads the reserved traceparent/tracestate keys from a
// decoded JSON object. Returns ok=false when no traceparent is present.
func traceContextFromObject(obj map[string]json.RawMessage) (TraceContext, bool) {
	tp := rawString(obj[TraceParentKey])
	if tp == "" {
		return TraceContext{}, false
	}
	return TraceContext{TraceParent: tp, TraceState: rawString(obj[TraceStateKey])}, true
}

// WriteMetaTraceContext returns body with params._meta carrying tc, creating
// params and/or _meta when absent and preserving every other field's value. It
// returns the input unchanged (changed=false) on a non-MCP / non-JSON /
// malformed body or an invalid tc, so a passthrough is never corrupted.
func WriteMetaTraceContext(body []byte, tc TraceContext) (out []byte, changed bool) {
	if !tc.Valid() {
		return body, false
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil || top == nil {
		return body, false
	}
	// Only a JSON-RPC request (has a method) is rewritten — responses and
	// unrelated JSON pass through untouched.
	if _, ok := top["method"]; !ok {
		return body, false
	}

	params, ok := decodeObject(top, "params")
	if !ok {
		return body, false
	}
	meta, ok := decodeObject(params, MetaKey)
	if !ok {
		return body, false
	}

	var err error
	if meta[TraceParentKey], err = json.Marshal(tc.TraceParent); err != nil {
		return body, false
	}
	if tc.TraceState != "" {
		if meta[TraceStateKey], err = json.Marshal(tc.TraceState); err != nil {
			return body, false
		}
	}

	if params[MetaKey], err = json.Marshal(meta); err != nil {
		return body, false
	}
	if top["params"], err = json.Marshal(params); err != nil {
		return body, false
	}
	if out, err = json.Marshal(top); err != nil {
		return body, false
	}
	return out, true
}

// decodeObject returns the JSON object at parent[key] as a mutable map: an empty
// map when the key is absent, or ok=false when the value is present but not a
// JSON object.
func decodeObject(parent map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool) {
	obj := map[string]json.RawMessage{}
	raw, ok := parent[key]
	if !ok {
		return obj, true
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}
	return obj, true
}

// rawString decodes a JSON string RawMessage to its Go string, or "" if absent
// or not a string.
func rawString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}
