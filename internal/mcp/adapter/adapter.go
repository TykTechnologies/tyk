// Package adapter contains the pure (gateway-agnostic) building blocks
// of the REST-as-MCP adapter: tool-argument expansion into an http.Request,
// and the size-capped response recorder used to wrap the looped REST response
// as an MCP `result.content[]` envelope.
//
// The package is consumed by the gateway's loader/synthesiser and the
// SDK-backed synthetic adapter. Splitting it out keeps the gateway package
// free of MCP protocol details and makes the protocol-level logic
// independently testable.
package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// BodyTruncationBytes is the maximum size of an upstream response body
// the adapter inlines into the MCP `result.content[]` envelope. Bodies
// larger than this are truncated, tagged `_meta.truncated: true`, and shown
// with an appended notice in `content` so models do not treat partial data as
// complete.
const BodyTruncationBytes = 1 << 20 // 1 MiB

const (
	headerContentType          = "Content-Type"
	contentTypeApplicationJSON = "application/json"
	contentTypeFormURLEncoded  = "application/x-www-form-urlencoded"
	truncationNotice           = "Tyk truncated the upstream response after 1048576 bytes. The content above is incomplete."
)

const (
	metaUpstreamHTTPStatus  = "upstreamHttpStatus"
	metaUpstreamContentType = "upstreamContentType"
	metaTruncated           = "truncated"
)

// BuildUpstreamRequest expands MCP `tools/call` arguments per the
// tool's ParamLocations into an http.Request whose URL host is the
// source REST APIID (so downstream rewriters see a coherent host).
//
// The function is parent-context-aware: the returned request inherits
// the parent's context, body, and trailers are not propagated (the
// adapter does not stream).
//
// Returned errors are user-facing — they are surfaced via the JSON-RPC
// `error` envelope.
func BuildUpstreamRequest(
	parent *http.Request,
	tool *oas.DerivedTool,
	restAPIID string,
	args map[string]any,
) (*http.Request, error) {

	if tool == nil {
		return nil, fmt.Errorf("nil tool")
	}
	if err := ValidateToolMetadata(tool); err != nil {
		return nil, err
	}

	builder := newUpstreamRequestBuilder(parent, tool, restAPIID)
	return builder.build(args)
}

// InvalidParamsError marks client-supplied MCP call arguments that should be
// surfaced as JSON-RPC -32602 InvalidParams.
type InvalidParamsError struct {
	message string
}

func (e *InvalidParamsError) Error() string { return e.message }

func invalidParamsf(format string, args ...any) error {
	return &InvalidParamsError{message: fmt.Sprintf(format, args...)}
}

// IsInvalidParams reports whether err should be returned as JSON-RPC
// InvalidParams.
func IsInvalidParams(err error) bool {
	var invalid *InvalidParamsError
	return errors.As(err, &invalid)
}

// ValidateToolMetadata validates adapter-only metadata before translating
// caller arguments. It catches impossible catalogue entries that cannot map to
// one upstream REST request shape.
func ValidateToolMetadata(tool *oas.DerivedTool) error {
	if tool == nil {
		return fmt.Errorf("nil tool")
	}

	wholeBodyArg := ""
	bodyFieldArg := ""
	for argName, loc := range tool.ParamLocations {
		switch {
		case loc == oas.DerivedParamLocationBody:
			wholeBodyArg = argName
		case strings.HasPrefix(loc, oas.DerivedParamLocationBodyPrefix):
			bodyFieldArg = argName
		}
	}
	if wholeBodyArg != "" && bodyFieldArg != "" {
		return invalidParamsf("argument %q cannot be combined with whole-body argument %q", bodyFieldArg, wholeBodyArg)
	}
	return nil
}

type queryParam struct {
	name  string
	value string
}

type upstreamRequestBuilder struct {
	parent   *http.Request
	tool     *oas.DerivedTool
	restID   string
	path     string
	query    []queryParam
	headers  http.Header
	bodyJSON any
	hasBody  bool
}

func newUpstreamRequestBuilder(parent *http.Request, tool *oas.DerivedTool, restAPIID string) upstreamRequestBuilder {
	return upstreamRequestBuilder{
		parent:  parent,
		tool:    tool,
		restID:  restAPIID,
		path:    tool.PathTemplate,
		headers: http.Header{},
	}
}

func (b *upstreamRequestBuilder) build(args map[string]any) (*http.Request, error) {
	if err := b.rejectUnknownArgs(args); err != nil {
		return nil, err
	}
	if err := b.rejectMixedBodyArgs(args); err != nil {
		return nil, err
	}

	for _, argName := range b.orderedArgNames(args) {
		raw := args[argName]
		loc, known := b.tool.ParamLocations[argName]
		if !known {
			continue
		}
		if err := b.applyArg(argName, loc, raw); err != nil {
			return nil, err
		}
	}

	if strings.Contains(b.path, "{") {
		return nil, invalidParamsf("missing required path parameter in %q", b.tool.PathTemplate)
	}

	return b.request()
}

func (b *upstreamRequestBuilder) orderedArgNames(args map[string]any) []string {
	names := make([]string, 0, len(args))
	seen := make(map[string]struct{}, len(args))
	for _, argName := range b.tool.ParamOrder {
		if _, exists := args[argName]; !exists {
			continue
		}
		if _, known := b.tool.ParamLocations[argName]; !known {
			continue
		}
		names = append(names, argName)
		seen[argName] = struct{}{}
	}

	var remaining []string
	for argName := range args {
		if _, done := seen[argName]; done {
			continue
		}
		if _, known := b.tool.ParamLocations[argName]; !known {
			continue
		}
		remaining = append(remaining, argName)
	}
	sort.Strings(remaining)
	return append(names, remaining...)
}

func (b *upstreamRequestBuilder) rejectUnknownArgs(args map[string]any) error {
	for argName := range args {
		if _, known := b.tool.ParamLocations[argName]; !known {
			return invalidParamsf("unknown argument %q", argName)
		}
	}
	return nil
}

func (b *upstreamRequestBuilder) rejectMixedBodyArgs(args map[string]any) error {
	hasWholeBody := false
	bodyFieldArg := ""
	for argName := range args {
		loc, known := b.tool.ParamLocations[argName]
		if !known {
			continue
		}
		switch {
		case loc == oas.DerivedParamLocationBody:
			hasWholeBody = true
		case strings.HasPrefix(loc, oas.DerivedParamLocationBodyPrefix):
			bodyFieldArg = argName
		}
	}
	if hasWholeBody && bodyFieldArg != "" {
		return invalidParamsf("argument %q cannot be combined with whole-body argument", bodyFieldArg)
	}
	return nil
}

func (b *upstreamRequestBuilder) applyArg(argName, loc string, raw any) error {
	sourceName := b.sourceName(argName)
	switch {
	case loc == oas.DerivedParamLocationPath:
		b.applyPathArg(sourceName, raw)
	case loc == oas.DerivedParamLocationQuery:
		b.query = append(b.query, queryParam{name: sourceName, value: fmt.Sprint(raw)})
	case loc == oas.DerivedParamLocationHeader:
		b.headers.Set(sourceName, fmt.Sprint(raw))
	case loc == oas.DerivedParamLocationBody:
		b.bodyJSON = raw
		b.hasBody = true
	case strings.HasPrefix(loc, oas.DerivedParamLocationBodyPrefix):
		return b.applyBodyFieldArg(argName, loc, raw)
	}
	return nil
}

func (b *upstreamRequestBuilder) sourceName(argName string) string {
	if b.tool.ParamSourceNames != nil {
		if sourceName := b.tool.ParamSourceNames[argName]; sourceName != "" {
			return sourceName
		}
	}
	return argName
}

func (b *upstreamRequestBuilder) applyPathArg(argName string, raw any) {
	escaped := url.PathEscape(fmt.Sprint(raw))
	b.path = strings.ReplaceAll(b.path, "{"+argName+"}", escaped)
}

func (b *upstreamRequestBuilder) applyBodyFieldArg(argName, loc string, raw any) error {
	bodyFields, ok := b.bodyJSON.(map[string]any)
	if !b.hasBody {
		bodyFields = map[string]any{}
		b.bodyJSON = bodyFields
		b.hasBody = true
	} else if !ok {
		return invalidParamsf("argument %q cannot be combined with whole-body argument", argName)
	}

	fieldName := b.sourceName(argName)
	if fieldName == "" {
		fieldName = strings.TrimPrefix(loc, oas.DerivedParamLocationBodyPrefix)
	}
	if fieldName == "" {
		fieldName = argName
	}
	bodyFields[fieldName] = raw
	return nil
}

func (b *upstreamRequestBuilder) request() (*http.Request, error) {
	var body io.Reader
	if b.hasBody {
		buf, err := b.marshalBody()
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(b.parent.Context(), b.tool.Method, b.path, body)
	if err != nil {
		return nil, err
	}
	if rawQuery := encodeQuery(b.query); rawQuery != "" {
		req.URL.RawQuery = rawQuery
	}
	copyHeaders(req.Header, b.headers)
	if body != nil {
		req.Header.Set(headerContentType, b.requestBodyContentType())
	}

	// Host = source REST APIID so downstream code that reads it sees a
	// coherent value (the loop primitive looks up handlers by APIID).
	req.URL.Host = b.restID
	req.URL.Scheme = "http"
	req.Host = ""
	return req, nil
}

func encodeQuery(params []queryParam) string {
	if len(params) == 0 {
		return ""
	}

	encoded := make([]string, 0, len(params))
	for _, param := range params {
		encoded = append(encoded, url.QueryEscape(param.name)+"="+url.QueryEscape(param.value))
	}
	return strings.Join(encoded, "&")
}

func (b *upstreamRequestBuilder) marshalBody() ([]byte, error) {
	if b.isFormURLEncodedBody() {
		return []byte(encodeFormBody(b.bodyJSON)), nil
	}
	buf, err := json.Marshal(b.bodyJSON)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}
	return buf, nil
}

func (b *upstreamRequestBuilder) requestBodyContentType() string {
	if b.isFormURLEncodedBody() {
		return contentTypeFormURLEncoded
	}
	return contentTypeApplicationJSON
}

func (b *upstreamRequestBuilder) isFormURLEncodedBody() bool {
	return strings.EqualFold(strings.TrimSpace(b.tool.RequestBodyContentType), contentTypeFormURLEncoded)
}

func encodeFormBody(body any) string {
	values := url.Values{}
	switch v := body.(type) {
	case map[string]any:
		for key, value := range v {
			values.Set(key, fmt.Sprint(value))
		}
	case url.Values:
		return v.Encode()
	default:
		values.Set(oas.DerivedParamLocationBody, fmt.Sprint(v))
	}
	return values.Encode()
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Set(k, v)
		}
	}
}

// Recorder buffers an http.Handler response into memory, capping the
// body at BodyTruncationBytes. Anything written past the cap is
// silently discarded and Truncated() returns true.
type Recorder struct {
	status      int
	header      http.Header
	body        bytes.Buffer
	overflow    bool
	wroteHeader bool
}

// NewRecorder returns a Recorder ready to capture a single response.
func NewRecorder() *Recorder {
	return &Recorder{status: http.StatusOK, header: http.Header{}}
}

// Header satisfies http.ResponseWriter.
func (r *Recorder) Header() http.Header { return r.header }

// WriteHeader satisfies http.ResponseWriter.
func (r *Recorder) WriteHeader(s int) {
	if r.wroteHeader {
		return
	}
	r.status = s
	r.wroteHeader = true
}

// Write satisfies http.ResponseWriter; truncates at BodyTruncationBytes.
func (r *Recorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	remaining := BodyTruncationBytes - r.body.Len()
	if remaining <= 0 {
		r.overflow = true
		return len(b), nil
	}
	if len(b) > remaining {
		r.body.Write(b[:remaining])
		r.overflow = true
		return len(b), nil
	}
	return r.body.Write(b)
}

// Status returns the HTTP status code the handler chose (defaults to 200).
func (r *Recorder) Status() int { return r.status }

// Body returns the captured body bytes (up to BodyTruncationBytes).
func (r *Recorder) Body() []byte { return r.body.Bytes() }

// ContentType returns the recorded Content-Type header (empty if unset).
func (r *Recorder) ContentType() string { return r.header.Get(headerContentType) }

// Truncated reports whether more bytes were written than the recorder
// retained.
func (r *Recorder) Truncated() bool { return r.overflow }

// ToolResultEnvelope wraps a recorded response as an MCP `result`
// envelope. `meta` is merged into `_meta`.
func ToolResultEnvelope(rec *Recorder) map[string]any {
	meta := map[string]any{
		metaUpstreamHTTPStatus:  rec.Status(),
		metaUpstreamContentType: rec.ContentType(),
	}
	if rec.Truncated() {
		meta[metaTruncated] = true
	}
	return map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": ToolResultText(rec)},
		},
		"isError": rec.Status() >= 400,
		"_meta":   meta,
	}
}

// ToolResultText returns the text content exposed to the MCP client. When
// the recorder truncated the upstream response, append a visible notice so
// LLM-facing clients do not receive partial data as if it were complete.
func ToolResultText(rec *Recorder) string {
	body := string(rec.Body())
	if !rec.Truncated() {
		return body
	}
	if body == "" {
		return truncationNotice
	}
	return body + "\n\n" + truncationNotice
}
