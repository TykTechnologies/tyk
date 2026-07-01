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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
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
	defaultTruncationNotice    = "Tyk truncated the upstream response after 1048576 bytes. The content above is incomplete."
	truncationNoticeTemplate   = "Tyk truncated the upstream response after %d bytes. The content above is incomplete."
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
// parent context values without inheriting parent cancellation. The body
// and trailers are not propagated (the adapter does not stream).
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
		if err := b.applyPathArg(argName, sourceName, raw); err != nil {
			return err
		}
	case loc == oas.DerivedParamLocationQuery:
		params, err := b.queryParams(argName, sourceName, raw)
		if err != nil {
			return err
		}
		b.query = append(b.query, params...)
	case loc == oas.DerivedParamLocationHeader:
		value, err := b.headerValue(argName, sourceName, raw)
		if err != nil {
			return err
		}
		b.headers.Set(sourceName, value)
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
	if b.tool.ParamSerializations != nil {
		if sourceName := b.tool.ParamSerializations[argName].SourceName; sourceName != "" {
			return sourceName
		}
	}
	return argName
}

func (b *upstreamRequestBuilder) applyPathArg(argName, sourceName string, raw any) error {
	serialization := b.paramSerialization(argName, sourceName, oas.DerivedParamLocationPath)
	value, err := serializedParameterValue(argName, raw, serialization)
	if err != nil {
		return err
	}
	escaped := url.PathEscape(value)
	b.path = strings.ReplaceAll(b.path, "{"+sourceName+"}", escaped)
	return nil
}

func (b *upstreamRequestBuilder) queryParams(argName, sourceName string, raw any) ([]queryParam, error) {
	serialization := b.paramSerialization(argName, sourceName, oas.DerivedParamLocationQuery)
	values, array, err := parameterValues(argName, raw)
	if err != nil {
		return nil, err
	}
	if !array {
		return []queryParam{{name: sourceName, value: values[0]}}, nil
	}
	if len(values) == 0 {
		return nil, nil
	}
	if serialization.Style == "form" && serialization.Explode {
		params := make([]queryParam, 0, len(values))
		for _, value := range values {
			params = append(params, queryParam{name: sourceName, value: value})
		}
		return params, nil
	}
	delimiter, ok := queryArrayDelimiter(serialization.Style)
	if !ok {
		return nil, invalidParamsf("cannot serialize argument %q with query style %q", argName, serialization.Style)
	}
	return []queryParam{{name: sourceName, value: strings.Join(values, delimiter)}}, nil
}

func (b *upstreamRequestBuilder) headerValue(argName, sourceName string, raw any) (string, error) {
	serialization := b.paramSerialization(argName, sourceName, oas.DerivedParamLocationHeader)
	return serializedParameterValue(argName, raw, serialization)
}

func (b *upstreamRequestBuilder) paramSerialization(argName, sourceName, loc string) oas.DerivedParamSerialization {
	if b.tool.ParamSerializations != nil {
		if serialization, ok := b.tool.ParamSerializations[argName]; ok {
			if serialization.SourceName == "" {
				serialization.SourceName = sourceName
			}
			if serialization.Location == "" {
				serialization.Location = loc
			}
			if serialization.Style == "" {
				serialization.Style = oas.DefaultDerivedParamStyle(loc)
				serialization.Explode = oas.DefaultDerivedParamExplode(serialization.Style)
			}
			return serialization
		}
	}
	style := oas.DefaultDerivedParamStyle(loc)
	return oas.DerivedParamSerialization{
		SourceName: sourceName,
		Location:   loc,
		Style:      style,
		Explode:    oas.DefaultDerivedParamExplode(style),
	}
}

func serializedParameterValue(argName string, raw any, serialization oas.DerivedParamSerialization) (string, error) {
	values, array, err := parameterValues(argName, raw)
	if err != nil {
		return "", err
	}
	if !array {
		return values[0], nil
	}
	switch serialization.Location {
	case oas.DerivedParamLocationPath:
		if serialization.Style != "simple" {
			return "", invalidParamsf("cannot serialize argument %q with path style %q", argName, serialization.Style)
		}
		return strings.Join(values, ","), nil
	case oas.DerivedParamLocationHeader:
		return strings.Join(values, ","), nil
	default:
		return "", invalidParamsf("cannot serialize argument %q as %s parameter", argName, serialization.Location)
	}
}

func parameterValues(argName string, raw any) ([]string, bool, error) {
	if values, ok, err := arrayParameterValues(argName, raw); ok || err != nil {
		return values, ok, err
	}
	value, ok := scalarParameterValue(raw)
	if !ok {
		return nil, false, invalidParamsf("cannot serialize argument %q of type %T as path/query/header parameter", argName, raw)
	}
	return []string{value}, false, nil
}

func arrayParameterValues(argName string, raw any) ([]string, bool, error) {
	value := reflect.ValueOf(raw)
	if !value.IsValid() {
		return nil, false, nil
	}
	switch value.Kind() {
	case reflect.Slice, reflect.Array:
	default:
		return nil, false, nil
	}

	values := make([]string, 0, value.Len())
	for i := 0; i < value.Len(); i++ {
		item := value.Index(i).Interface()
		text, ok := scalarParameterValue(item)
		if !ok {
			return nil, true, invalidParamsf("cannot serialize argument %q array item %d of type %T as path/query/header parameter", argName, i, item)
		}
		values = append(values, text)
	}
	return values, true, nil
}

func scalarParameterValue(raw any) (string, bool) {
	switch v := raw.(type) {
	case string:
		return v, true
	case bool:
		return fmt.Sprint(v), true
	case int, int8, int16, int32, int64:
		return fmt.Sprint(v), true
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprint(v), true
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case json.Number:
		return v.String(), true
	default:
		return "", false
	}
}

func queryArrayDelimiter(style string) (string, bool) {
	switch style {
	case "form":
		return ",", true
	case "spaceDelimited":
		return " ", true
	case "pipeDelimited":
		return "|", true
	default:
		return "", false
	}
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

	req, err := http.NewRequestWithContext(context.WithoutCancel(b.parent.Context()), b.tool.Method, b.path, body)
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

	size := len(params) - 1
	for _, param := range params {
		size += len(param.name) + len(param.value) + 1
	}

	var builder strings.Builder
	builder.Grow(size)
	for i, param := range params {
		if i > 0 {
			builder.WriteByte('&')
		}
		builder.WriteString(url.QueryEscape(param.name))
		builder.WriteByte('=')
		builder.WriteString(url.QueryEscape(param.value))
	}
	return builder.String()
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
	if contentType := strings.TrimSpace(b.tool.RequestBodyContentType); contentType != "" {
		return contentType
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

// Recorder buffers an http.Handler response into memory, capping the body at
// its configured limit. Anything written past the cap is silently discarded and
// Truncated() returns true.
type Recorder struct {
	status      int
	header      http.Header
	body        bytes.Buffer
	bodyLimit   int
	overflow    bool
	wroteHeader bool
}

// NewRecorder returns a Recorder ready to capture a single response with the
// default body cap.
func NewRecorder() *Recorder {
	return NewRecorderWithBodyLimit(BodyTruncationBytes)
}

// NewRecorderWithBodyLimit returns a Recorder ready to capture a single
// response using bodyLimit as the retained response body cap. Non-positive
// limits fall back to BodyTruncationBytes.
func NewRecorderWithBodyLimit(bodyLimit int) *Recorder {
	if bodyLimit <= 0 {
		bodyLimit = BodyTruncationBytes
	}
	return &Recorder{status: http.StatusOK, header: http.Header{}, bodyLimit: bodyLimit}
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

// Write satisfies http.ResponseWriter; truncates at the configured body limit.
func (r *Recorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	remaining := r.effectiveBodyLimit() - r.body.Len()
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

func (r *Recorder) effectiveBodyLimit() int {
	if r.bodyLimit > 0 {
		return r.bodyLimit
	}
	return BodyTruncationBytes
}

// Status returns the HTTP status code the handler chose (defaults to 200).
func (r *Recorder) Status() int { return r.status }

// Body returns the captured body bytes, up to the configured body limit.
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
	body := rec.Body()
	if !rec.Truncated() {
		return string(body)
	}
	notice := truncationNotice(rec.effectiveBodyLimit())
	if len(body) == 0 {
		return notice
	}
	var builder strings.Builder
	builder.Grow(len(body) + len(notice) + 2)
	builder.Write(body)
	builder.WriteString("\n\n")
	builder.WriteString(notice)
	return builder.String()
}

func truncationNotice(bodyLimit int) string {
	if bodyLimit == BodyTruncationBytes {
		return defaultTruncationNotice
	}
	return fmt.Sprintf(truncationNoticeTemplate, bodyLimit)
}
