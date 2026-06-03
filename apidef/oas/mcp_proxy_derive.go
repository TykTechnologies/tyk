package oas

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// DerivedTool is the runtime descriptor the adapter needs to translate
// a `tools/call` JSON-RPC envelope into an HTTP request against the
// source REST API.
//
// It carries everything the adapter middleware needs — method, path
// template, where each argument lives (path / query / header / body /
// body.<field>), and the synthesised input JSON schema that is served
// back on `tools/list`.
type DerivedTool struct {
	// OperationID is the source REST operationId this tool calls.
	OperationID string `json:"-"`

	// SourceKey identifies the source operation even when operationId is
	// absent. OperationId-backed tools use "operationId:<id>"; path+method
	// fallbacks use "http:<METHOD> <PATH>".
	SourceKey string `json:"-"`

	// CanonicalName is the source-derived MCP tool name before any proxy-side
	// alias is applied.
	CanonicalName string `json:"-"`

	// Name is the MCP tool name agents call.
	Name string `json:"name"`

	// Description is taken from the OAS operation summary or description.
	Description string `json:"description,omitempty"`

	// Method is the HTTP method (GET, POST, ...).
	Method string `json:"-"`

	// PathTemplate is the OAS path template (e.g. "/orders/{id}").
	PathTemplate string `json:"-"`

	// ParamLocations maps each argument name to its source location.
	// Recognised values:
	//   - "path"
	//   - "query"
	//   - "header"
	//   - "body"          (the whole JSON body)
	//   - "body.<field>"  (a single JSON body field)
	// Locations are used internally by the REST-as-MCP adapter.
	ParamLocations map[string]string `json:"-"`

	// ParamSourceNames maps each MCP-facing argument name back to the
	// original REST parameter or body field name.
	ParamSourceNames map[string]string `json:"-"`

	// RequestBodyContentType is the selected source request body media type.
	// Empty means JSON/default.
	RequestBodyContentType string `json:"-"`

	// InputSchema is the JSON schema published in tools/list to describe
	// the tool's accepted arguments. Built from the operation's
	// parameters + requestBody.
	InputSchema map[string]any `json:"inputSchema"`

	// Annotations are MCP tool annotations published in tools/list.
	Annotations *DerivedToolAnnotations `json:"annotations,omitempty"`

	// OutputSchema is the JSON schema published in tools/list to describe
	// structuredContent returned by successful tools/call responses.
	OutputSchema map[string]any `json:"outputSchema,omitempty"`
}

// DerivedToolAnnotations describes MCP tool annotations derived from the
// source REST operation and optional proxy-side overrides.
type DerivedToolAnnotations struct {
	Title           string `bson:"title,omitempty" json:"title,omitempty"`
	ReadOnlyHint    *bool  `bson:"readOnlyHint,omitempty" json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `bson:"destructiveHint,omitempty" json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `bson:"idempotentHint,omitempty" json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `bson:"openWorldHint,omitempty" json:"openWorldHint,omitempty"`
}

const (
	// MCPPrimitiveTypeTool is the only primitive type emitted in v1.
	MCPPrimitiveTypeTool = "tool"
	// MCPPrimitiveTypeResource is reserved for a future resource catalogue.
	MCPPrimitiveTypeResource = "resource"
)

const (
	// DerivedParamLocationPath identifies a path-template argument.
	DerivedParamLocationPath = "path"
	// DerivedParamLocationQuery identifies a query-string argument.
	DerivedParamLocationQuery = "query"
	// DerivedParamLocationHeader identifies a header argument.
	DerivedParamLocationHeader = "header"
	// DerivedParamLocationBody identifies the whole request body argument.
	DerivedParamLocationBody = "body"
	// DerivedParamLocationBodyPrefix identifies a single JSON body field.
	DerivedParamLocationBodyPrefix = DerivedParamLocationBody + "."
)

const (
	schemaKeyType        = "type"
	schemaKeyProperties  = "properties"
	schemaKeyRequired    = "required"
	schemaKeyDescription = "description"
	schemaKeyFormat      = "format"
	schemaKeyEnum        = "enum"
	schemaKeyItems       = "items"

	schemaTypeString  = "string"
	schemaTypeInteger = "integer"
	schemaTypeNumber  = "number"
	schemaTypeBoolean = "boolean"
	schemaTypeArray   = "array"
	schemaTypeObject  = "object"
)

const (
	warningMissingOperationID      = "missing operationId"
	warningOperationMarkedInternal = "operation marked internal - skipped"
	warningOperationMarkedBlocked  = "operation marked blocked - skipped"
	warningOperationNotSourceAllow = "operation not in source allow-list - skipped"
)

const (
	maxMCPToolNameLength      = 64
	contentTypeFormURLEncoded = "application/x-www-form-urlencoded"
)

// DerivedPrimitive is the internal primitive-aware catalogue entry used by the
// REST-to-MCP derivation layer. V1 emits only tool primitives; resources are
// reserved for v2 without changing this catalogue shape again.
type DerivedPrimitive struct {
	// Type identifies the MCP primitive category.
	Type string `json:"type"`
	// Tool holds the derived tool descriptor for tool primitives.
	Tool DerivedTool `json:"tool,omitempty"`
}

// DeriveWarning describes a non-fatal issue encountered while deriving
// tools — for example, a missing operationId or a source operation excluded by
// visibility controls.
type DeriveWarning struct {
	// Operation identifies the source operation that produced the warning.
	Operation string
	// Method is the HTTP method for the source operation.
	Method string
	// Path is the OAS path template for the source operation.
	Path string
	// Reason explains why the source operation was skipped or warned.
	Reason string
}

// DeriveSourcePrimitives walks a REST OAS document and produces the internal
// primitive catalogue for the synthetic MCP adapter. V1 emits only tool
// primitives.
func DeriveSourcePrimitives(srcOAS *OAS) ([]DerivedPrimitive, []DeriveWarning, error) {
	return deriveSourcePrimitives(srcOAS, nil)
}

// DeriveSourceTools walks a REST OAS document and produces a runtime
// tool catalogue for the synthetic MCP adapter.
//
// The function is pure and gateway-agnostic; the same inputs always
// yield the same outputs. It is called fresh on every reload — no
// snapshot is persisted.
//
// Exposure rules:
//   - If expose is nil or empty, every operation becomes a tool (default).
//   - Otherwise, only operations whose validated tool name appears in expose
//     are emitted.
//
// Tools are returned in deterministic (alphabetical-by-name) order so
// reload-to-reload diffs are stable.
func DeriveSourceTools(srcOAS *OAS, expose []string) ([]DerivedTool, []DeriveWarning, error) {
	primitives, warnings, err := deriveSourcePrimitives(srcOAS, expose)
	if err != nil {
		return nil, warnings, err
	}
	tools := ToolPrimitives(primitives)
	if err := validateDerivedToolNames(tools); err != nil {
		return nil, warnings, err
	}
	return tools, warnings, nil
}

// ToolPrimitives projects tool primitives into SDK-facing DerivedTool entries.
func ToolPrimitives(primitives []DerivedPrimitive) []DerivedTool {
	tools := make([]DerivedTool, 0, len(primitives))
	for _, primitive := range primitives {
		if primitive.Type == MCPPrimitiveTypeTool {
			tools = append(tools, primitive.Tool)
		}
	}
	return tools
}

func deriveSourcePrimitives(srcOAS *OAS, expose []string) ([]DerivedPrimitive, []DeriveWarning, error) {
	if srcOAS == nil {
		return nil, nil, fmt.Errorf("source OAS is nil")
	}

	var (
		primitives []DerivedPrimitive
		warnings   []DeriveWarning
		seen       = map[string]bool{}
		exposeSet  = buildExposeSet(expose)
	)

	if srcOAS.Paths == nil {
		return primitives, warnings, nil
	}

	visibility := sourceOperationVisibilityFromOAS(srcOAS)
	for _, p := range sortedPathKeys(srcOAS.Paths) {
		item := srcOAS.Paths.Map()[p]
		if item == nil {
			continue
		}

		for _, mo := range methodOperations(p, item) {
			primitive, warning, ok, err := deriveOperationPrimitive(item, mo, exposeSet, visibility, seen)
			if err != nil {
				return nil, warnings, err
			}
			if warning != nil {
				warnings = append(warnings, *warning)
			}
			if ok {
				primitives = append(primitives, primitive)
			}
		}
	}

	sort.Slice(primitives, func(i, j int) bool { return primitives[i].Tool.Name < primitives[j].Tool.Name })

	return primitives, warnings, nil
}

func buildExposeSet(expose []string) map[string]struct{} {
	if len(expose) == 0 {
		return nil
	}

	exposeSet := make(map[string]struct{}, len(expose))
	for _, name := range expose {
		exposeSet[name] = struct{}{}
	}
	return exposeSet
}

func sortedPathKeys(paths *openapi3.Paths) []string {
	keys := make([]string, 0, len(paths.Map()))
	for k := range paths.Map() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func deriveOperationPrimitive(
	item *openapi3.PathItem,
	mo derivedOp,
	exposeSet map[string]struct{},
	visibility sourceOperationVisibility,
	seen map[string]bool,
) (DerivedPrimitive, *DeriveWarning, bool, error) {

	rawName := mo.op.OperationID
	if rawName == "" {
		return DerivedPrimitive{}, deriveWarning(mo, fmt.Sprintf("%s %s", mo.method, mo.path), warningMissingOperationID), false, nil
	}

	if reason := visibility.skipReason(rawName); reason != "" {
		return DerivedPrimitive{}, deriveWarning(mo, rawName, reason), false, nil
	}

	name := rawName

	if seen[name] {
		return DerivedPrimitive{}, nil, false, fmt.Errorf("duplicate tool name %q", name)
	}

	if exposeSet != nil {
		if _, ok := exposeSet[name]; !ok {
			return DerivedPrimitive{}, nil, false, nil
		}
	}

	seen[name] = true
	locs, sourceNames, bodyContentType, schema, err := deriveParams(item, mo.op)
	if err != nil {
		return DerivedPrimitive{}, nil, false, fmt.Errorf("operationId %q: %w", rawName, err)
	}
	outputSchema := deriveOutputSchema(mo.op)

	return DerivedPrimitive{
		Type: MCPPrimitiveTypeTool,
		Tool: DerivedTool{
			OperationID:            rawName,
			SourceKey:              operationIDSourceKey(rawName),
			CanonicalName:          name,
			Name:                   name,
			Description:            operationDescription(mo.op),
			Method:                 mo.method,
			PathTemplate:           mo.path,
			ParamLocations:         locs,
			ParamSourceNames:       sourceNames,
			RequestBodyContentType: bodyContentType,
			InputSchema:            schema,
			Annotations:            defaultDerivedToolAnnotations(mo.method, mo.op, name),
			OutputSchema:           outputSchema,
		},
	}, nil, true, nil
}

func deriveWarning(mo derivedOp, operation, reason string) *DeriveWarning {
	return &DeriveWarning{
		Operation: operation,
		Method:    mo.method,
		Path:      mo.path,
		Reason:    reason,
	}
}

type sourceOperationVisibility struct {
	allowListEnabled bool
	allowed          map[string]bool
	blocked          map[string]bool
	internal         map[string]bool
}

func sourceOperationVisibilityFromOAS(srcOAS *OAS) sourceOperationVisibility {
	visibility := sourceOperationVisibility{
		allowed:  map[string]bool{},
		blocked:  map[string]bool{},
		internal: map[string]bool{},
	}
	if srcOAS == nil {
		return visibility
	}
	ext := srcOAS.GetTykExtension()
	if ext == nil || ext.Middleware == nil {
		return visibility
	}
	for opID, op := range ext.Middleware.Operations {
		if op == nil {
			continue
		}
		if op.Allow != nil && op.Allow.Enabled {
			visibility.allowListEnabled = true
			visibility.allowed[opID] = true
		}
		if op.Block != nil && op.Block.Enabled {
			visibility.blocked[opID] = true
		}
		if op.Internal != nil && op.Internal.Enabled {
			visibility.internal[opID] = true
		}
	}
	return visibility
}

func (v sourceOperationVisibility) skipReason(operationID string) string {
	if v.internal[operationID] {
		return warningOperationMarkedInternal
	}
	if v.blocked[operationID] {
		return warningOperationMarkedBlocked
	}
	if v.allowListEnabled && !v.allowed[operationID] {
		return warningOperationNotSourceAllow
	}
	return ""
}

type derivedOp struct {
	method string
	path   string
	op     *openapi3.Operation
}

func methodOperations(p string, item *openapi3.PathItem) []derivedOp {
	ops := []derivedOp{}
	add := func(method string, op *openapi3.Operation) {
		if op != nil {
			ops = append(ops, derivedOp{method: method, path: p, op: op})
		}
	}
	add(http.MethodGet, item.Get)
	add(http.MethodPut, item.Put)
	add(http.MethodPost, item.Post)
	add(http.MethodDelete, item.Delete)
	add(http.MethodOptions, item.Options)
	add(http.MethodHead, item.Head)
	add(http.MethodPatch, item.Patch)
	add(http.MethodTrace, item.Trace)
	return ops
}

func operationDescription(op *openapi3.Operation) string {
	if op.Summary != "" {
		return op.Summary
	}
	return op.Description
}

func defaultDerivedToolAnnotations(method string, op *openapi3.Operation, toolName string) *DerivedToolAnnotations {
	title := toolName
	if op != nil && op.Summary != "" {
		title = op.Summary
	}

	readOnly, destructive, idempotent, openWorld := defaultAnnotationHints(method)
	return &DerivedToolAnnotations{
		Title:           title,
		ReadOnlyHint:    boolRef(readOnly),
		DestructiveHint: boolRef(destructive),
		IdempotentHint:  boolRef(idempotent),
		OpenWorldHint:   boolRef(openWorld),
	}
}

func defaultAnnotationHints(method string) (readOnly, destructive, idempotent, openWorld bool) {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true, false, true, false
	case http.MethodPut, http.MethodDelete:
		return false, true, true, true
	default:
		return false, true, false, true
	}
}

func boolRef(v bool) *bool {
	return &v
}

var (
	toolNameInvalid = regexp.MustCompile(`[^A-Za-z0-9_.-]`)
	toolNameValid   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// ValidateMCPToolName enforces the gateway REST-as-MCP tool-name contract.
func ValidateMCPToolName(name string) error {
	if name == "" {
		return fmt.Errorf("invalid tool name: name is required")
	}
	if len(name) > maxMCPToolNameLength {
		return fmt.Errorf("invalid tool name %q: exceeds maximum length of %d", name, maxMCPToolNameLength)
	}
	if !toolNameValid.MatchString(name) {
		return fmt.Errorf("invalid tool name %q: use ASCII letters, digits, underscores, hyphens, and dots only", name)
	}
	return nil
}

func validateDerivedToolNames(tools []DerivedTool) error {
	for _, tool := range tools {
		if err := validateDerivedToolName(tool); err != nil {
			return err
		}
	}
	return nil
}

func validateDerivedToolName(tool DerivedTool) error {
	if err := ValidateMCPToolName(tool.Name); err != nil {
		if tool.OperationID != "" {
			return fmt.Errorf("operationId %q: %w", tool.OperationID, err)
		}
		if tool.SourceKey != "" {
			return fmt.Errorf("source %q: %w", tool.SourceKey, err)
		}
		return err
	}
	return nil
}

// SanitizeToolName strips characters MCP clients dislike.
//
// Deprecated: REST-as-MCP tool derivation validates tool names instead of
// silently sanitising them.
// The result is restricted to [A-Za-z0-9_.-]; consecutive runs of invalid
// characters collapse into a single underscore. Leading/trailing
// underscores are trimmed.
func SanitizeToolName(raw string) string {
	if raw == "" {
		return ""
	}
	cleaned := toolNameInvalid.ReplaceAllString(raw, "_")
	// collapse repeated underscores
	for strings.Contains(cleaned, "__") {
		cleaned = strings.ReplaceAll(cleaned, "__", "_")
	}
	return strings.Trim(cleaned, "_")
}

// deriveParams walks an operation's parameters and requestBody and returns
// (paramLocations, paramSourceNames, requestBodyContentType, inputSchema). The
// emitted schemas intentionally use a small JSON Schema subset that is valid
// under MCP's default JSON Schema 2020-12 interpretation.
func deriveParams(item *openapi3.PathItem, op *openapi3.Operation) (map[string]string, map[string]string, string, map[string]any, error) {
	params := newDerivedParams()
	params.addParameters(item.Parameters)
	params.addParameters(op.Parameters)
	params.addRequestBody(op.RequestBody)
	locations, sourceNames, schema, err := params.build()
	return locations, sourceNames, params.requestBodyContentType, schema, err
}

func schemaType(s *openapi3.Schema) string {
	if s == nil || s.Type == nil {
		if s != nil && len(s.Properties) > 0 {
			return schemaTypeObject
		}
		if s != nil && s.Items != nil {
			return schemaTypeArray
		}
		return ""
	}
	switch {
	case s.Type.Is(schemaTypeString):
		return schemaTypeString
	case s.Type.Is(schemaTypeInteger):
		return schemaTypeInteger
	case s.Type.Is(schemaTypeNumber):
		return schemaTypeNumber
	case s.Type.Is(schemaTypeBoolean):
		return schemaTypeBoolean
	case s.Type.Is(schemaTypeArray):
		return schemaTypeArray
	case s.Type.Is(schemaTypeObject):
		return schemaTypeObject
	}
	return ""
}

type derivedParam struct {
	sourceName string
	location   string
	schema     map[string]any
	required   bool
}

type derivedParams struct {
	params                 []derivedParam
	requestBodyContentType string
}

func newDerivedParams() derivedParams {
	return derivedParams{}
}

func (p *derivedParams) addParameters(params openapi3.Parameters) {
	for _, ref := range params {
		if ref != nil {
			p.addParameter(ref.Value)
		}
	}
}

func (p *derivedParams) addParameter(param *openapi3.Parameter) {
	if param == nil || param.Name == "" {
		return
	}

	location := parameterLocation(param.In)
	if location == "" {
		return
	}

	p.addOrReplace(derivedParam{
		sourceName: param.Name,
		location:   location,
		schema:     schemaForParameter(param),
		required:   param.Required,
	})
}

func parameterLocation(in string) string {
	switch in {
	case openapi3.ParameterInPath:
		return DerivedParamLocationPath
	case openapi3.ParameterInQuery:
		return DerivedParamLocationQuery
	case openapi3.ParameterInHeader:
		return DerivedParamLocationHeader
	default:
		return ""
	}
}

func schemaForParameter(param *openapi3.Parameter) map[string]any {
	schema := map[string]any{schemaKeyType: schemaTypeString}
	if param.Schema != nil && param.Schema.Value != nil {
		schema = schemaForOpenAPISchema(param.Schema.Value, schemaTypeString)
	}
	if param.Description != "" {
		schema[schemaKeyDescription] = param.Description
	}
	return schema
}

func (p *derivedParams) addRequestBody(ref *openapi3.RequestBodyRef) {
	if ref == nil || ref.Value == nil {
		return
	}

	rb := ref.Value
	media, contentType := selectRequestBodyMediaType(rb.Content)
	if media == nil || media.Schema == nil || media.Schema.Value == nil {
		return
	}
	p.requestBodyContentType = contentType

	body := media.Schema.Value
	if body.Type != nil && body.Type.Is(schemaTypeObject) && len(body.Properties) > 0 {
		p.addRequestBodyFields(body)
		return
	}

	p.addOrReplace(derivedParam{
		sourceName: DerivedParamLocationBody,
		location:   DerivedParamLocationBody,
		schema:     schemaForOpenAPISchema(body, schemaTypeObject),
		required:   rb.Required,
	})
}

func (p *derivedParams) addRequestBodyFields(body *openapi3.Schema) {
	bodyRequired := make(map[string]struct{}, len(body.Required))
	for _, name := range body.Required {
		bodyRequired[name] = struct{}{}
	}

	for _, name := range sortedSchemaPropertyNames(body.Properties) {
		_, required := bodyRequired[name]
		p.addOrReplace(derivedParam{
			sourceName: name,
			location:   DerivedParamLocationBodyPrefix + name,
			schema:     schemaForSchemaRef(body.Properties[name], schemaTypeString),
			required:   required,
		})
	}
}

func (p *derivedParams) addOrReplace(param derivedParam) {
	for i, existing := range p.params {
		if existing.sourceName == param.sourceName && existing.location == param.location {
			p.params[i] = param
			return
		}
	}
	p.params = append(p.params, param)
}

func (p *derivedParams) build() (map[string]string, map[string]string, map[string]any, error) {
	nameCounts := make(map[string]int, len(p.params))
	for _, param := range p.params {
		nameCounts[param.sourceName]++
	}

	locations := make(map[string]string, len(p.params))
	sourceNames := make(map[string]string, len(p.params))
	props := make(map[string]any, len(p.params))
	required := map[string]struct{}{}

	for _, param := range p.params {
		name := exposedParamName(param, nameCounts[param.sourceName] > 1)
		if _, duplicate := locations[name]; duplicate {
			return nil, nil, nil, fmt.Errorf("duplicate exposed parameter name %q", name)
		}
		locations[name] = param.location
		sourceNames[name] = param.sourceName
		props[name] = param.schema
		if param.required {
			required[name] = struct{}{}
		}
	}

	schema := map[string]any{
		schemaKeyType:       schemaTypeObject,
		schemaKeyProperties: props,
	}
	if len(required) > 0 {
		schema[schemaKeyRequired] = sortedRequiredNames(required)
	}
	return locations, sourceNames, schema, nil
}

func exposedParamName(param derivedParam, collides bool) string {
	if !collides || isBodyParamLocation(param.location) {
		return param.sourceName
	}
	return param.location + "_" + param.sourceName
}

func isBodyParamLocation(location string) bool {
	return location == DerivedParamLocationBody || strings.HasPrefix(location, DerivedParamLocationBodyPrefix)
}

func selectRequestBodyMediaType(content openapi3.Content) (*openapi3.MediaType, string) {
	if media := selectJSONMediaType(content); media != nil {
		return media, contentTypeJSON
	}
	if media := selectFormURLEncodedMediaType(content); media != nil {
		return media, contentTypeFormURLEncoded
	}
	return nil, ""
}

func selectJSONMediaType(content openapi3.Content) *openapi3.MediaType {
	if len(content) == 0 {
		return nil
	}

	for ct, media := range content {
		if strings.EqualFold(ct, contentTypeJSON) {
			return media
		}
	}

	jsonTypes := make([]string, 0, len(content))
	for ct := range content {
		if strings.Contains(strings.ToLower(ct), "json") {
			jsonTypes = append(jsonTypes, ct)
		}
	}
	sort.Strings(jsonTypes)
	for _, ct := range jsonTypes {
		if media := content[ct]; media != nil {
			return media
		}
	}
	return nil
}

func selectFormURLEncodedMediaType(content openapi3.Content) *openapi3.MediaType {
	if len(content) == 0 {
		return nil
	}
	for ct, media := range content {
		if strings.EqualFold(strings.TrimSpace(ct), contentTypeFormURLEncoded) {
			return media
		}
	}
	for ct, media := range content {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), contentTypeFormURLEncoded+";") {
			return media
		}
	}
	return nil
}

func sortedSchemaPropertyNames(props openapi3.Schemas) []string {
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func schemaForSchemaRef(ref *openapi3.SchemaRef, fallbackType string) map[string]any {
	if ref == nil || ref.Value == nil {
		return map[string]any{schemaKeyType: fallbackType}
	}
	return schemaForOpenAPISchema(ref.Value, fallbackType)
}

func schemaForOpenAPISchema(src *openapi3.Schema, fallbackType string) map[string]any {
	schema := map[string]any{}
	if fallbackType != "" {
		schema[schemaKeyType] = fallbackType
	}
	if src == nil {
		return schema
	}
	if t := schemaType(src); t != "" {
		schema[schemaKeyType] = t
	}
	if src.Description != "" {
		schema[schemaKeyDescription] = src.Description
	}
	if src.Format != "" {
		schema[schemaKeyFormat] = src.Format
	}
	if len(src.Enum) > 0 {
		schema[schemaKeyEnum] = append([]any(nil), src.Enum...)
	}
	if len(src.Properties) > 0 {
		props := make(map[string]any, len(src.Properties))
		for _, name := range sortedSchemaPropertyNames(src.Properties) {
			props[name] = schemaForSchemaRef(src.Properties[name], "")
		}
		schema[schemaKeyProperties] = props
	}
	if len(src.Required) > 0 {
		required := append([]string(nil), src.Required...)
		sort.Strings(required)
		schema[schemaKeyRequired] = required
	}
	if src.Items != nil {
		schema[schemaKeyItems] = schemaForSchemaRef(src.Items, "")
	}
	return schema
}

func deriveOutputSchema(op *openapi3.Operation) map[string]any {
	if op == nil || op.Responses == nil {
		return nil
	}

	if schemaRef := responseJSONSchema(op.Responses.Value("200")); schemaRef != nil {
		return mcpOutputSchemaForSchemaRef(schemaRef)
	}

	for _, status := range sortedNumeric2xxResponseStatuses(op.Responses) {
		if status == http.StatusOK || status == http.StatusNoContent {
			continue
		}
		if schemaRef := responseJSONSchema(op.Responses.Value(fmt.Sprintf("%d", status))); schemaRef != nil {
			return mcpOutputSchemaForSchemaRef(schemaRef)
		}
	}
	return nil
}

func sortedNumeric2xxResponseStatuses(responses *openapi3.Responses) []int {
	statuses := []int{}
	for status := range responses.Map() {
		code, err := strconv.Atoi(status)
		if err != nil {
			continue
		}
		if code >= 200 && code < 300 {
			statuses = append(statuses, code)
		}
	}
	sort.Ints(statuses)
	return statuses
}

func responseJSONSchema(responseRef *openapi3.ResponseRef) *openapi3.SchemaRef {
	if responseRef == nil || responseRef.Value == nil {
		return nil
	}
	media := selectJSONMediaType(responseRef.Value.Content)
	if media == nil || media.Schema == nil || media.Schema.Value == nil {
		return nil
	}
	return media.Schema
}

func mcpOutputSchemaForSchemaRef(ref *openapi3.SchemaRef) map[string]any {
	schema := schemaForSchemaRef(ref, "")
	if schema[schemaKeyType] == schemaTypeObject {
		return schema
	}
	return map[string]any{
		schemaKeyType: schemaTypeObject,
		schemaKeyProperties: map[string]any{
			"result": schema,
		},
		schemaKeyRequired: []string{"result"},
	}
}

func sortedRequiredNames(required map[string]struct{}) []string {
	names := make([]string, 0, len(required))
	for name := range required {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// MCPToolView is the proxy-specific list of MCP tools exposed by one
// REST-as-MCP proxy. Tool entries retain their canonical source operation
// fields so aliases can be mapped back before issuing REST requests.
type MCPToolView struct {
	// Tools is the proxy-specific caller-facing tool catalogue.
	Tools []DerivedTool `json:"tools,omitempty"`
}

// ToolNames returns visible tool names in view order.
func (v MCPToolView) ToolNames() []string {
	names := make([]string, 0, len(v.Tools))
	for _, tool := range v.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// ToolByName returns the visible tool descriptor for a caller-facing name.
func (v MCPToolView) ToolByName(name string) (DerivedTool, bool) {
	for _, tool := range v.Tools {
		if tool.Name == name {
			return tool, true
		}
	}
	return DerivedTool{}, false
}

// DeriveMCPToolView builds a proxy-specific MCP tool view from source REST
// primitives and an optional x-tyk-mcp-server extension.
func DeriveMCPToolView(srcOAS *OAS, config *TykMCPServer) (MCPToolView, []DeriveWarning, error) {
	primitives, warnings, err := DeriveSourcePrimitives(srcOAS)
	if err != nil {
		return MCPToolView{}, warnings, err
	}

	tools := ToolPrimitives(primitives)
	configuredPathTools, err := deriveConfiguredPathMethodTools(srcOAS, config, tools)
	if err != nil {
		return MCPToolView{}, warnings, err
	}
	tools = append(tools, configuredPathTools...)

	view, err := BuildMCPToolView(tools, config)
	return view, warnings, err
}

// BuildMCPToolView applies a proxy-side x-tyk-mcp-server extension to a
// canonical source tool catalogue.
func BuildMCPToolView(canonical []DerivedTool, config *TykMCPServer) (MCPToolView, error) {
	catalogue := newMCPToolViewCatalogue(canonical)
	selection, err := buildMCPToolViewSelection(config, catalogue)
	if err != nil {
		return MCPToolView{}, err
	}

	view := MCPToolView{Tools: make([]DerivedTool, 0, len(selection.sourceKeys))}
	seenNames := make(map[string]string, len(selection.sourceKeys))
	for _, sourceKey := range selection.sourceKeys {
		tool := cloneDerivedTool(catalogue.bySourceKey[sourceKey])
		if override, ok := selection.overrides[sourceKey]; ok {
			if err := applyMCPToolViewOverride(&tool, override); err != nil {
				return MCPToolView{}, err
			}
		}
		if err := validateDerivedToolName(tool); err != nil {
			return MCPToolView{}, err
		}

		if existing, duplicate := seenNames[tool.Name]; duplicate {
			return MCPToolView{}, fmt.Errorf("duplicate exposed tool name %q for sources %q and %q", tool.Name, existing, sourceKey)
		}
		seenNames[tool.Name] = sourceKey
		view.Tools = append(view.Tools, tool)
	}

	sort.Slice(view.Tools, func(i, j int) bool { return view.Tools[i].Name < view.Tools[j].Name })
	return view, nil
}

const (
	sourceSelectorOperationID = "operationId"
	sourceSelectorPathMethod  = "path+method"
)

type mcpToolViewCatalogue struct {
	tools       []DerivedTool
	bySourceKey map[string]DerivedTool
}

type mcpToolViewSelection struct {
	sourceKeys []string
	overrides  map[string]TykMCPServerPrimitive
}

func newMCPToolViewCatalogue(tools []DerivedTool) mcpToolViewCatalogue {
	catalogue := mcpToolViewCatalogue{
		tools:       make([]DerivedTool, 0, len(tools)),
		bySourceKey: make(map[string]DerivedTool, len(tools)),
	}
	for _, tool := range tools {
		normalised := normaliseCanonicalTool(tool)
		if normalised.SourceKey == "" {
			continue
		}
		if _, exists := catalogue.bySourceKey[normalised.SourceKey]; exists {
			continue
		}
		catalogue.tools = append(catalogue.tools, normalised)
		catalogue.bySourceKey[normalised.SourceKey] = normalised
	}
	return catalogue
}

func normaliseCanonicalTool(tool DerivedTool) DerivedTool {
	if tool.CanonicalName == "" {
		tool.CanonicalName = tool.Name
	}
	if tool.SourceKey == "" && tool.OperationID != "" {
		tool.SourceKey = operationIDSourceKey(tool.OperationID)
	}
	if tool.SourceKey == "" && tool.Method != "" && tool.PathTemplate != "" {
		tool.SourceKey = pathMethodSourceKey(tool.Method, tool.PathTemplate)
	}
	if tool.SourceKey == "" && tool.OperationID == "" {
		tool.OperationID = tool.CanonicalName
		if tool.OperationID != "" {
			tool.SourceKey = operationIDSourceKey(tool.OperationID)
		}
	}
	return tool
}

func buildMCPToolViewSelection(config *TykMCPServer, catalogue mcpToolViewCatalogue) (mcpToolViewSelection, error) {
	selection := mcpToolViewSelection{
		overrides: map[string]TykMCPServerPrimitive{},
	}
	explicitAllow := false

	if config != nil {
		seenSourceKeys := map[string]struct{}{}
		for _, primitive := range config.Primitives {
			sourceKey, _, err := mcpPrimitiveSourceKey(primitive.Source)
			if err != nil {
				return selection, err
			}
			tool, ok := catalogue.bySourceKey[sourceKey]
			if !ok {
				return selection, fmt.Errorf("%s primitive references non-exposable source %q", ExtensionTykMCPServer, sourceKey)
			}
			if _, duplicate := seenSourceKeys[sourceKey]; duplicate {
				return selection, fmt.Errorf("%s has duplicate primitive source %q", ExtensionTykMCPServer, sourceKey)
			}
			seenSourceKeys[sourceKey] = struct{}{}

			if err := validateMCPToolViewParameterOverrides(tool, primitive); err != nil {
				return selection, err
			}
			selection.overrides[sourceKey] = primitive

			if primitive.Allow != nil && *primitive.Allow {
				explicitAllow = true
				selection.sourceKeys = append(selection.sourceKeys, sourceKey)
			}
		}
	}

	if explicitAllow {
		return selection, nil
	}

	selection.sourceKeys = make([]string, 0, len(catalogue.tools))
	for _, tool := range catalogue.tools {
		selection.sourceKeys = append(selection.sourceKeys, tool.SourceKey)
	}
	return selection, nil
}

func deriveConfiguredPathMethodTools(srcOAS *OAS, config *TykMCPServer, canonical []DerivedTool) ([]DerivedTool, error) {
	if config == nil || len(config.Primitives) == 0 {
		return nil, nil
	}

	catalogue := newMCPToolViewCatalogue(canonical)
	var tools []DerivedTool
	seen := map[string]struct{}{}
	for _, primitive := range config.Primitives {
		sourceKey, selector, err := mcpPrimitiveSourceKey(primitive.Source)
		if err != nil {
			return nil, err
		}
		if selector != sourceSelectorPathMethod {
			continue
		}
		if _, duplicate := seen[sourceKey]; duplicate {
			continue
		}
		seen[sourceKey] = struct{}{}
		if _, exists := catalogue.bySourceKey[sourceKey]; exists {
			continue
		}

		tool, err := deriveConfiguredPathMethodTool(srcOAS, primitive)
		if err != nil {
			return nil, err
		}
		tools = append(tools, tool)
	}
	return tools, nil
}

func deriveConfiguredPathMethodTool(srcOAS *OAS, primitive TykMCPServerPrimitive) (DerivedTool, error) {
	path := strings.TrimSpace(primitive.Source.Path)
	method := strings.ToUpper(strings.TrimSpace(primitive.Source.Method))
	item, mo, ok := sourceOperationByPathMethod(srcOAS, path, method)
	if !ok {
		return DerivedTool{}, fmt.Errorf("%s primitive source %s %s references unknown source operation", ExtensionTykMCPServer, method, path)
	}
	if mo.op.OperationID != "" {
		return DerivedTool{}, fmt.Errorf("%s primitive source %s %s has operationId %q; use source.operationId", ExtensionTykMCPServer, method, path, mo.op.OperationID)
	}
	visibility := sourceOperationVisibilityFromOAS(srcOAS)
	if visibility.allowListEnabled {
		return DerivedTool{}, fmt.Errorf("%s primitive source %s %s references non-exposable operation because source allow-list requires operationId", ExtensionTykMCPServer, method, path)
	}

	name := strings.TrimSpace(primitive.Name)
	if name == "" {
		return DerivedTool{}, fmt.Errorf("%s primitive source %s %s name is required for operations without operationId", ExtensionTykMCPServer, method, path)
	}
	if err := ValidateMCPToolName(name); err != nil {
		return DerivedTool{}, fmt.Errorf("%s primitive source %s %s: %w", ExtensionTykMCPServer, method, path, err)
	}

	locs, sourceNames, bodyContentType, schema, err := deriveParams(item, mo.op)
	if err != nil {
		return DerivedTool{}, fmt.Errorf("source %s %s: %w", method, path, err)
	}
	outputSchema := deriveOutputSchema(mo.op)
	return DerivedTool{
		SourceKey:              pathMethodSourceKey(method, path),
		CanonicalName:          name,
		Name:                   name,
		Description:            operationDescription(mo.op),
		Method:                 method,
		PathTemplate:           path,
		ParamLocations:         locs,
		ParamSourceNames:       sourceNames,
		RequestBodyContentType: bodyContentType,
		InputSchema:            schema,
		Annotations:            defaultDerivedToolAnnotations(method, mo.op, name),
		OutputSchema:           outputSchema,
	}, nil
}

func sourceOperationByPathMethod(srcOAS *OAS, path, method string) (*openapi3.PathItem, derivedOp, bool) {
	if srcOAS == nil || srcOAS.Paths == nil {
		return nil, derivedOp{}, false
	}
	item := srcOAS.Paths.Map()[path]
	if item == nil {
		return nil, derivedOp{}, false
	}
	for _, mo := range methodOperations(path, item) {
		if strings.EqualFold(mo.method, method) {
			return item, mo, true
		}
	}
	return nil, derivedOp{}, false
}

func mcpPrimitiveSourceKey(source TykMCPServerSource) (string, string, error) {
	operationID := strings.TrimSpace(source.OperationID)
	path := strings.TrimSpace(source.Path)
	method := strings.TrimSpace(source.Method)
	hasOperationID := operationID != ""
	hasPathMethod := path != "" || method != ""

	if hasOperationID == hasPathMethod {
		return "", "", fmt.Errorf("%s primitive source must specify exactly one source selector: operationId or path+method", ExtensionTykMCPServer)
	}
	if hasOperationID {
		return operationIDSourceKey(operationID), sourceSelectorOperationID, nil
	}
	if path == "" || method == "" {
		return "", "", fmt.Errorf("%s primitive source path+method selector requires both path and method", ExtensionTykMCPServer)
	}
	return pathMethodSourceKey(method, path), sourceSelectorPathMethod, nil
}

func operationIDSourceKey(operationID string) string {
	return "operationId:" + operationID
}

func pathMethodSourceKey(method, path string) string {
	return fmt.Sprintf("http:%s %s", strings.ToUpper(strings.TrimSpace(method)), strings.TrimSpace(path))
}

func validateMCPToolViewParameterOverrides(tool DerivedTool, primitive TykMCPServerPrimitive) error {
	sourceKey, _, err := mcpPrimitiveSourceKey(primitive.Source)
	if err != nil {
		return err
	}

	seen := map[string]struct{}{}
	for _, param := range primitive.Parameters {
		if param.Param == "" {
			return fmt.Errorf("%s primitive %q has parameter override missing param", ExtensionTykMCPServer, sourceKey)
		}
		if _, duplicate := seen[param.Param]; duplicate {
			return fmt.Errorf("%s primitive %q has duplicate parameter override %q", ExtensionTykMCPServer, sourceKey, param.Param)
		}
		seen[param.Param] = struct{}{}
		if _, ok := tool.ParamLocations[param.Param]; !ok {
			return fmt.Errorf("%s primitive %q references unknown parameter %q", ExtensionTykMCPServer, sourceKey, param.Param)
		}
	}
	return nil
}

func applyMCPToolViewOverride(tool *DerivedTool, override TykMCPServerPrimitive) error {
	if override.Name != "" {
		name := strings.TrimSpace(override.Name)
		if err := ValidateMCPToolName(name); err != nil {
			return fmt.Errorf("%s primitive %q: %w", ExtensionTykMCPServer, sourceKeyForMCPPrimitiveMessage(override), err)
		}
		if tool.Annotations != nil && tool.Annotations.Title == tool.Name {
			tool.Annotations.Title = name
		}
		tool.Name = name
	}
	if override.Description != "" {
		tool.Description = override.Description
	}
	applyMCPToolAnnotationOverrides(tool, override.Annotations)
	for _, param := range override.Parameters {
		paramName := param.Param
		if param.Name != "" {
			if err := renameMCPToolParameter(tool, param.Param, param.Name); err != nil {
				return fmt.Errorf("%s primitive %q: %w", ExtensionTykMCPServer, sourceKeyForMCPPrimitiveMessage(override), err)
			}
			paramName = param.Name
		}
		if param.Description != "" {
			setMCPToolParameterDescription(tool, paramName, param.Description)
		}
	}
	return nil
}

func applyMCPToolAnnotationOverrides(tool *DerivedTool, override *DerivedToolAnnotations) {
	if override == nil {
		return
	}
	if tool.Annotations == nil {
		tool.Annotations = &DerivedToolAnnotations{}
	}
	if override.Title != "" {
		tool.Annotations.Title = override.Title
	}
	if override.ReadOnlyHint != nil {
		tool.Annotations.ReadOnlyHint = boolRef(*override.ReadOnlyHint)
	}
	if override.DestructiveHint != nil {
		tool.Annotations.DestructiveHint = boolRef(*override.DestructiveHint)
	}
	if override.IdempotentHint != nil {
		tool.Annotations.IdempotentHint = boolRef(*override.IdempotentHint)
	}
	if override.OpenWorldHint != nil {
		tool.Annotations.OpenWorldHint = boolRef(*override.OpenWorldHint)
	}
}

func sourceKeyForMCPPrimitiveMessage(primitive TykMCPServerPrimitive) string {
	sourceKey, _, err := mcpPrimitiveSourceKey(primitive.Source)
	if err != nil {
		return "<invalid source>"
	}
	return sourceKey
}

func renameMCPToolParameter(tool *DerivedTool, oldName, newName string) error {
	newName = strings.TrimSpace(newName)
	if err := ValidateMCPToolName(newName); err != nil {
		return fmt.Errorf("parameter override %q: %w", oldName, err)
	}
	if oldName == newName {
		return nil
	}

	location, ok := tool.ParamLocations[oldName]
	if !ok {
		return fmt.Errorf("parameter override references unknown parameter %q", oldName)
	}
	if _, duplicate := tool.ParamLocations[newName]; duplicate {
		return fmt.Errorf("parameter override renames %q to duplicate parameter %q", oldName, newName)
	}

	delete(tool.ParamLocations, oldName)
	tool.ParamLocations[newName] = location

	if tool.ParamSourceNames == nil {
		tool.ParamSourceNames = map[string]string{}
	}
	sourceName := tool.ParamSourceNames[oldName]
	if sourceName == "" {
		sourceName = oldName
	}
	delete(tool.ParamSourceNames, oldName)
	tool.ParamSourceNames[newName] = sourceName

	renameMCPToolInputSchemaParameter(tool, oldName, newName)
	return nil
}

func renameMCPToolInputSchemaParameter(tool *DerivedTool, oldName, newName string) {
	if tool.InputSchema == nil {
		return
	}

	props, ok := tool.InputSchema[schemaKeyProperties].(map[string]any)
	if ok {
		if prop, exists := props[oldName]; exists {
			delete(props, oldName)
			props[newName] = prop
		}
	}

	switch required := tool.InputSchema[schemaKeyRequired].(type) {
	case []string:
		for i, name := range required {
			if name == oldName {
				required[i] = newName
			}
		}
		sort.Strings(required)
	case []any:
		for i, name := range required {
			if name == oldName {
				required[i] = newName
			}
		}
		sort.Slice(required, func(i, j int) bool {
			return fmt.Sprint(required[i]) < fmt.Sprint(required[j])
		})
	}
}

func setMCPToolParameterDescription(tool *DerivedTool, paramName, description string) {
	if tool.InputSchema == nil {
		tool.InputSchema = map[string]any{schemaKeyType: schemaTypeObject}
	}

	props, ok := tool.InputSchema[schemaKeyProperties].(map[string]any)
	if !ok {
		props = map[string]any{}
		tool.InputSchema[schemaKeyProperties] = props
	}

	prop, ok := props[paramName].(map[string]any)
	if !ok {
		prop = map[string]any{}
		props[paramName] = prop
	}
	prop[schemaKeyDescription] = description
}

func cloneDerivedTool(tool DerivedTool) DerivedTool {
	tool = normaliseCanonicalTool(tool)

	if tool.ParamLocations != nil {
		locations := make(map[string]string, len(tool.ParamLocations))
		for k, v := range tool.ParamLocations {
			locations[k] = v
		}
		tool.ParamLocations = locations
	}
	if tool.ParamSourceNames != nil {
		sourceNames := make(map[string]string, len(tool.ParamSourceNames))
		for k, v := range tool.ParamSourceNames {
			sourceNames[k] = v
		}
		tool.ParamSourceNames = sourceNames
	}
	tool.InputSchema = cloneMapAny(tool.InputSchema)
	tool.Annotations = cloneDerivedToolAnnotations(tool.Annotations)
	tool.OutputSchema = cloneMapAny(tool.OutputSchema)
	return tool
}

func cloneDerivedToolAnnotations(src *DerivedToolAnnotations) *DerivedToolAnnotations {
	if src == nil {
		return nil
	}
	dst := &DerivedToolAnnotations{
		Title: src.Title,
	}
	if src.ReadOnlyHint != nil {
		dst.ReadOnlyHint = boolRef(*src.ReadOnlyHint)
	}
	if src.DestructiveHint != nil {
		dst.DestructiveHint = boolRef(*src.DestructiveHint)
	}
	if src.IdempotentHint != nil {
		dst.IdempotentHint = boolRef(*src.IdempotentHint)
	}
	if src.OpenWorldHint != nil {
		dst.OpenWorldHint = boolRef(*src.OpenWorldHint)
	}
	return dst
}

func cloneMapAny(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}

	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = cloneAny(v)
	}
	return dst
}

func cloneAny(src any) any {
	switch v := src.(type) {
	case map[string]any:
		return cloneMapAny(v)
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = cloneAny(v[i])
		}
		return out
	case []string:
		return append([]string(nil), v...)
	default:
		return v
	}
}

const (
	// AdapterLoopPath is the default path marker used in tyk:// URLs to
	// address the REST-as-MCP adapter paired with the source REST API in
	// the URL host.
	AdapterLoopPath = "/mcp"

	// AdapterAPIIDSuffix is the fallback suffix appended to the source REST
	// APIID to form a synthetic adapter host when the source OAS already has
	// a real /mcp endpoint.
	AdapterAPIIDSuffix = "__mcp-server"
)

// AdapterAPIID returns the fallback synthetic adapter APIID paired with the
// given REST API.
func AdapterAPIID(restAPIID string) string {
	return restAPIID + AdapterAPIIDSuffix
}

// IsAdapterAPIID reports whether an APIID is the fallback synthetic adapter ID
// derived from some REST APIID via AdapterAPIID.
func IsAdapterAPIID(id string) bool {
	return strings.HasSuffix(id, AdapterAPIIDSuffix) && len(id) > len(AdapterAPIIDSuffix)
}

// AdapterSourceAPIID returns the REST APIID corresponding to a fallback
// synthetic adapter APIID, or "" if id is not an adapter ID.
func AdapterSourceAPIID(id string) string {
	if !IsAdapterAPIID(id) {
		return ""
	}
	return strings.TrimSuffix(id, AdapterAPIIDSuffix)
}

// IsAdapterLoopPath reports whether a tyk:// URL path addresses the
// REST-as-MCP adapter.
func IsAdapterLoopPath(path string) bool {
	return path == AdapterLoopPath || path == AdapterLoopPath+"/"
}

// SourceHasAdapterLoopPath reports whether the source OAS already defines the
// default REST-as-MCP adapter path.
func SourceHasAdapterLoopPath(srcOAS *OAS) bool {
	if srcOAS == nil || srcOAS.Paths == nil {
		return false
	}
	return srcOAS.Paths.Value(AdapterLoopPath) != nil || srcOAS.Paths.Value(AdapterLoopPath+"/") != nil
}

// AdapterLoopHost returns the host portion of the tyk:// URL used by an
// MCP proxy to address its REST source API.
func AdapterLoopHost(restAPIID string) string {
	return restAPIID
}

// AdapterLoopURL returns the full tyk:// URL an MCP proxy should set as
// its upstream to dispatch into the paired adapter.
func AdapterLoopURL(restAPIID string) string {
	return "tyk://" + AdapterLoopHost(restAPIID) + AdapterLoopPath
}

// AdapterFallbackLoopHost returns the fallback host portion of the tyk:// URL
// used when the source REST OAS already defines /mcp.
func AdapterFallbackLoopHost(restAPIID string) string {
	return AdapterAPIID(restAPIID)
}

// AdapterFallbackLoopURL returns the fallback tyk:// URL an MCP proxy should
// use when the source REST OAS already defines /mcp.
func AdapterFallbackLoopURL(restAPIID string) string {
	return "tyk://" + AdapterFallbackLoopHost(restAPIID)
}

// AdapterLoopURLForSource returns the canonical adapter target for the source
// OAS, falling back to a synthetic adapter host when /mcp is already a source
// endpoint.
func AdapterLoopURLForSource(restAPIID string, srcOAS *OAS) string {
	if SourceHasAdapterLoopPath(srcOAS) {
		return AdapterFallbackLoopURL(restAPIID)
	}
	return AdapterLoopURL(restAPIID)
}

// ParseAdapterTarget extracts the adapter host and REST source APIID from a
// REST-as-MCP tyk:// adapter target.
func ParseAdapterTarget(target string) (adapterID, restAPIID string, ok bool) {
	host, path, ok := parseTykAdapterTarget(target)
	if !ok {
		return "", "", false
	}
	if IsAdapterAPIID(host) {
		if path != "" && path != "/" {
			return "", "", false
		}
		return host, AdapterSourceAPIID(host), true
	}
	if IsAdapterLoopPath(path) {
		return host, host, true
	}
	return "", "", false
}

func parseTykAdapterTarget(target string) (host, path string, ok bool) {
	target = strings.TrimSpace(target)
	const scheme = "tyk://"
	if !strings.HasPrefix(target, scheme) {
		return "", "", false
	}

	rest := strings.TrimPrefix(target, scheme)
	rest = strings.TrimPrefix(rest, "id:")
	if rest == "" {
		return "", "", false
	}

	hostEnd := len(rest)
	if i := strings.IndexAny(rest, "/?#"); i != -1 {
		hostEnd = i
	}
	host = rest[:hostEnd]
	if host == "" {
		return "", "", false
	}

	if hostEnd < len(rest) && rest[hostEnd] == '/' {
		pathEnd := len(rest)
		if i := strings.IndexAny(rest[hostEnd:], "?#"); i != -1 {
			pathEnd = hostEnd + i
		}
		path = rest[hostEnd:pathEnd]
	}

	return host, path, true
}
