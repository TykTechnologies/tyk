package oas

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
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
	// Name is the sanitised operationId — the tool name agents call.
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
	ParamLocations map[string]string `json:"-"`

	// InputSchema is the JSON schema published in tools/list to describe
	// the tool's accepted arguments. Built from the operation's
	// parameters + requestBody.
	InputSchema map[string]any `json:"inputSchema"`
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

	schemaTypeString  = "string"
	schemaTypeInteger = "integer"
	schemaTypeNumber  = "number"
	schemaTypeBoolean = "boolean"
	schemaTypeArray   = "array"
	schemaTypeObject  = "object"
)

const (
	warningMissingOperationID      = "missing operationId"
	warningEmptySanitizedToolName  = "operationId sanitises to empty string"
	warningToolNameCollision       = "tool name collision after sanitisation"
	warningOperationMarkedInternal = "operation marked internal - skipped"
	warningOperationMarkedBlocked  = "operation marked blocked - skipped"
	warningOperationNotSourceAllow = "operation not in source allow-list - skipped"
)

// DerivedPrimitive is the internal primitive-aware catalogue entry used by the
// REST-to-MCP derivation layer. V1 emits only tool primitives; resources are
// reserved for v2 without changing this catalogue shape again.
type DerivedPrimitive struct {
	Type string      `json:"type"`
	Tool DerivedTool `json:"tool,omitempty"`
}

// DeriveWarning describes a non-fatal issue encountered while deriving
// tools — for example, a collision between two operationIds after
// sanitisation, or a parameter type that could not be represented.
type DeriveWarning struct {
	Operation string
	Method    string
	Path      string
	Reason    string
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
//   - Otherwise, only operations whose sanitised name appears in expose
//     are emitted.
//
// Tools are returned in deterministic (alphabetical-by-name) order so
// reload-to-reload diffs are stable.
func DeriveSourceTools(srcOAS *OAS, expose []string) ([]DerivedTool, []DeriveWarning, error) {
	primitives, warnings, err := deriveSourcePrimitives(srcOAS, expose)
	if err != nil {
		return nil, warnings, err
	}
	return ToolPrimitives(primitives), warnings, nil
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
			primitive, warning, ok := deriveOperationPrimitive(item, mo, exposeSet, visibility, seen)
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
		exposeSet[SanitizeToolName(name)] = struct{}{}
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
) (DerivedPrimitive, *DeriveWarning, bool) {

	rawName := mo.op.OperationID
	if rawName == "" {
		return DerivedPrimitive{}, deriveWarning(mo, fmt.Sprintf("%s %s", mo.method, mo.path), warningMissingOperationID), false
	}

	if reason := visibility.skipReason(rawName); reason != "" {
		return DerivedPrimitive{}, deriveWarning(mo, rawName, reason), false
	}

	name := SanitizeToolName(rawName)
	if name == "" {
		return DerivedPrimitive{}, deriveWarning(mo, rawName, warningEmptySanitizedToolName), false
	}

	if seen[name] {
		return DerivedPrimitive{}, deriveWarning(mo, rawName, warningToolNameCollision), false
	}

	if exposeSet != nil {
		if _, ok := exposeSet[name]; !ok {
			return DerivedPrimitive{}, nil, false
		}
	}

	seen[name] = true
	locs, schema := deriveParams(item, mo.op)

	return DerivedPrimitive{
		Type: MCPPrimitiveTypeTool,
		Tool: DerivedTool{
			Name:           name,
			Description:    operationDescription(mo.op),
			Method:         mo.method,
			PathTemplate:   mo.path,
			ParamLocations: locs,
			InputSchema:    schema,
		},
	}, nil, true
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

var toolNameInvalid = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

// SanitizeToolName strips characters MCP clients dislike.
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

// deriveParams walks an operation's parameters and requestBody and
// returns (paramLocations, inputSchema). The schema follows the JSON
// Schema draft-07 dialect that MCP clients expect for tool inputs.
func deriveParams(item *openapi3.PathItem, op *openapi3.Operation) (map[string]string, map[string]any) {
	params := newDerivedParams()
	params.addParameters(item.Parameters)
	params.addParameters(op.Parameters)
	params.addRequestBody(op.RequestBody)
	return params.locations, params.inputSchema()
}

func schemaType(s *openapi3.Schema) string {
	if s == nil || s.Type == nil {
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

type derivedParams struct {
	locations map[string]string
	props     map[string]any
	required  map[string]struct{}
}

func newDerivedParams() derivedParams {
	return derivedParams{
		locations: map[string]string{},
		props:     map[string]any{},
		required:  map[string]struct{}{},
	}
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

	p.locations[param.Name] = location
	p.props[param.Name] = schemaForParameter(param)
	if param.Required {
		p.required[param.Name] = struct{}{}
	}
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
	media := selectJSONMediaType(rb.Content)
	if media == nil || media.Schema == nil || media.Schema.Value == nil {
		return
	}

	body := media.Schema.Value
	if body.Type != nil && body.Type.Is(schemaTypeObject) && len(body.Properties) > 0 {
		p.addRequestBodyFields(body)
		return
	}

	p.locations[DerivedParamLocationBody] = DerivedParamLocationBody
	p.props[DerivedParamLocationBody] = schemaForOpenAPISchema(body, schemaTypeObject)
	if rb.Required {
		p.required[DerivedParamLocationBody] = struct{}{}
	}
}

func (p *derivedParams) addRequestBodyFields(body *openapi3.Schema) {
	bodyRequired := make(map[string]struct{}, len(body.Required))
	for _, name := range body.Required {
		bodyRequired[name] = struct{}{}
	}

	for _, name := range sortedSchemaPropertyNames(body.Properties) {
		if _, clash := p.locations[name]; clash {
			continue
		}

		p.locations[name] = DerivedParamLocationBodyPrefix + name
		p.props[name] = schemaForSchemaRef(body.Properties[name], schemaTypeString)
		if _, required := bodyRequired[name]; required {
			p.required[name] = struct{}{}
		}
	}
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
	schema := map[string]any{schemaKeyType: fallbackType}
	if src == nil {
		return schema
	}
	if t := schemaType(src); t != "" {
		schema[schemaKeyType] = t
	}
	if src.Description != "" {
		schema[schemaKeyDescription] = src.Description
	}
	return schema
}

func (p *derivedParams) inputSchema() map[string]any {
	schema := map[string]any{
		schemaKeyType:       schemaTypeObject,
		schemaKeyProperties: p.props,
	}
	if len(p.required) > 0 {
		schema[schemaKeyRequired] = sortedRequiredNames(p.required)
	}
	return schema
}

func sortedRequiredNames(required map[string]struct{}) []string {
	names := make([]string, 0, len(required))
	for name := range required {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// AdapterAPIIDSuffix is the deterministic suffix appended to the source
// REST APIID to form the synthetic adapter APIID, e.g.
// "abc123" -> "abc123__mcp-server".
const AdapterAPIIDSuffix = "__mcp-server"

// AdapterAPIID returns the deterministic APIID for the synthetic adapter
// paired with the given REST API.
func AdapterAPIID(restAPIID string) string {
	return restAPIID + AdapterAPIIDSuffix
}

// IsAdapterAPIID reports whether an APIID is the deterministic adapter
// ID derived from some REST APIID via AdapterAPIID.
func IsAdapterAPIID(id string) bool {
	return strings.HasSuffix(id, AdapterAPIIDSuffix) && len(id) > len(AdapterAPIIDSuffix)
}

// AdapterSourceAPIID returns the REST APIID corresponding to an adapter
// APIID, or "" if id is not an adapter ID.
func AdapterSourceAPIID(id string) string {
	if !IsAdapterAPIID(id) {
		return ""
	}
	return strings.TrimSuffix(id, AdapterAPIIDSuffix)
}

// AdapterLoopHost returns the host portion of the tyk:// URL used by an
// MCP proxy to address its paired adapter unambiguously, e.g.
// "abc123__mcp-server". The deterministic AdapterAPIIDSuffix ensures
// exact-APIID matching in the gateway's loopback resolver wins before
// any fuzzy name-based match could collide.
func AdapterLoopHost(restAPIID string) string {
	return AdapterAPIID(restAPIID)
}

// AdapterLoopURL returns the full tyk:// URL an MCP proxy should set as
// its upstream to dispatch into the paired adapter.
func AdapterLoopURL(restAPIID string) string {
	return "tyk://" + AdapterLoopHost(restAPIID)
}
