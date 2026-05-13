package oas

import (
	"fmt"
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

// DeriveWarning describes a non-fatal issue encountered while deriving
// tools — for example, a collision between two operationIds after
// sanitisation, or a parameter type that could not be represented.
type DeriveWarning struct {
	Operation string
	Reason    string
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
	var exposeSet map[string]struct{}
	if len(expose) > 0 {
		exposeSet = make(map[string]struct{}, len(expose))
		for _, name := range expose {
			exposeSet[SanitizeToolName(name)] = struct{}{}
		}
	}
	if srcOAS == nil {
		return nil, nil, fmt.Errorf("source OAS is nil")
	}

	var (
		tools    []DerivedTool
		warnings []DeriveWarning
		seen     = map[string]bool{}
	)

	if srcOAS.Paths == nil {
		return tools, warnings, nil
	}

	// Operations marked `internal.enabled: true` in the Tyk extension are
	// hidden from the public listenPath; the adapter loop bypasses that
	// check, so we must filter them out at derivation time.
	var internalOps map[string]bool
	if ext := srcOAS.GetTykExtension(); ext != nil && ext.Middleware != nil {
		for opID, op := range ext.Middleware.Operations {
			if op != nil && op.Internal != nil && op.Internal.Enabled {
				if internalOps == nil {
					internalOps = map[string]bool{}
				}
				internalOps[opID] = true
			}
		}
	}

	pathKeys := make([]string, 0, len(srcOAS.Paths.Map()))
	for k := range srcOAS.Paths.Map() {
		pathKeys = append(pathKeys, k)
	}
	sort.Strings(pathKeys)

	for _, p := range pathKeys {
		item := srcOAS.Paths.Map()[p]
		if item == nil {
			continue
		}

		for _, mo := range methodOperations(p, item) {
			rawName := mo.op.OperationID
			if rawName == "" {
				warnings = append(warnings, DeriveWarning{
					Operation: fmt.Sprintf("%s %s", mo.method, mo.path),
					Reason:    "missing operationId",
				})
				continue
			}

			if internalOps[rawName] {
				warnings = append(warnings, DeriveWarning{
					Operation: rawName,
					Reason:    "operation marked internal — skipped",
				})
				continue
			}

			name := SanitizeToolName(rawName)
			if name == "" {
				warnings = append(warnings, DeriveWarning{
					Operation: rawName,
					Reason:    "operationId sanitises to empty string",
				})
				continue
			}

			if seen[name] {
				warnings = append(warnings, DeriveWarning{
					Operation: rawName,
					Reason:    "tool name collision after sanitisation",
				})
				continue
			}

			if exposeSet != nil {
				if _, ok := exposeSet[name]; !ok {
					continue
				}
			}

			seen[name] = true

			locs, schema := deriveParams(item, mo.op)

			tools = append(tools, DerivedTool{
				Name:           name,
				Description:    operationDescription(mo.op),
				Method:         mo.method,
				PathTemplate:   mo.path,
				ParamLocations: locs,
				InputSchema:    schema,
			})
		}
	}

	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

	return tools, warnings, nil
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
	add("GET", item.Get)
	add("PUT", item.Put)
	add("POST", item.Post)
	add("DELETE", item.Delete)
	add("OPTIONS", item.Options)
	add("HEAD", item.Head)
	add("PATCH", item.Patch)
	add("TRACE", item.Trace)
	return ops
}

func operationDescription(op *openapi3.Operation) string {
	if op.Summary != "" {
		return op.Summary
	}
	return op.Description
}

var toolNameInvalid = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

// SanitizeToolName lowercases and strips characters MCP clients dislike.
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
	locs := map[string]string{}
	props := map[string]any{}
	required := []string{}

	addParam := func(param *openapi3.Parameter) {
		if param == nil || param.Name == "" {
			return
		}
		var loc string
		switch param.In {
		case openapi3.ParameterInPath:
			loc = "path"
		case openapi3.ParameterInQuery:
			loc = "query"
		case openapi3.ParameterInHeader:
			loc = "header"
		default:
			return
		}
		locs[param.Name] = loc

		schema := map[string]any{"type": "string"}
		if param.Schema != nil && param.Schema.Value != nil {
			if t := schemaType(param.Schema.Value); t != "" {
				schema["type"] = t
			}
			if d := param.Description; d != "" {
				schema["description"] = d
			}
		}
		props[param.Name] = schema
		if param.Required {
			required = append(required, param.Name)
		}
	}

	for _, p := range item.Parameters {
		if p != nil {
			addParam(p.Value)
		}
	}
	for _, p := range op.Parameters {
		if p != nil {
			addParam(p.Value)
		}
	}

	if op.RequestBody != nil && op.RequestBody.Value != nil {
		rb := op.RequestBody.Value
		// Pick first JSON-ish content type.
		var media *openapi3.MediaType
		for ct, m := range rb.Content {
			if strings.Contains(ct, "json") {
				media = m
				break
			}
		}
		if media != nil && media.Schema != nil && media.Schema.Value != nil {
			body := media.Schema.Value
			if body.Type != nil && body.Type.Is("object") && len(body.Properties) > 0 {
				bodyRequired := map[string]bool{}
				for _, name := range body.Required {
					bodyRequired[name] = true
				}
				for name, ref := range body.Properties {
					if _, clash := locs[name]; clash {
						continue
					}
					locs[name] = "body." + name
					field := map[string]any{"type": "string"}
					if ref != nil && ref.Value != nil {
						if t := schemaType(ref.Value); t != "" {
							field["type"] = t
						}
						if ref.Value.Description != "" {
							field["description"] = ref.Value.Description
						}
					}
					props[name] = field
					if bodyRequired[name] {
						required = append(required, name)
					}
				}
			} else {
				locs["body"] = "body"
				bodyProp := map[string]any{"type": "object"}
				if t := schemaType(body); t != "" {
					bodyProp["type"] = t
				}
				if body.Description != "" {
					bodyProp["description"] = body.Description
				}
				props["body"] = bodyProp
				if rb.Required {
					required = append(required, "body")
				}
			}
		}
	}

	sort.Strings(required)

	schema := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return locs, schema
}

func schemaType(s *openapi3.Schema) string {
	if s == nil || s.Type == nil {
		return ""
	}
	switch {
	case s.Type.Is("string"):
		return "string"
	case s.Type.Is("integer"):
		return "integer"
	case s.Type.Is("number"):
		return "number"
	case s.Type.Is("boolean"):
		return "boolean"
	case s.Type.Is("array"):
		return "array"
	case s.Type.Is("object"):
		return "object"
	}
	return ""
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
