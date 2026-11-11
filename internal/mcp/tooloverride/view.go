// Package tooloverride applies x-tyk-mcp-server tool overrides to the
// responses of a remote MCP proxy's upstream.
package tooloverride

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

// MissingSourceWarningInterval is how often ShouldWarnMissing and
// ShouldWarnHidden let a warning about the same tool through.
const MissingSourceWarningInterval = 10 * time.Minute

// View is the compiled set of tool overrides for one remote MCP proxy, keyed
// by upstream tool name. The overrides are immutable; only the warning state
// changes.
type View struct {
	bySource map[string]*Override
	// exposed maps every name the view exposes to its upstream source tool.
	exposed map[string]string
	// quotedNames are the source and exposed names as JSON strings, used to
	// skip decoding tools that the view cannot affect.
	quotedNames [][]byte

	warnMu      sync.Mutex
	lastWarning map[warning]time.Time
}

type warning struct {
	hidden bool
	tool   string
}

// Drift reports where an upstream tools/list response no longer matches the
// overrides. Missing lists override sources that the complete list lacks.
// Hidden lists upstream tools that were dropped because their own name is
// bound to an override of another tool.
type Drift struct {
	Missing []string
	Hidden  []string
}

// Override holds what a View changes on one upstream tool.
type Override struct {
	source string
	// name is the exposed name; it equals source when the tool is not renamed.
	name string
	// fields are the top-level tool fields that replace the upstream values.
	fields      []jsonField
	annotations []jsonField
}

type jsonField struct {
	key   string
	value json.RawMessage
}

// Compile validates ext and compiles it into a View. It returns a nil View
// when there is nothing to override.
func Compile(ext *oas.TykMCPServer) (*View, error) {
	if ext == nil || len(ext.Primitives) == 0 {
		return nil, nil
	}
	if err := oas.ValidateRemoteMCPToolOverrides(ext); err != nil {
		return nil, err
	}

	view := &View{
		bySource: make(map[string]*Override, len(ext.Primitives)),
		exposed:  make(map[string]string, len(ext.Primitives)),
	}
	for _, primitive := range ext.Primitives {
		override := &Override{source: primitive.Source.ToolName, name: primitive.Source.ToolName}
		if primitive.Name != "" && primitive.Name != override.source {
			override.name = primitive.Name
			override.fields = append(override.fields, jsonField{key: "name", value: jsonString(primitive.Name)})
			view.quotedNames = append(view.quotedNames, jsonString(primitive.Name))
		}
		if primitive.Description != "" {
			override.fields = append(override.fields, jsonField{key: "description", value: jsonString(primitive.Description)})
		}
		override.annotations = compileAnnotations(primitive.Annotations)
		view.bySource[override.source] = override
		view.exposed[override.name] = override.source
		view.quotedNames = append(view.quotedNames, jsonString(override.source))
	}
	return view, nil
}

func jsonString(s string) json.RawMessage {
	quoted, _ := json.Marshal(s) //nolint:errchkjson // a string always marshals
	return quoted
}

// Override returns the override configured for an upstream tool.
func (v *View) Override(source string) (*Override, bool) {
	if v == nil {
		return nil, false
	}
	override, ok := v.bySource[source]
	return override, ok
}

// ShouldWarnMissing reports whether a warning that source is missing from the
// upstream tool list is due, so that per-request warnings are rate limited.
func (v *View) ShouldWarnMissing(source string, now time.Time) bool {
	return v.shouldWarn(warning{tool: source}, now)
}

// ShouldWarnHidden reports whether a warning that the upstream's own tool
// called name is hidden behind an override is due. It is rate limited like
// ShouldWarnMissing.
func (v *View) ShouldWarnHidden(name string, now time.Time) bool {
	return v.shouldWarn(warning{hidden: true, tool: name}, now)
}

func (v *View) shouldWarn(key warning, now time.Time) bool {
	v.warnMu.Lock()
	defer v.warnMu.Unlock()
	if last, ok := v.lastWarning[key]; ok && now.Sub(last) < MissingSourceWarningInterval {
		return false
	}
	if v.lastWarning == nil {
		v.lastWarning = map[warning]time.Time{}
	}
	v.lastWarning[key] = now
	return true
}

func compileAnnotations(a *oas.DerivedToolAnnotations) []jsonField {
	if a == nil {
		return nil
	}
	var fields []jsonField
	if a.Title != "" {
		fields = append(fields, jsonField{key: "title", value: jsonString(a.Title)})
	}
	for _, hint := range []struct {
		key   string
		value *bool
	}{
		{"readOnlyHint", a.ReadOnlyHint},
		{"destructiveHint", a.DestructiveHint},
		{"idempotentHint", a.IdempotentHint},
		{"openWorldHint", a.OpenWorldHint},
	} {
		if hint.value != nil {
			fields = append(fields, jsonField{key: hint.key, value: json.RawMessage(strconv.FormatBool(*hint.value))})
		}
	}
	return fields
}

// RewriteToolsList applies the view to a JSON-RPC tools/list response body.
//
// Each overridden tool is merged field by field: a configured name or
// description replaces the upstream value, a configured annotation replaces
// the upstream annotation (an explicit false included), and every other
// field is kept, including unknown ones. An upstream tool whose own name is
// bound to an override of another tool is dropped and reported as hidden, so
// the explicit override wins. Tools without an override and responses that
// need no change are returned untouched, with changed false. Error responses
// and server messages pass through.
//
// complete reports that the request asked for the first page; when the
// response also has no nextCursor the list is the whole catalogue, and
// sources of overrides that it does not contain are reported as missing.
func (v *View) RewriteToolsList(body []byte, complete bool) (out []byte, changed bool, drift Drift, err error) {
	var envelope mcp.JSONRPCResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false, Drift{}, err
	}
	if envelope.Result == nil {
		return body, false, Drift{}, nil
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return nil, false, Drift{}, fmt.Errorf("invalid tools/list result: %w", err)
	}
	rawTools, ok := result["tools"]
	if !ok {
		return body, false, Drift{}, nil
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return nil, false, Drift{}, fmt.Errorf("invalid tools/list tools: %w", err)
	}

	_, hasNextCursor := result["nextCursor"]
	var seen map[string]struct{}
	if complete && !hasNextCursor {
		seen = make(map[string]struct{}, len(v.bySource))
	}

	// Hidden tools are dropped in place; kept never overtakes the loop index.
	kept := tools[:0]
	for _, tool := range tools {
		if !v.mayAffect(tool) {
			kept = append(kept, tool)
			continue
		}
		var named struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(tool, &named) != nil {
			kept = append(kept, tool)
			continue
		}
		if override, ok := v.bySource[named.Name]; ok {
			if seen != nil {
				seen[named.Name] = struct{}{}
			}
			rewritten, toolChanged, err := override.apply(tool)
			if err != nil {
				return nil, false, Drift{}, fmt.Errorf("tool %q: %w", named.Name, err)
			}
			if toolChanged {
				tool = rewritten
				changed = true
			}
			kept = append(kept, tool)
			continue
		}
		if _, bound := v.exposed[named.Name]; bound {
			drift.Hidden = append(drift.Hidden, named.Name)
			changed = true
			continue
		}
		kept = append(kept, tool)
	}

	if seen != nil {
		for source := range v.bySource {
			if _, ok := seen[source]; !ok {
				drift.Missing = append(drift.Missing, source)
			}
		}
		sort.Strings(drift.Missing)
	}

	if !changed {
		return body, false, drift, nil
	}
	out, err = mcp.ReencodeEnvelope(&envelope, result, "tools", kept)
	if err != nil {
		return nil, false, Drift{}, err
	}
	return out, true, drift, nil
}

// mayAffect reports whether a raw tool mentions any source or exposed name.
// Tool names are restricted to characters JSON never escapes, so a tool
// whose bytes lack every quoted name cannot be one of them.
func (v *View) mayAffect(tool json.RawMessage) bool {
	for _, quoted := range v.quotedNames {
		if bytes.Contains(tool, quoted) {
			return true
		}
	}
	return false
}

func (o *Override) apply(tool json.RawMessage) (json.RawMessage, bool, error) {
	if len(o.fields) == 0 && len(o.annotations) == 0 {
		return tool, false, nil
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(tool, &fields); err != nil {
		return nil, false, err
	}

	changed := mergeFields(fields, o.fields)
	if len(o.annotations) > 0 {
		var annotations map[string]json.RawMessage
		if raw := fields["annotations"]; len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
			if err := json.Unmarshal(raw, &annotations); err != nil {
				return nil, false, fmt.Errorf("invalid annotations: %w", err)
			}
		}
		if annotations == nil {
			annotations = make(map[string]json.RawMessage, len(o.annotations))
		}
		if mergeFields(annotations, o.annotations) {
			raw, err := json.Marshal(annotations)
			if err != nil {
				return nil, false, err
			}
			fields["annotations"] = raw
			changed = true
		}
	}
	if !changed {
		return tool, false, nil
	}

	out, err := json.Marshal(fields)
	return out, err == nil, err
}

// mergeFields sets each override in target and reports whether any value
// changed.
func mergeFields(target map[string]json.RawMessage, overrides []jsonField) bool {
	changed := false
	for _, field := range overrides {
		if current, ok := target[field.key]; ok && jsonEqual(current, field.value) {
			continue
		}
		target[field.key] = field.value
		changed = true
	}
	return changed
}

func jsonEqual(a, b json.RawMessage) bool {
	var compactA, compactB bytes.Buffer
	if json.Compact(&compactA, a) != nil || json.Compact(&compactB, b) != nil {
		return false
	}
	return bytes.Equal(compactA.Bytes(), compactB.Bytes())
}

// ResolveCall returns the upstream tool that a tools/call for the exposed
// name must reach. known is false when name is an upstream tool renamed away
// by an override and not bound to another one; such a call must not reach
// the upstream. Names the view does not mention resolve to themselves.
//
// Resolution never consults the upstream catalogue. A call to a name whose
// source tool has disappeared upstream is still sent under the source name,
// so the upstream decides. An upstream tool that shares its own name with
// an override of another tool cannot be called: the name always reaches the
// override's source.
func (v *View) ResolveCall(name string) (upstream string, known bool) {
	if source, ok := v.exposed[name]; ok {
		return source, true
	}
	if _, renamedAway := v.bySource[name]; renamedAway {
		return "", false
	}
	return name, true
}

// TranslateToolsCall rewrites params.name of a JSON-RPC tools/call request
// from exposed to upstream. Every other member of the request and of its
// params, including id, arguments and _meta, is copied verbatim. It fails
// when the body does not name exposed, so a call is never sent to a tool
// other than the one that was authorised.
func TranslateToolsCall(body []byte, exposed, upstream string) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("invalid tools/call request: %w", err)
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(envelope["params"], &params); err != nil || params == nil {
		return nil, errors.New("invalid tools/call request: params is not an object")
	}
	var name string
	if err := json.Unmarshal(params["name"], &name); err != nil || name != exposed {
		return nil, fmt.Errorf("tools/call request does not name tool %q", exposed)
	}

	params["name"] = jsonString(upstream)
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	envelope["params"] = rawParams
	return json.Marshal(envelope)
}
