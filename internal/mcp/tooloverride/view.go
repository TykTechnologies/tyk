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
		override, err := compileOverride(primitive)
		if err != nil {
			return nil, fmt.Errorf("tool %q: %w", primitive.Source.ToolName, err)
		}
		names := []string{override.source}
		if override.name != override.source {
			names = []string{override.name, override.source}
		}
		for _, name := range names {
			quoted, err := jsonString(name)
			if err != nil {
				return nil, fmt.Errorf("tool %q: %w", override.source, err)
			}
			view.quotedNames = append(view.quotedNames, quoted)
		}
		view.bySource[override.source] = override
		view.exposed[override.name] = override.source
	}
	return view, nil
}

// compileOverride compiles the name, description and annotation overrides of
// one primitive.
func compileOverride(primitive oas.TykMCPServerPrimitive) (*Override, error) {
	override := &Override{source: primitive.Source.ToolName, name: primitive.Source.ToolName}
	if primitive.Name != "" && primitive.Name != override.source {
		override.name = primitive.Name
		field, err := stringField("name", primitive.Name)
		if err != nil {
			return nil, err
		}
		override.fields = append(override.fields, field)
	}
	if primitive.Description != "" {
		field, err := stringField("description", primitive.Description)
		if err != nil {
			return nil, err
		}
		override.fields = append(override.fields, field)
	}
	annotations, err := compileAnnotations(primitive.Annotations)
	if err != nil {
		return nil, err
	}
	override.annotations = annotations
	return override, nil
}

func jsonString(s string) (json.RawMessage, error) {
	return json.Marshal(s)
}

func stringField(key, value string) (jsonField, error) {
	quoted, err := jsonString(value)
	if err != nil {
		return jsonField{}, fmt.Errorf("%s: %w", key, err)
	}
	return jsonField{key: key, value: quoted}, nil
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

func compileAnnotations(a *oas.DerivedToolAnnotations) ([]jsonField, error) {
	if a == nil {
		return nil, nil
	}
	var fields []jsonField
	if a.Title != "" {
		title, err := stringField("title", a.Title)
		if err != nil {
			return nil, fmt.Errorf("annotations.%w", err)
		}
		fields = append(fields, title)
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
	return fields, nil
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
	list, err := decodeToolsList(body)
	if err != nil {
		return nil, false, Drift{}, err
	}
	if list == nil {
		return body, false, Drift{}, nil
	}

	var seen sourceSet
	if complete && !list.hasNextCursor() {
		seen = make(sourceSet, len(v.bySource))
	}
	kept, changed, err := v.applyOverrides(list.tools, seen, &drift)
	if err != nil {
		return nil, false, Drift{}, err
	}
	drift.Missing = v.missingSources(seen)

	if !changed {
		return body, false, drift, nil
	}
	out, err = mcp.ReencodeEnvelope(&list.envelope, list.result, "tools", kept)
	if err != nil {
		return nil, false, Drift{}, err
	}
	return out, true, drift, nil
}

// toolsList is a decoded tools/list response whose tools can be rewritten
// in place and re-encoded with every other member preserved.
type toolsList struct {
	envelope mcp.JSONRPCResponse
	result   map[string]json.RawMessage
	tools    []json.RawMessage
}

// decodeToolsList decodes a tools/list response body. It returns a nil list
// for responses that carry no tools to rewrite, such as errors and server
// messages.
func decodeToolsList(body []byte) (*toolsList, error) {
	list := &toolsList{}
	if err := json.Unmarshal(body, &list.envelope); err != nil {
		return nil, err
	}
	if list.envelope.Result == nil {
		return nil, nil
	}
	if err := json.Unmarshal(list.envelope.Result, &list.result); err != nil {
		return nil, fmt.Errorf("invalid tools/list result: %w", err)
	}
	rawTools, ok := list.result["tools"]
	if !ok {
		return nil, nil
	}
	if err := json.Unmarshal(rawTools, &list.tools); err != nil {
		return nil, fmt.Errorf("invalid tools/list tools: %w", err)
	}
	return list, nil
}

func (l *toolsList) hasNextCursor() bool {
	_, ok := l.result["nextCursor"]
	return ok
}

// sourceSet records the override sources found in a tools/list response. A
// nil set records nothing; it is used when the response is not the complete
// catalogue.
type sourceSet map[string]struct{}

func (s sourceSet) add(source string) {
	if s != nil {
		s[source] = struct{}{}
	}
}

// applyOverrides returns tools with every overridden tool rewritten and
// every upstream tool hidden behind an override dropped, and reports whether
// anything changed. Sources of the overridden tools are added to seen and
// hidden tools to drift.Hidden. Hidden tools are dropped in place, reusing
// the backing array of tools; kept never overtakes the loop index.
func (v *View) applyOverrides(tools []json.RawMessage, seen sourceSet, drift *Drift) (kept []json.RawMessage, changed bool, err error) {
	kept = tools[:0]
	for _, tool := range tools {
		name, ok := v.affectedToolName(tool)
		if !ok {
			kept = append(kept, tool)
			continue
		}
		if override, ok := v.bySource[name]; ok {
			seen.add(name)
			rewritten, toolChanged, err := override.apply(tool)
			if err != nil {
				return nil, false, fmt.Errorf("tool %q: %w", name, err)
			}
			if toolChanged {
				tool = rewritten
				changed = true
			}
			kept = append(kept, tool)
			continue
		}
		if _, bound := v.exposed[name]; bound {
			drift.Hidden = append(drift.Hidden, name)
			changed = true
			continue
		}
		kept = append(kept, tool)
	}
	return kept, changed, nil
}

// affectedToolName returns the name of a raw tool that may be affected by
// the view. Tools that cannot be decoded are left alone.
func (v *View) affectedToolName(tool json.RawMessage) (string, bool) {
	if !v.mayAffect(tool) {
		return "", false
	}
	var named struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(tool, &named) != nil {
		return "", false
	}
	return named.Name, true
}

// missingSources returns, sorted, the override sources that are not in seen.
// It returns nil when seen is nil, because only a complete catalogue proves
// that a source is missing.
func (v *View) missingSources(seen sourceSet) []string {
	if seen == nil {
		return nil
	}
	var missing []string
	for source := range v.bySource {
		if _, ok := seen[source]; !ok {
			missing = append(missing, source)
		}
	}
	sort.Strings(missing)
	return missing
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
	annotationsChanged, err := o.applyAnnotations(fields)
	if err != nil {
		return nil, false, err
	}
	if !changed && !annotationsChanged {
		return tool, false, nil
	}

	out, err := json.Marshal(fields)
	return out, err == nil, err
}

// applyAnnotations merges the annotation overrides into the annotations
// member of a decoded tool and reports whether it changed.
func (o *Override) applyAnnotations(fields map[string]json.RawMessage) (bool, error) {
	if len(o.annotations) == 0 {
		return false, nil
	}
	var annotations map[string]json.RawMessage
	if raw := fields["annotations"]; len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if err := json.Unmarshal(raw, &annotations); err != nil {
			return false, fmt.Errorf("invalid annotations: %w", err)
		}
	}
	if annotations == nil {
		annotations = make(map[string]json.RawMessage, len(o.annotations))
	}
	if !mergeFields(annotations, o.annotations) {
		return false, nil
	}
	raw, err := json.Marshal(annotations)
	if err != nil {
		return false, err
	}
	fields["annotations"] = raw
	return true, nil
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

	quotedUpstream, err := jsonString(upstream)
	if err != nil {
		return nil, err
	}
	params["name"] = quotedUpstream
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	envelope["params"] = rawParams
	return json.Marshal(envelope)
}
