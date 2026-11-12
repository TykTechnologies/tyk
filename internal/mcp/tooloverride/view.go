// Package tooloverride applies x-tyk-mcp-server tool overrides to the
// responses of a remote MCP proxy's upstream.
package tooloverride

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

// MissingSourceWarningInterval is how often ShouldWarnMissing lets a warning
// about the same missing source tool through.
const MissingSourceWarningInterval = 10 * time.Minute

// View is the compiled set of tool overrides for one remote MCP proxy, keyed
// by upstream tool name. The overrides are immutable; only the
// missing-source warning state changes.
type View struct {
	bySource map[string]*Override
	// quotedSources are the source names as JSON strings, used to skip
	// decoding tools that cannot have an override.
	quotedSources [][]byte

	warnMu      sync.Mutex
	lastWarning map[string]time.Time
}

// Override holds what a View changes on one upstream tool.
type Override struct {
	source      string
	annotations []annotationField
}

type annotationField struct {
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

	view := &View{bySource: make(map[string]*Override, len(ext.Primitives))}
	for _, primitive := range ext.Primitives {
		override := &Override{source: primitive.Source.ToolName}
		annotations, err := compileAnnotations(primitive.Annotations)
		if err != nil {
			return nil, fmt.Errorf("tool %q: %w", override.source, err)
		}
		override.annotations = annotations
		view.bySource[override.source] = override
		quoted, err := json.Marshal(override.source)
		if err != nil {
			return nil, fmt.Errorf("tool %q: %w", override.source, err)
		}
		view.quotedSources = append(view.quotedSources, quoted)
	}
	return view, nil
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
	v.warnMu.Lock()
	defer v.warnMu.Unlock()
	if last, ok := v.lastWarning[source]; ok && now.Sub(last) < MissingSourceWarningInterval {
		return false
	}
	if v.lastWarning == nil {
		v.lastWarning = map[string]time.Time{}
	}
	v.lastWarning[source] = now
	return true
}

func compileAnnotations(a *oas.DerivedToolAnnotations) ([]annotationField, error) {
	if a == nil {
		return nil, nil
	}
	var fields []annotationField
	if a.Title != "" {
		title, err := json.Marshal(a.Title)
		if err != nil {
			return nil, fmt.Errorf("annotations.title: %w", err)
		}
		fields = append(fields, annotationField{key: "title", value: title})
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
			fields = append(fields, annotationField{key: hint.key, value: json.RawMessage(strconv.FormatBool(*hint.value))})
		}
	}
	return fields, nil
}

// RewriteToolsList applies the view to a JSON-RPC tools/list response body.
//
// Each tool is merged field by field: a configured annotation replaces the
// upstream value (an explicit false included), and every other annotation
// and tool field is kept, including unknown ones. Tools without an override
// and responses that need no change are returned untouched, with changed
// false. Error responses and server messages pass through.
//
// complete reports that the request asked for the first page; when the
// response also has no nextCursor the list is the whole catalogue, and
// sources of overrides that it does not contain are returned as missing.
func (v *View) RewriteToolsList(body []byte, complete bool) (out []byte, changed bool, missing []string, err error) {
	list, err := decodeToolsList(body)
	if err != nil {
		return nil, false, nil, err
	}
	if list == nil {
		return body, false, nil, nil
	}

	var seen sourceSet
	if complete && !list.hasNextCursor() {
		seen = make(sourceSet, len(v.bySource))
	}
	changed, err = v.applyOverrides(list.tools, seen)
	if err != nil {
		return nil, false, nil, err
	}
	missing = v.missingSources(seen)

	if !changed {
		return body, false, missing, nil
	}
	out, err = mcp.ReencodeEnvelope(&list.envelope, list.result, "tools", list.tools)
	if err != nil {
		return nil, false, nil, err
	}
	return out, true, missing, nil
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

// applyOverrides rewrites, in place, every tool that has an override and
// reports whether any tool changed. Sources of the overridden tools are
// added to seen.
func (v *View) applyOverrides(tools []json.RawMessage, seen sourceSet) (bool, error) {
	changed := false
	for i, tool := range tools {
		name, ok := v.overriddenToolName(tool)
		if !ok {
			continue
		}
		seen.add(name)
		rewritten, toolChanged, err := v.bySource[name].apply(tool)
		if err != nil {
			return false, fmt.Errorf("tool %q: %w", name, err)
		}
		if toolChanged {
			tools[i] = rewritten
			changed = true
		}
	}
	return changed, nil
}

// overriddenToolName returns the name of a raw tool when the view has an
// override for it. Tools that cannot be decoded are left alone.
func (v *View) overriddenToolName(tool json.RawMessage) (string, bool) {
	if !v.mayHaveOverride(tool) {
		return "", false
	}
	var named struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(tool, &named) != nil {
		return "", false
	}
	if _, ok := v.bySource[named.Name]; !ok {
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

// mayHaveOverride reports whether a raw tool mentions any source name.
// Source names are restricted to characters JSON never escapes, so a tool
// whose bytes lack every quoted source name cannot be one of them.
func (v *View) mayHaveOverride(tool json.RawMessage) bool {
	for _, quoted := range v.quotedSources {
		if bytes.Contains(tool, quoted) {
			return true
		}
	}
	return false
}

func (o *Override) apply(tool json.RawMessage) (json.RawMessage, bool, error) {
	if len(o.annotations) == 0 {
		return tool, false, nil
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(tool, &fields); err != nil {
		return nil, false, err
	}

	var annotations map[string]json.RawMessage
	if raw := fields["annotations"]; len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		if err := json.Unmarshal(raw, &annotations); err != nil {
			return nil, false, fmt.Errorf("invalid annotations: %w", err)
		}
	}
	if annotations == nil {
		annotations = make(map[string]json.RawMessage, len(o.annotations))
	}

	changed := false
	for _, field := range o.annotations {
		if current, ok := annotations[field.key]; ok && jsonEqual(current, field.value) {
			continue
		}
		annotations[field.key] = field.value
		changed = true
	}
	if !changed {
		return tool, false, nil
	}

	raw, err := json.Marshal(annotations)
	if err != nil {
		return nil, false, err
	}
	fields["annotations"] = raw
	out, err := json.Marshal(fields)
	return out, err == nil, err
}

func jsonEqual(a, b json.RawMessage) bool {
	var compactA, compactB bytes.Buffer
	if json.Compact(&compactA, a) != nil || json.Compact(&compactB, b) != nil {
		return false
	}
	return bytes.Equal(compactA.Bytes(), compactB.Bytes())
}
