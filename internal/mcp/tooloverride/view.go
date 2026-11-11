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
		override.annotations = compileAnnotations(primitive.Annotations)
		view.bySource[override.source] = override
		quoted, _ := json.Marshal(override.source) //nolint:errchkjson // a string always marshals
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

func compileAnnotations(a *oas.DerivedToolAnnotations) []annotationField {
	if a == nil {
		return nil
	}
	var fields []annotationField
	if a.Title != "" {
		title, _ := json.Marshal(a.Title) //nolint:errchkjson // a string always marshals
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
	return fields
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
	var envelope mcp.JSONRPCResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false, nil, err
	}
	if envelope.Result == nil {
		return body, false, nil, nil
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return nil, false, nil, fmt.Errorf("invalid tools/list result: %w", err)
	}
	rawTools, ok := result["tools"]
	if !ok {
		return body, false, nil, nil
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return nil, false, nil, fmt.Errorf("invalid tools/list tools: %w", err)
	}

	_, hasNextCursor := result["nextCursor"]
	var seen map[string]struct{}
	if complete && !hasNextCursor {
		seen = make(map[string]struct{}, len(v.bySource))
	}

	for i, tool := range tools {
		if !v.mayHaveOverride(tool) {
			continue
		}
		var named struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(tool, &named) != nil {
			continue
		}
		override, ok := v.bySource[named.Name]
		if !ok {
			continue
		}
		if seen != nil {
			seen[named.Name] = struct{}{}
		}
		rewritten, toolChanged, err := override.apply(tool)
		if err != nil {
			return nil, false, nil, fmt.Errorf("tool %q: %w", named.Name, err)
		}
		if toolChanged {
			tools[i] = rewritten
			changed = true
		}
	}

	if seen != nil {
		for source := range v.bySource {
			if _, ok := seen[source]; !ok {
				missing = append(missing, source)
			}
		}
		sort.Strings(missing)
	}

	if !changed {
		return body, false, missing, nil
	}
	out, err = mcp.ReencodeEnvelope(&envelope, result, "tools", tools)
	if err != nil {
		return nil, false, nil, err
	}
	return out, true, missing, nil
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
