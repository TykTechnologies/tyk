// Package tooloverride applies x-tyk-mcp-server tool overrides to the
// responses of a remote MCP proxy's upstream.
package tooloverride

import (
	"encoding/json"
	"strconv"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// View is the compiled, immutable set of tool overrides for one remote MCP
// proxy, keyed by upstream tool name.
type View struct {
	bySource map[string]*Override
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
