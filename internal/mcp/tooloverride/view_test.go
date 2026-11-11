package tooloverride

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func boolPtr(v bool) *bool { return &v }

func TestCompile(t *testing.T) {
	t.Parallel()

	t.Run("no primitives compiles to no view", func(t *testing.T) {
		view, err := Compile(nil)
		require.NoError(t, err)
		assert.Nil(t, view)

		view, err = Compile(&oas.TykMCPServer{})
		require.NoError(t, err)
		assert.Nil(t, view)
	})

	t.Run("invalid configuration is rejected", func(t *testing.T) {
		_, err := Compile(&oas.TykMCPServer{Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{ToolName: "a"}, Name: "same"},
			{Source: oas.TykMCPServerSource{ToolName: "b"}, Name: "same"},
		}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"same" is a duplicate tool name`)
	})

	t.Run("view is detached from the configuration it was compiled from", func(t *testing.T) {
		ext := &oas.TykMCPServer{Primitives: []oas.TykMCPServerPrimitive{{
			Source:      oas.TykMCPServerSource{ToolName: "delete_repo"},
			Annotations: &oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)},
		}}}
		view, err := Compile(ext)
		require.NoError(t, err)

		*ext.Primitives[0].Annotations.DestructiveHint = false
		ext.Primitives[0].Source.ToolName = "other"

		override, ok := view.Override("delete_repo")
		require.True(t, ok)
		assert.Equal(t, []annotationField{{key: "destructiveHint", value: []byte("true")}}, override.annotations)
		_, ok = view.Override("other")
		assert.False(t, ok)
	})
}

func compileView(t *testing.T, primitives ...oas.TykMCPServerPrimitive) *View {
	t.Helper()
	view, err := Compile(&oas.TykMCPServer{Primitives: primitives})
	require.NoError(t, err)
	require.NotNil(t, view)
	return view
}

func annotate(source string, a oas.DerivedToolAnnotations) oas.TykMCPServerPrimitive {
	return oas.TykMCPServerPrimitive{Source: oas.TykMCPServerSource{ToolName: source}, Annotations: &a}
}

func toolsByName(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var envelope struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	out := map[string]json.RawMessage{}
	for _, tool := range envelope.Result.Tools {
		var named struct {
			Name string `json:"name"`
		}
		require.NoError(t, json.Unmarshal(tool, &named))
		out[named.Name] = tool
	}
	return out
}

func TestView_RewriteToolsList(t *testing.T) {
	t.Parallel()

	const (
		deleteRepo  = `{"name":"delete_repo","description":"Delete a repository","inputSchema":{"type":"object","properties":{"repo":{"type":"string"}}}}`
		createIssue = `{"name":"create_issue","title":"Create issue","description":"Open <b>an</b> issue","inputSchema":{"type":"object"},"annotations":{"idempotentHint":false,"destructiveHint":false,"x-vendor":"kept"},"_meta":{"io.example/x":1},"vendorField":[1,2]}`
		mergeBranch = `{"name":"merge_branch","inputSchema":{"type":"object"},"annotations":{"idempotentHint":true,"openWorldHint":true,"readOnlyHint":false}}`
		listRepos   = `{"name":"list_repos","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true},"outputSchema":{"type":"object"}}`
	)
	body := []byte(`{"jsonrpc":"2.0","id":7,"result":{"tools":[` + deleteRepo + `,` + createIssue + `,` + mergeBranch + `,` + listRepos + `],"nextCursor":"page-2","_meta":{"upstream":"kept"}},"extra":true}`)

	view := compileView(t,
		annotate("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		annotate("create_issue", oas.DerivedToolAnnotations{Title: "Create GitHub issue"}),
		annotate("merge_branch", oas.DerivedToolAnnotations{IdempotentHint: boolPtr(false), OpenWorldHint: boolPtr(false)}),
	)

	out, changed, missing, err := view.RewriteToolsList(body, false)
	require.NoError(t, err)
	require.True(t, changed)
	assert.Empty(t, missing, "a paged list cannot prove a source is missing")

	tools := toolsByName(t, out)

	t.Run("destructiveHint added to a tool without annotations", func(t *testing.T) {
		assert.JSONEq(t, `{"name":"delete_repo","description":"Delete a repository","inputSchema":{"type":"object","properties":{"repo":{"type":"string"}}},"annotations":{"destructiveHint":true}}`, string(tools["delete_repo"]))
	})

	t.Run("annotations.title set, upstream hints, unknown annotation keys and other fields kept", func(t *testing.T) {
		assert.JSONEq(t, `{"name":"create_issue","title":"Create issue","description":"Open <b>an</b> issue","inputSchema":{"type":"object"},"annotations":{"title":"Create GitHub issue","idempotentHint":false,"destructiveHint":false,"x-vendor":"kept"},"_meta":{"io.example/x":1},"vendorField":[1,2]}`, string(tools["create_issue"]))
	})

	t.Run("true hints overridden with explicit false, unset hints kept", func(t *testing.T) {
		assert.JSONEq(t, `{"name":"merge_branch","inputSchema":{"type":"object"},"annotations":{"idempotentHint":false,"openWorldHint":false,"readOnlyHint":false}}`, string(tools["merge_branch"]))
	})

	t.Run("tool without override unchanged", func(t *testing.T) {
		assert.JSONEq(t, listRepos, string(tools["list_repos"]))
	})

	t.Run("envelope, cursor and result fields kept", func(t *testing.T) {
		var envelope map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out, &envelope))
		assert.JSONEq(t, `true`, string(envelope["extra"]))
		assert.JSONEq(t, `7`, string(envelope["id"]))
		var result map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(envelope["result"], &result))
		assert.JSONEq(t, `"page-2"`, string(result["nextCursor"]))
		assert.JSONEq(t, `{"upstream":"kept"}`, string(result["_meta"]))
		assert.NotContains(t, result, "cacheScope")
	})
}

func TestView_RewriteToolsList_AnnotationsOfARenamedTool(t *testing.T) {
	t.Parallel()

	primitive := annotate("remove_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true), ReadOnlyHint: boolPtr(false)})
	primitive.Name = "delete_repository"
	view := compileView(t, primitive)

	out, changed, _, err := view.RewriteToolsList([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"remove_repo","inputSchema":{"type":"object"}}]}}`), true)
	require.NoError(t, err)
	require.True(t, changed)

	var envelope struct {
		Result struct {
			Tools []struct {
				Annotations map[string]any `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out, &envelope))
	require.Len(t, envelope.Result.Tools, 1)
	assert.Equal(t, map[string]any{"destructiveHint": true, "readOnlyHint": false}, envelope.Result.Tools[0].Annotations)
}

func TestView_RewriteToolsList_MissingSources(t *testing.T) {
	t.Parallel()

	view := compileView(t,
		annotate("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		annotate("archived_tool", oas.DerivedToolAnnotations{ReadOnlyHint: boolPtr(true)}),
	)
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_repo"}]}}`)

	_, _, missing, err := view.RewriteToolsList(body, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"archived_tool"}, missing, "a complete single-page list proves the source is missing")

	_, _, missing, err = view.RewriteToolsList(body, false)
	require.NoError(t, err)
	assert.Empty(t, missing, "a later page cannot prove the source is missing")

	_, _, missing, err = view.RewriteToolsList([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_repo"}],"nextCursor":"x"}}`), true)
	require.NoError(t, err)
	assert.Empty(t, missing, "a first page with more pages cannot prove the source is missing")
}

func TestView_RewriteToolsList_PassesThroughNonListBodies(t *testing.T) {
	t.Parallel()

	view := compileView(t, annotate("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}))
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`,
		`{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"create_issue"}]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_repo","annotations":{"destructiveHint":true}}]}}`,
	} {
		out, changed, _, err := view.RewriteToolsList([]byte(body), false)
		require.NoError(t, err, body)
		assert.False(t, changed, body)
		assert.Equal(t, body, string(out), body)
	}

	_, _, _, err := view.RewriteToolsList([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":"oops"}}`), false)
	assert.Error(t, err)
}

func BenchmarkView_RewriteToolsList(b *testing.B) {
	ext := &oas.TykMCPServer{}
	parts := make([]string, 0, 50)
	for i := range 50 {
		name := fmt.Sprintf("tool_%d", i)
		parts = append(parts, fmt.Sprintf(`{"name":%q,"description":"d","inputSchema":{"type":"object","properties":{"a":{"type":"string"}}},"annotations":{"readOnlyHint":true}}`, name))
		if i%5 == 0 {
			ext.Primitives = append(ext.Primitives, annotate(name, oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}))
		}
	}
	view, err := Compile(ext)
	require.NoError(b, err)
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` + strings.Join(parts, ",") + `]}}`)

	b.ReportAllocs()
	for b.Loop() {
		if _, _, _, err := view.RewriteToolsList(body, true); err != nil {
			b.Fatal(err)
		}
	}
}

func TestView_ShouldWarnMissing(t *testing.T) {
	t.Parallel()

	view := compileView(t, annotate("archived_tool", oas.DerivedToolAnnotations{ReadOnlyHint: boolPtr(true)}))
	now := time.Unix(1_000, 0)

	assert.True(t, view.ShouldWarnMissing("archived_tool", now))
	assert.False(t, view.ShouldWarnMissing("archived_tool", now.Add(time.Minute)))
	assert.True(t, view.ShouldWarnMissing("other", now))
	assert.True(t, view.ShouldWarnMissing("archived_tool", now.Add(MissingSourceWarningInterval)))
}
