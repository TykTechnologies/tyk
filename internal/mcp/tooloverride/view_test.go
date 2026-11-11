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
		assert.Equal(t, []jsonField{{key: "destructiveHint", value: []byte("true")}}, override.annotations)
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

	out, changed, drift, err := view.RewriteToolsList(body, false)
	require.NoError(t, err)
	require.True(t, changed)
	assert.Empty(t, drift.Missing, "a paged list cannot prove a source is missing")

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

	_, _, drift, err := view.RewriteToolsList(body, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"archived_tool"}, drift.Missing, "a complete single-page list proves the source is missing")

	_, _, drift, err = view.RewriteToolsList(body, false)
	require.NoError(t, err)
	assert.Empty(t, drift.Missing, "a later page cannot prove the source is missing")

	_, _, drift, err = view.RewriteToolsList([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_repo"}],"nextCursor":"x"}}`), true)
	require.NoError(t, err)
	assert.Empty(t, drift.Missing, "a first page with more pages cannot prove the source is missing")
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

func rename(source, name, description string) oas.TykMCPServerPrimitive {
	return oas.TykMCPServerPrimitive{Source: oas.TykMCPServerSource{ToolName: source}, Name: name, Description: description}
}

func listedNames(t *testing.T, body []byte) []string {
	t.Helper()
	var envelope struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	names := make([]string, 0, len(envelope.Result.Tools))
	for _, tool := range envelope.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func toolsListBody(tools ...string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":3,"result":{"tools":[` + strings.Join(tools, ",") + `],"_meta":{"upstream":"kept"}}}`)
}

func TestView_RewriteToolsList_NamesAndDescriptions(t *testing.T) {
	t.Parallel()

	const (
		createIssue = `{"name":"create_issue","title":"Create issue","description":"Open an issue","inputSchema":{"type":"object","properties":{"repo":{"type":"string"},"title":{"type":"string"}},"required":["repo","title"]},"annotations":{"destructiveHint":false,"x-vendor":"kept"},"_meta":{"io.example/x":1},"vendorField":[1,2]}`
		listIssues  = `{"name":"list_issues","description":"List issues","inputSchema":{"type":"object","properties":{"repo":{"type":"string"}}}}`
		deleteRepo  = `{"name":"delete_repo","description":"Delete a repository","inputSchema":{"type":"object"}}`
	)

	t.Run("name and description replaced, every other field kept, original name gone", func(t *testing.T) {
		view := compileView(t, rename("create_issue", "open_issue", "Open a new issue in a repository. Requires the repository name and a title."))
		out, changed, drift, err := view.RewriteToolsList(toolsListBody(createIssue, listIssues), true)
		require.NoError(t, err)
		require.True(t, changed)
		assert.Empty(t, drift.Missing)
		assert.Empty(t, drift.Hidden)

		assert.Equal(t, []string{"open_issue", "list_issues"}, listedNames(t, out))
		assert.NotContains(t, string(out), `"create_issue"`)
		tools := toolsByName(t, out)
		assert.JSONEq(t, `{"name":"open_issue","title":"Create issue","description":"Open a new issue in a repository. Requires the repository name and a title.","inputSchema":{"type":"object","properties":{"repo":{"type":"string"},"title":{"type":"string"}},"required":["repo","title"]},"annotations":{"destructiveHint":false,"x-vendor":"kept"},"_meta":{"io.example/x":1},"vendorField":[1,2]}`, string(tools["open_issue"]))
		assert.JSONEq(t, listIssues, string(tools["list_issues"]))
	})

	t.Run("description only keeps the upstream name", func(t *testing.T) {
		view := compileView(t, rename("delete_repo", "", "Permanently delete a repository"))
		out, changed, _, err := view.RewriteToolsList(toolsListBody(deleteRepo), true)
		require.NoError(t, err)
		require.True(t, changed)
		assert.JSONEq(t, `{"name":"delete_repo","description":"Permanently delete a repository","inputSchema":{"type":"object"}}`, string(toolsByName(t, out)["delete_repo"]))
	})

	t.Run("name only keeps the upstream description and a missing description stays missing", func(t *testing.T) {
		view := compileView(t, rename("delete_repo", "remove_repository", ""), rename("merge_branch", "merge", ""))
		out, _, _, err := view.RewriteToolsList(toolsListBody(deleteRepo, `{"name":"merge_branch","inputSchema":{"type":"object"}}`), true)
		require.NoError(t, err)
		tools := toolsByName(t, out)
		assert.JSONEq(t, `{"name":"remove_repository","description":"Delete a repository","inputSchema":{"type":"object"}}`, string(tools["remove_repository"]))
		assert.JSONEq(t, `{"name":"merge","inputSchema":{"type":"object"}}`, string(tools["merge"]))
	})

	t.Run("renamed tool gets its annotation overrides", func(t *testing.T) {
		primitive := rename("create_issue", "open_issue", "")
		primitive.Annotations = &oas.DerivedToolAnnotations{IdempotentHint: boolPtr(true)}
		view := compileView(t, primitive)
		out, _, _, err := view.RewriteToolsList(toolsListBody(createIssue), true)
		require.NoError(t, err)
		tools := toolsByName(t, out)
		require.Contains(t, tools, "open_issue")
		var tool struct {
			Annotations map[string]any `json:"annotations"`
		}
		require.NoError(t, json.Unmarshal(tools["open_issue"], &tool))
		assert.Equal(t, map[string]any{"idempotentHint": true, "destructiveHint": false, "x-vendor": "kept"}, tool.Annotations)
	})

	t.Run("swap exposes each upstream tool under the other's name", func(t *testing.T) {
		view := compileView(t, rename("remove_repo", "delete_repo", ""), rename("update_repo", "remove_repo", ""))
		out, _, drift, err := view.RewriteToolsList(toolsListBody(
			`{"name":"remove_repo","description":"upstream remove_repo"}`,
			`{"name":"update_repo","description":"upstream update_repo"}`,
		), true)
		require.NoError(t, err)
		assert.Empty(t, drift.Hidden, "a swapped name is never an upstream drift collision")
		assert.Equal(t, []string{"delete_repo", "remove_repo"}, listedNames(t, out))
		tools := toolsByName(t, out)
		assert.JSONEq(t, `{"name":"delete_repo","description":"upstream remove_repo"}`, string(tools["delete_repo"]))
		assert.JSONEq(t, `{"name":"remove_repo","description":"upstream update_repo"}`, string(tools["remove_repo"]))
	})
}

func TestView_RewriteToolsList_UpstreamDrift(t *testing.T) {
	t.Parallel()

	const (
		createIssue   = `{"name":"create_issue","description":"Open an issue","inputSchema":{"type":"object"}}`
		upstreamOpen  = `{"name":"open_issue","description":"upstream's own open_issue","inputSchema":{"type":"object"}}`
		listIssues    = `{"name":"list_issues","inputSchema":{"type":"object"}}`
		openIssueDesc = "Open a new issue in a repository. Requires the repository name and a title."
	)
	view := compileView(t, rename("create_issue", "open_issue", openIssueDesc))

	t.Run("an upstream tool named like an override is hidden, wherever it appears", func(t *testing.T) {
		for _, order := range [][]string{{createIssue, upstreamOpen, listIssues}, {upstreamOpen, listIssues, createIssue}} {
			out, changed, drift, err := view.RewriteToolsList(toolsListBody(order...), true)
			require.NoError(t, err)
			require.True(t, changed)
			assert.Equal(t, []string{"open_issue"}, drift.Hidden)
			assert.Empty(t, drift.Missing)
			assert.ElementsMatch(t, []string{"open_issue", "list_issues"}, listedNames(t, out))
			assert.Contains(t, string(toolsByName(t, out)["open_issue"]), openIssueDesc)
			assert.NotContains(t, string(out), "upstream's own open_issue")
		}
	})

	t.Run("collisions are reported on any page", func(t *testing.T) {
		_, _, drift, err := view.RewriteToolsList([]byte(`{"jsonrpc":"2.0","id":3,"result":{"tools":[`+upstreamOpen+`],"nextCursor":"x"}}`), false)
		require.NoError(t, err)
		assert.Equal(t, []string{"open_issue"}, drift.Hidden)
	})

	t.Run("a renamed source missing upstream is reported and not exposed", func(t *testing.T) {
		out, changed, drift, err := view.RewriteToolsList(toolsListBody(listIssues), true)
		require.NoError(t, err)
		assert.False(t, changed)
		assert.Equal(t, []string{"create_issue"}, drift.Missing)
		assert.Equal(t, []string{"list_issues"}, listedNames(t, out))
	})

	t.Run("the name stays bound to the override while its source is missing", func(t *testing.T) {
		out, _, drift, err := view.RewriteToolsList(toolsListBody(upstreamOpen, listIssues), true)
		require.NoError(t, err)
		assert.Equal(t, []string{"create_issue"}, drift.Missing)
		assert.Equal(t, []string{"open_issue"}, drift.Hidden)
		assert.Equal(t, []string{"list_issues"}, listedNames(t, out))
	})
}

func TestView_ShouldWarnHidden(t *testing.T) {
	t.Parallel()

	view := compileView(t, rename("create_issue", "open_issue", ""))
	now := time.Unix(1_000, 0)

	assert.True(t, view.ShouldWarnHidden("open_issue", now))
	assert.False(t, view.ShouldWarnHidden("open_issue", now.Add(time.Minute)))
	assert.True(t, view.ShouldWarnMissing("open_issue", now), "missing and hidden warnings are limited separately")
	assert.True(t, view.ShouldWarnHidden("open_issue", now.Add(MissingSourceWarningInterval)))
}

func BenchmarkView_RewriteToolsList_Renames(b *testing.B) {
	ext := &oas.TykMCPServer{}
	parts := make([]string, 0, 50)
	for i := range 50 {
		name := fmt.Sprintf("tool_%d", i)
		parts = append(parts, fmt.Sprintf(`{"name":%q,"description":"d","inputSchema":{"type":"object","properties":{"a":{"type":"string"}}},"annotations":{"readOnlyHint":true}}`, name))
		if i%5 == 0 {
			primitive := annotate(name, oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)})
			primitive.Name = "renamed_" + name
			primitive.Description = "overridden"
			ext.Primitives = append(ext.Primitives, primitive)
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
