package apidef

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewriteToStartsWithRequestValue(t *testing.T) {
	for rewriteTo, want := range map[string]bool{
		"$0":                            true,
		"$1":                            true,
		"$12/rest":                      true,
		"$tyk_context.headers_X_Target": true,
		"$tyk_context.trigger-0-u-0":    true,
		"/$1":                           false,
		"/api/$1":                       false,
		"http://host/$1":                false,
		"tyk://other-api/$1":            false,
		"$tyk_meta.target":              false,
		"$secret_conf.target":           false,
		"$secret_env.TARGET/$1":         false,
		"$tyk_contextual":               false,
		"$":                             false,
		"":                              false,
		"/réécriture/$1":                false,
		"$tyk_context.日本":               true,
		" $1":                           false,
		"https://例え.テスト/$tyk_context.x": false,
	} {
		t.Run(rewriteTo, func(t *testing.T) {
			assert.Equal(t, want, RewriteToStartsWithRequestValue(rewriteTo))
		})
	}
}

func TestRuleURLRewriteTarget_Validate(t *testing.T) {
	apiDef := func(rewrites ...URLRewriteMeta) *APIDefinition {
		return &APIDefinition{VersionData: VersionData{Versions: map[string]VersionInfo{
			"Default": {Name: "Default", ExtendedPaths: ExtendedPathsSet{URLRewrite: rewrites}},
		}}}
	}

	t.Run("rejects rewrite_to that starts with a capture", func(t *testing.T) {
		result := Validate(apiDef(URLRewriteMeta{Path: "/q", Method: http.MethodGet, RewriteTo: "$1"}),
			ValidationRuleSet{&RuleURLRewriteTarget{}})

		assert.False(t, result.IsValid)
		require.Equal(t, 1, result.ErrorCount())
		assert.ErrorIs(t, result.FirstError(), ErrRewriteToStartsWithRequestValue)
		assert.Contains(t, result.FirstError().Error(), `GET /q in version "Default"`)
	})

	t.Run("rejects a trigger rewrite_to that starts with a context value", func(t *testing.T) {
		result := Validate(apiDef(URLRewriteMeta{
			Path: "/q", Method: http.MethodGet, RewriteTo: "/safe",
			Triggers: []RoutingTrigger{{RewriteTo: "/ok"}, {RewriteTo: "$tyk_context.headers_X"}},
		}), ValidationRuleSet{&RuleURLRewriteTarget{}})

		assert.False(t, result.IsValid)
		require.Equal(t, 1, result.ErrorCount())
		assert.ErrorIs(t, result.FirstError(), ErrRewriteToStartsWithRequestValue)
		assert.Contains(t, result.FirstError().Error(), "trigger 1")
	})

	t.Run("reports every offending rewrite", func(t *testing.T) {
		result := Validate(apiDef(
			URLRewriteMeta{Path: "/a", Method: http.MethodGet, RewriteTo: "$1"},
			URLRewriteMeta{Path: "/b", Method: http.MethodPost, RewriteTo: "$tyk_context.x"},
		), ValidationRuleSet{&RuleURLRewriteTarget{}})

		assert.Equal(t, 2, result.ErrorCount())
	})

	t.Run("ignores disabled rewrites", func(t *testing.T) {
		result := Validate(apiDef(URLRewriteMeta{Disabled: true, RewriteTo: "$1",
			Triggers: []RoutingTrigger{{RewriteTo: "$1"}}}), ValidationRuleSet{&RuleURLRewriteTarget{}})

		assert.True(t, result.IsValid)
	})

	t.Run("accepts literal prefixes and API manager values", func(t *testing.T) {
		result := Validate(apiDef(
			URLRewriteMeta{RewriteTo: "/$1"},
			URLRewriteMeta{RewriteTo: "https://other.example/$1"},
			URLRewriteMeta{RewriteTo: "$tyk_meta.target"},
			URLRewriteMeta{RewriteTo: "$secret_conf.target"},
			URLRewriteMeta{RewriteTo: "tyk://other-api/$1"},
		), ValidationRuleSet{&RuleURLRewriteTarget{}})

		assert.True(t, result.IsValid)
	})

	t.Run("no versions", func(t *testing.T) {
		result := Validate(&APIDefinition{}, ValidationRuleSet{&RuleURLRewriteTarget{}})
		assert.True(t, result.IsValid)
	})

	t.Run("part of the default rule set", func(t *testing.T) {
		assert.Contains(t, DefaultValidationRuleSet, &RuleURLRewriteTarget{})
	})
}
