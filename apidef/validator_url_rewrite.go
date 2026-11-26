package apidef

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
)

// ErrRewriteToStartsWithRequestValue is returned when a URL rewrite's
// rewrite_to starts with a value that comes from the request.
var ErrRewriteToStartsWithRequestValue = errors.New("rewrite_to can't start with a value from the request; add a literal prefix such as \"/\"")

// requestValueAtStart matches a numbered capture group ($0, $1, ...) or a
// request context variable at the start of a rewrite_to value.
var requestValueAtStart = regexp.MustCompile(`^\$(\d+|tyk_context\.)`)

// RewriteToStartsWithRequestValue reports whether rewriteTo starts with a
// value that the API client controls: a numbered capture group or a
// $tyk_context variable. A value there can name the upstream host, so the API
// client could choose which server the gateway connects to.
func RewriteToStartsWithRequestValue(rewriteTo string) bool {
	return requestValueAtStart.MatchString(rewriteTo)
}

// RuleURLRewriteTarget rejects enabled URL rewrites whose rewrite_to, or the
// rewrite_to of one of their triggers, starts with a value from the request.
type RuleURLRewriteTarget struct{}

// Validate adds one error for every rewrite_to that starts with a value from
// the request.
func (r *RuleURLRewriteTarget) Validate(apiDef *APIDefinition, validationResult *ValidationResult) {
	for _, version := range slices.Sorted(maps.Keys(apiDef.VersionData.Versions)) {
		for _, rewrite := range apiDef.VersionData.Versions[version].ExtendedPaths.URLRewrite {
			if rewrite.Disabled {
				continue
			}

			rule := urlRewriteRuleName(rewrite, version)

			if RewriteToStartsWithRequestValue(rewrite.RewriteTo) {
				validationResult.IsValid = false
				validationResult.AppendError(fmt.Errorf("%s: %w", rule, ErrRewriteToStartsWithRequestValue))
			}

			for i, trigger := range rewrite.Triggers {
				if RewriteToStartsWithRequestValue(trigger.RewriteTo) {
					validationResult.IsValid = false
					validationResult.AppendError(fmt.Errorf("%s, trigger %d: %w", rule, i, ErrRewriteToStartsWithRequestValue))
				}
			}
		}
	}
}

// urlRewriteRuleName names a URL rewrite in an error message. OAS APIs have a
// single unnamed version, so the version is left out when it has no name.
func urlRewriteRuleName(rewrite URLRewriteMeta, version string) string {
	if version == "" {
		return fmt.Sprintf("url rewrite %s %s", rewrite.Method, rewrite.Path)
	}
	return fmt.Sprintf("url rewrite %s %s in version %q", rewrite.Method, rewrite.Path, version)
}
