package gateway

import (
	"fmt"
	htmltemplate "html/template"
	"net/http"
	"strconv"
	"strings"
	texttemplate "text/template"

	"github.com/tidwall/gjson"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/errors"
)

const (
	// maxBodySizeForMatching is the maximum body size for regex/JSON path matching.
	// Large upstream error pages (HTML, stack traces) are truncated to this size
	// before pattern matching to prevent performance issues with regex on large bodies.
	// Gateway-generated errors are typically small and won't hit this limit.
	maxBodySizeForMatching = 4096 // 4KB
)

// CompiledErrorOverrides provides lookup for error overrides by status code.
type CompiledErrorOverrides struct {
	// ByExactCode maps exact status codes to their override rules.
	ByExactCode map[int][]*apidef.ErrorOverride

	// ByPrefix maps status code prefixes to pattern rules.
	ByPrefix map[int][]*apidef.ErrorOverride
}

// ErrorOverrides provides centralized error override logic for both
// Tyk-generated errors (via HandleError) and upstream error responses
// (via response middleware).
type ErrorOverrides struct {
	Spec *APISpec
	Gw   *Gateway
}

// OverrideResult contains the result of applying an error override.
// Holds context needed for response writing including the matched rule.
type OverrideResult struct {
	// StatusCode is the HTTP status code to return.
	StatusCode int

	// Headers are additional HTTP headers to include.
	Headers map[string]string

	// OriginalCode is the original error status code before override.
	OriginalCode int

	// rule is the matched ErrorOverride rule (for template access).
	rule *apidef.ErrorOverride
}

// NewErrorOverrides creates a new ErrorOverrides instance.
func NewErrorOverrides(spec *APISpec, gw *Gateway) *ErrorOverrides {
	return &ErrorOverrides{
		Spec: spec,
		Gw:   gw,
	}
}

// CompileErrorOverrides compiles all regex patterns, pre-compiles inline message
// templates, and builds an indexed lookup structure for O(1) status code matching.
// Called during config load (gateway-level) or API load (API-level).
// Compilation failures are logged as warnings and those rules are skipped.
// Returns nil if no overrides are provided or all rules failed to compile.
func CompileErrorOverrides(overrides apidef.ErrorOverridesMap) *CompiledErrorOverrides {
	if len(overrides) == 0 {
		return nil
	}

	compiled := &CompiledErrorOverrides{
		ByExactCode: make(map[int][]*apidef.ErrorOverride),
		ByPrefix:    make(map[int][]*apidef.ErrorOverride),
	}

	for statusCode, rules := range overrides {
		if statusCode == "" {
			continue
		}

		validRules := compileRulesForStatusCode(rules, statusCode)
		if len(validRules) == 0 {
			continue
		}

		indexCompiledRules(compiled, statusCode, validRules)
	}

	return compiled
}

// compileRulesForStatusCode validates and compiles all rules for a given status code.
// Returns pointers to successfully compiled rules; failed rules are logged and skipped.
func compileRulesForStatusCode(rules []apidef.ErrorOverride, statusCode string) []*apidef.ErrorOverride {
	validRules := make([]apidef.ErrorOverride, 0, len(rules))

	for i := range rules {
		if err := compileSingleRule(&rules[i]); err != nil {
			log.WithError(err).WithFields(map[string]any{
				"status_code": statusCode,
				"rule_index":  i,
			}).Warn("Failed to compile error override rule, skipping")
			continue
		}

		validRules = append(validRules, rules[i])
	}

	// Convert to pointer slice for storage
	rulePtrs := make([]*apidef.ErrorOverride, len(validRules))
	for i := range validRules {
		rulePtrs[i] = &validRules[i]
	}

	return rulePtrs
}

// compileSingleRule compiles regex patterns and templates for a single override rule.
// Returns error if compilation fails; the rule should be skipped.
func compileSingleRule(rule *apidef.ErrorOverride) error {
	// Compile regex pattern for matching
	if rule.Match != nil {
		if err := rule.Match.Compile(); err != nil {
			return fmt.Errorf("invalid match pattern: %w", err)
		}
	}

	// Pre-compile inline body templates
	if rule.Response.Body != "" {
		if err := compileBodyTemplates(rule); err != nil {
			return fmt.Errorf("invalid body template: %w", err)
		}
	}

	return nil
}

// indexCompiledRules adds validated rules to the appropriate index (exact code or pattern).
func indexCompiledRules(compiled *CompiledErrorOverrides, statusCode string, rules []*apidef.ErrorOverride) {
	// Try exact match first: "500", "401"
	if exact, err := strconv.Atoi(statusCode); err == nil {
		compiled.ByExactCode[exact] = rules
		return
	}

	// Try pattern match: "4xx", "5xx"
	if len(statusCode) == 3 && statusCode[1:] == "xx" {
		if prefix, err := strconv.Atoi(string(statusCode[0])); err == nil {
			compiled.ByPrefix[prefix] = rules
			return
		}
		log.WithField("status_code", statusCode).Warn("Invalid status code pattern, skipping")
		return
	}

	log.WithField("status_code", statusCode).Warn("Unrecognized status code format, skipping")
}

// compileBodyTemplates pre-compiles inline Body into both template types if it contains template variables.
// text/template is used for XML, html/template for JSON (auto-escapes).
// Plain text bodies are skipped - they'll be written directly.
func compileBodyTemplates(rule *apidef.ErrorOverride) error {
	body := rule.Response.Body

	// Simple heuristic: check if body looks like a template
	// We support {{.StatusCode}} and {{.Message}}, so checking for "{{." is sufficient
	// This is O(n) with zero allocations, much faster than parsing the template
	if !strings.Contains(body, "{{.") {
		return nil
	}

	// Compile text/template (for XML content)
	textTmpl, err := texttemplate.New("body").Parse(body)
	if err != nil {
		return fmt.Errorf("invalid template syntax: %w", err)
	}

	// Compile html/template (for JSON content - auto-escapes HTML)
	htmlTmpl, err := htmltemplate.New("body").Parse(body)
	if err != nil {
		return fmt.Errorf("invalid template syntax: %w", err)
	}

	rule.SetCompiledTemplates(textTmpl, htmlTmpl)
	return nil
}

// ApplyOverride attempts to match and apply an override for the given error.
// Uses O(1) lookup by status code, then checks additional matching criteria.
// Returns nil if no override matches.
func (o *ErrorOverrides) ApplyOverride(r *http.Request, statusCode int, body []byte) *OverrideResult {
	apiCompiled := o.Spec.GetCompiledErrorOverrides()
	gwCompiled := o.Gw.GetCompiledErrorOverrides()

	if apiCompiled == nil && gwCompiled == nil {
		return nil
	}

	if apiCompiled != nil {
		if rule := o.findMatchingRule(r, apiCompiled, statusCode, body); rule != nil {
			return o.createOverrideResult(rule, statusCode)
		}
	}

	if gwCompiled != nil {
		if rule := o.findMatchingRule(r, gwCompiled, statusCode, body); rule != nil {
			return o.createOverrideResult(rule, statusCode)
		}
	}

	return nil
}

// findMatchingRuleGeneric searches for a matching override rule using a custom match function.
// Checks exact status code first, then pattern matches (4xx, 5xx).
// Rules are evaluated in order within each status code (first match wins).
func (o *ErrorOverrides) findMatchingRuleGeneric(
	compiled *CompiledErrorOverrides,
	statusCode int,
	matchFunc func(*apidef.ErrorOverride) bool,
) *apidef.ErrorOverride {
	// First, check exact status code matches (O(1) lookup)
	if rules, ok := compiled.ByExactCode[statusCode]; ok {
		for _, rule := range rules {
			if matchFunc(rule) {
				return rule
			}
		}
	}

	// Then, check pattern matches (4xx, 5xx) - O(1) lookup by prefix
	prefix := statusCode / 100
	if rules, ok := compiled.ByPrefix[prefix]; ok {
		for _, rule := range rules {
			if matchFunc(rule) {
				return rule
			}
		}
	}

	return nil
}

// findMatchingRule searches for a matching override rule.
// Checks exact status code first, then pattern matches (4xx, 5xx).
// Rules are evaluated in order within each status code (first match wins).
func (o *ErrorOverrides) findMatchingRule(r *http.Request, compiled *CompiledErrorOverrides, statusCode int, body []byte) *apidef.ErrorOverride {
	return o.findMatchingRuleGeneric(compiled, statusCode, func(rule *apidef.ErrorOverride) bool {
		return o.matchesAdditionalCriteria(r, rule, body)
	})
}

// matchesAdditionalCriteria checks if request/body matches flag and message_pattern criteria.
// Used for gateway-generated errors where body is plain text (not JSON).
// For upstream JSON responses, use matchesUpstreamCriteria instead.
// Status code is already matched via map lookup.
func (o *ErrorOverrides) matchesAdditionalCriteria(r *http.Request, rule *apidef.ErrorOverride, body []byte) bool {
	if rule.Match == nil {
		return true
	}

	// Flag matching (highest priority - semantic match from error classification)
	if rule.Match.Flag != "" {
		if o.matchFlag(r, rule.Match.Flag) {
			return true
		}
	}

	// Message pattern matching (regex on error message)
	if rule.Match.MessagePattern != "" {
		return o.matchMessagePattern(rule.Match, body)
	}

	// No criteria specified = match all
	hasMatchCriteria := rule.Match.Flag != "" || rule.Match.MessagePattern != ""
	return !hasMatchCriteria
}

// matchFlag checks if the error classification flag matches the expected flag.
func (o *ErrorOverrides) matchFlag(r *http.Request, expectedFlag errors.ResponseFlag) bool {
	errClass := ctx.GetErrorClassification(r)
	if errClass == nil {
		return false
	}
	return errClass.Flag == expectedFlag
}

// matchMessagePattern matches body against a pre-compiled regex pattern.
func (o *ErrorOverrides) matchMessagePattern(match *apidef.ErrorMatcher, body []byte) bool {
	if match.CompiledPattern == nil {
		// Pattern was not compiled (should not happen if CompileErrorOverrides was called)
		log.Warn("Error override message_pattern not compiled, skipping match")
		return false
	}
	return match.CompiledPattern.Match(body)
}

// matchBodyField extracts a JSON value using gjson and compares it.
func (o *ErrorOverrides) matchBodyField(field, expectedValue string, body []byte) bool {
	result := gjson.GetBytes(body, field)
	if !result.Exists() {
		return false
	}
	return result.String() == expectedValue
}

// GetTemplateExecutor returns the template to execute, or nil if body should be written directly.
func (r *OverrideResult) GetTemplateExecutor(gw *Gateway, errCtx *ErrorResponseContext) TemplateExecutor {
	// Body with template variables
	if r.rule.Response.Body != "" && r.rule.HasCompiledTemplate() {
		return r.getInlineTemplate(errCtx)
	}

	// Plain body - written directly, no template needed
	if r.rule.Response.Body != "" {
		return nil
	}

	// File template
	if r.rule.Response.Template != "" {
		return r.getFileTemplate(gw, errCtx)
	}

	return nil
}

// GetMessageForTemplate returns the semantic message for {{.Message}} in templates.
func (r *OverrideResult) GetMessageForTemplate() string {
	return r.rule.Response.Message
}

// GetBody returns the response body.
func (r *OverrideResult) GetBody() string {
	return r.rule.Response.Body
}

// ShouldWriteDirectly returns true if body should be written as-is (no template variables).
func (r *OverrideResult) ShouldWriteDirectly() bool {
	return r.rule.Response.Body != "" && !r.rule.HasCompiledTemplate()
}

// ShouldUseDefaultTemplate returns true when only Message is set (no Body, no Template).
func (r *OverrideResult) ShouldUseDefaultTemplate() bool {
	return r.rule.Response.Body == "" &&
		r.rule.Response.Template == "" &&
		r.rule.Response.Message != ""
}

// getFileTemplate looks up a template file from the gateway's template cache.
func (r *OverrideResult) getFileTemplate(gw *Gateway, errCtx *ErrorResponseContext) TemplateExecutor {
	templateName := r.rule.Response.Template + "." + errCtx.TemplateExtension

	if errCtx.IsXML {
		if tmpl := gw.templatesRaw.Lookup(templateName); tmpl != nil {
			return tmpl
		}
		// Fallback: try without extension
		return gw.templatesRaw.Lookup(r.rule.Response.Template)
	}

	if tmpl := gw.templates.Lookup(templateName); tmpl != nil {
		return tmpl
	}
	// Fallback: try without extension
	return gw.templates.Lookup(r.rule.Response.Template)
}

// getInlineTemplate returns the pre-compiled inline message template.
func (r *OverrideResult) getInlineTemplate(errCtx *ErrorResponseContext) TemplateExecutor {
	compiled := r.rule.GetCompiledTemplate(errCtx.IsXML)
	if compiled == nil {
		return nil
	}

	// The compiled template is already a TemplateExecutor (either text/template or html/template)
	if tmpl, ok := compiled.(TemplateExecutor); ok {
		return tmpl
	}

	return nil
}

// ApplyUpstreamOverride applies overrides for upstream 4xx/5xx responses.
// Uses lazy body reading via closure.
func (o *ErrorOverrides) ApplyUpstreamOverride(statusCode int, readBody func() []byte) *OverrideResult {
	apiCompiled := o.Spec.GetCompiledErrorOverrides()
	gwCompiled := o.Gw.GetCompiledErrorOverrides()

	if apiCompiled == nil && gwCompiled == nil {
		return nil
	}

	matchFunc := func(rule *apidef.ErrorOverride) bool {
		var matchBody []byte
		if o.needsBodyForMatch(rule) {
			matchBody = readBody()
		}

		return o.matchesUpstreamCriteria(rule, matchBody, statusCode)
	}

	if apiCompiled != nil {
		if rule := o.findMatchingRuleGeneric(apiCompiled, statusCode, matchFunc); rule != nil {
			return o.createOverrideResult(rule, statusCode)
		}
	}

	if gwCompiled != nil {
		if rule := o.findMatchingRuleGeneric(gwCompiled, statusCode, matchFunc); rule != nil {
			return o.createOverrideResult(rule, statusCode)
		}
	}

	return nil
}

func (o *ErrorOverrides) createOverrideResult(rule *apidef.ErrorOverride, statusCode int) *OverrideResult {
	result := &OverrideResult{
		StatusCode:   rule.Response.StatusCode,
		Headers:      rule.Response.Headers,
		OriginalCode: statusCode,
		rule:         rule,
	}
	if result.StatusCode == 0 {
		result.StatusCode = statusCode
	}
	return result
}

// matchesUpstreamCriteria checks if an upstream response matches the rule.
// Handles URS flag specially for 5xx responses, supports body_field and message_pattern.
// Skips gateway-only flags (AKI, RLT, etc.) since they require request context.
func (o *ErrorOverrides) matchesUpstreamCriteria(rule *apidef.ErrorOverride, body []byte, statusCode int) bool {
	if rule.Match == nil {
		return true
	}

	// URS flag matches any 5xx upstream response
	if rule.Match.Flag == errors.URS {
		return statusCode >= 500 && statusCode <= 599
	}

	// Skip rules with other flags - they're gateway-only (AKI, RLT, etc.)
	if rule.Match.Flag != "" {
		return false
	}

	// Body field matching (JSON path) - useful for upstream JSON responses
	if rule.Match.BodyField != "" && rule.Match.BodyValue != "" {
		if o.matchBodyField(rule.Match.BodyField, rule.Match.BodyValue, body) {
			return true
		}
	}

	// Message pattern matching (regex)
	if rule.Match.MessagePattern != "" {
		return o.matchMessagePattern(rule.Match, body)
	}

	// No match criteria = match all
	hasMatchCriteria := rule.Match.MessagePattern != "" ||
		(rule.Match.BodyField != "" && rule.Match.BodyValue != "")
	return !hasMatchCriteria
}

// needsBodyForMatch returns true if the rule requires body inspection.
func (o *ErrorOverrides) needsBodyForMatch(rule *apidef.ErrorOverride) bool {
	if rule.Match == nil {
		return false
	}
	return rule.Match.BodyField != "" || rule.Match.MessagePattern != ""
}
