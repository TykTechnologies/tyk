package oas

import (
	"fmt"
	"sort"

	"github.com/TykTechnologies/tyk/apidef"
)

// URLRewrite configures URL rewriting.
// Tyk classic API definition: `version_data.versions..extended_paths.url_rewrite`.
type URLRewrite struct {
	// Enabled activates URL rewriting if set to true.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Pattern is the regular expression against which the request URL is compared for the primary rewrite check.
	// If this matches the defined pattern, the primary URL rewrite is triggered.
	Pattern string `bson:"pattern,omitempty" json:"pattern,omitempty"`

	// RewriteTo specifies the URL to which the request shall be rewritten if the primary URL rewrite is triggered.
	RewriteTo string `bson:"rewriteTo,omitempty" json:"rewriteTo,omitempty"`

	// Triggers contain advanced additional triggers for the URL rewrite.
	// The triggers are processed only if the requested URL matches the pattern above.
	Triggers []*URLRewriteTrigger `bson:"triggers,omitempty" json:"triggers,omitempty"`
}

// URLRewriteInput defines the input for an URL rewrite rule.
// Tyk classic API definition: Input source for URL rewrite rules in `version_data.versions..extended_paths.url_rewrite[].triggers[].options`.
//
// The following values are valid:
//
// - `url`, match pattern against URL
// - `query`, match pattern against named query parameter value
// - `path`, match pattern against named path parameter value
// - `header`, match pattern against named header value
// - `sessionMetadata`, match pattern against session metadata
// - `requestBody`, match pattern against request body
// - `requestContext`, match pattern against request context
//
// The default `url` is used as the input source.
type URLRewriteInput string

// URLRewriteCondition defines the matching mode for an URL rewrite rules.
// Tyk classic API definition: Matching condition in `version_data.versions..extended_paths.url_rewrite[].triggers[].on`.
//
// - Value `any` means any of the defined trigger rules may match.
// - Value `all` means all the defined trigger rules must match.
type URLRewriteCondition string

// Enumerated constants for inputs and conditions.
const (
	InputQuery           URLRewriteInput = "query"
	InputPath            URLRewriteInput = "path"
	InputHeader          URLRewriteInput = "header"
	InputSessionMetadata URLRewriteInput = "sessionMetadata"
	InputRequestBody     URLRewriteInput = "requestBody"
	InputRequestContext  URLRewriteInput = "requestContext"

	ConditionAll URLRewriteCondition = "all"
	ConditionAny URLRewriteCondition = "any"
)

var (
	// URLRewriteConditions contains all valid URL rewrite condition values.
	URLRewriteConditions = []URLRewriteCondition{
		ConditionAll,
		ConditionAny,
	}

	// URLRewriteInputs contains all valid URL rewrite input values.
	URLRewriteInputs = []URLRewriteInput{
		InputQuery,
		InputPath,
		InputHeader,
		InputSessionMetadata,
		InputRequestBody,
		InputRequestContext,
	}
)

// URLRewriteTrigger represents a set of matching rules for a rewrite.
// Tyk classic API definition: `version_data.versions..extended_paths.url_rewrite[].triggers`.
type URLRewriteTrigger struct {
	// Condition indicates the logical combination that will be applied to the rules for an advanced trigger.
	Condition URLRewriteCondition `bson:"condition" json:"condition"`

	// Rules contain individual checks that are combined according to the
	// `condition` to determine if the URL rewrite will be triggered.
	// If empty, the trigger is ignored.
	Rules []*URLRewriteRule `bson:"rules,omitempty" json:"rules,omitempty"`

	// RewriteTo specifies the URL to which the request shall be rewritten
	// if indicated by the combination of `condition` and `rules`.
	RewriteTo string `bson:"rewriteTo" json:"rewriteTo"`
}

// URLRewriteRule represents a rewrite matching rules.
// Tyk classic API definition: `version_data.versions..extended_paths.url_rewrite[].triggers[].options`.
type URLRewriteRule struct {
	// In specifies one of the valid inputs for URL rewriting.
	In URLRewriteInput `bson:"in" json:"in"`

	// Name is the index in the value declared inside `in`.
	//
	// Example: for `in=query`, `name=q`, the parameter `q` would
	// be read from the request query parameters.
	//
	// The value of name is unused when `in` is set to `requestBody`,
	// as the request body is a single value and not a set of values.
	Name string `bson:"name,omitempty" json:"name,omitempty"`

	// Pattern is the regular expression against which the `in` values are compared for this rule check.
	// If the value matches the defined `pattern`, the URL rewrite is triggered for this rule.
	Pattern string `bson:"pattern" json:"pattern"`

	// Negate is a boolean negation operator. Setting it to true inverts the matching behaviour
	// such that the rewrite will be triggered if the value does not match the `pattern` for this rule.
	Negate bool `bson:"negate" json:"negate"`
}

// Fill fills *URLRewrite receiver from apidef.URLRewriteMeta.
func (v *URLRewrite) Fill(meta apidef.URLRewriteMeta) {
	v.Enabled = !meta.Disabled
	v.Pattern = meta.MatchPattern
	v.RewriteTo = meta.RewriteTo

	v.Triggers = v.fillTriggers(meta.Triggers)

	if len(v.Triggers) == 0 {
		v.Triggers = nil
	}

	v.Sort()
}

func (v *URLRewrite) fillTriggers(from []apidef.RoutingTrigger) []*URLRewriteTrigger {
	result := make([]*URLRewriteTrigger, 0)
	for _, t := range from {
		rules := v.fillRules(t.Options)
		if len(rules) == 0 {
			continue
		}

		trigger := &URLRewriteTrigger{
			Condition: URLRewriteCondition(t.On),
			Rules:     rules,
			RewriteTo: t.RewriteTo,
		}
		result = append(result, trigger)
	}
	return result
}

// Sort reorders the internal trigger rules.
func (v *URLRewrite) Sort() {
	for _, t := range v.Triggers {
		rules := t.Rules

		sort.Slice(rules, func(i, j int) bool {
			return rules[i].In.Index() < rules[j].In.Index()
		})
	}
}

func (v *URLRewrite) fillRules(from apidef.RoutingTriggerOptions) []*URLRewriteRule {
	result := []*URLRewriteRule{}

	v.appendRules(&result, from.HeaderMatches, InputHeader)
	v.appendRules(&result, from.QueryValMatches, InputQuery)
	v.appendRules(&result, from.PathPartMatches, InputPath)
	v.appendRules(&result, from.SessionMetaMatches, InputSessionMetadata)
	v.appendRules(&result, from.RequestContextMatches, InputRequestContext)

	v.appendRules(&result, map[string]apidef.StringRegexMap{
		"": from.PayloadMatches,
	}, InputRequestBody)

	return result
}

func (*URLRewrite) appendRules(rules *[]*URLRewriteRule, from map[string]apidef.StringRegexMap, in URLRewriteInput) {
	for name, v := range from {
		if v.Empty() {
			continue
		}

		rule := &URLRewriteRule{
			In:      in,
			Name:    name,
			Pattern: v.MatchPattern,
			Negate:  v.Reverse,
		}
		*rules = append(*rules, rule)
	}
}

// ExtractTo fills *apidef.URLRewriteMeta from *URLRewrite.
func (v *URLRewrite) ExtractTo(dest *apidef.URLRewriteMeta) {
	dest.Disabled = !v.Enabled
	dest.MatchPattern = v.Pattern
	dest.RewriteTo = v.RewriteTo
	dest.Triggers = v.extractTriggers()
	if len(dest.Triggers) == 0 {
		dest.Triggers = nil
	}
}

func (v *URLRewrite) extractTriggers() []apidef.RoutingTrigger {
	triggers := make([]apidef.RoutingTrigger, len(v.Triggers))
	for i, trigger := range v.Triggers {
		routingTrigger := apidef.RoutingTrigger{
			On:        apidef.RoutingTriggerOnType(trigger.Condition),
			RewriteTo: trigger.RewriteTo,
			Options:   v.extractTriggerOptions(trigger.Rules),
		}
		triggers[i] = routingTrigger
	}
	return triggers
}

func (*URLRewrite) extractTriggerOptions(rules []*URLRewriteRule) apidef.RoutingTriggerOptions {
	result := apidef.NewRoutingTriggerOptions()

	for _, rule := range rules {
		item := apidef.StringRegexMap{
			MatchPattern: rule.Pattern,
			Reverse:      rule.Negate,
		}

		switch rule.In {
		case InputRequestBody:
			result.PayloadMatches = item
		case InputRequestContext:
			result.RequestContextMatches[rule.Name] = item
		case InputHeader:
			result.HeaderMatches[rule.Name] = item
		case InputPath:
			result.PathPartMatches[rule.Name] = item
		case InputQuery:
			result.QueryValMatches[rule.Name] = item
		case InputSessionMetadata:
			result.SessionMetaMatches[rule.Name] = item
		}
	}

	return result
}

// Valid returns true if the type value matches valid values, false otherwise.
func (i URLRewriteInput) Valid() bool {
	switch i {
	case InputQuery, InputPath, InputHeader, InputSessionMetadata, InputRequestBody, InputRequestContext:
		return true
	}
	return false
}

// Index returns the cardinal order for the value. Used for sorting.
func (i URLRewriteInput) Index() int {
	for k, v := range URLRewriteInputs {
		if v == i {
			return k
		}
	}
	return -1
}

// Err returns an error if the type value is invalid, nil otherwise.
func (i URLRewriteInput) Err() error {
	if !i.Valid() {
		return fmt.Errorf("Invalid value for URL rewrite input: %s", i)
	}
	return nil
}

func fillURLRewrite(meta apidef.URLRewriteMeta, operation *Operation) {
	if operation.URLRewrite == nil {
		operation.URLRewrite = &URLRewrite{}
	}

	operation.URLRewrite.Fill(meta)
	if ShouldOmit(operation.URLRewrite) {
		operation.URLRewrite = nil
	}
}

func (o *Operation) extractURLRewriteTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.URLRewrite == nil {
		return
	}

	meta := apidef.URLRewriteMeta{Path: path, Method: method}
	o.URLRewrite.ExtractTo(&meta)
	ep.URLRewrite = append(ep.URLRewrite, meta)
}
