package oas

import (
	"fmt"
	"sort"

	"github.com/TykTechnologies/tyk/apidef"
)

// URLRewrite configures URL rewriting.
type URLRewrite struct {
	// Enabled enables URL rewriting if set to true.
	Enabled bool `bson:"enabled" json:"enabled"`

	// Pattern is the regular expression to match values against. If a value matches the
	// defined pattern, the URL rewrite is triggered for the rule.
	Pattern string `bson:"pattern,omitempty" json:"pattern,omitempty"`

	// RewriteTo specifies a URL to rewrite the request to, if the
	// embedded URL rewrite rule is a match.
	RewriteTo string `bson:"rewriteTo,omitempty" json:"rewriteTo,omitempty"`

	// Triggers contain advanced additional triggers for the URL rewrite.
	// The triggers are processed only if the requested URL matches the pattern above.
	Triggers []*URLRewriteTrigger `bson:"triggers,omitempty" json:"triggers,omitempty"`
}

// URLRewriteInput defines the input for an URL rewrite rule.
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
type URLRewriteInput string

// URLRewriteConditions defines the matching mode for an URL rewrite rules.
//
// - Value `or` means any of the defined trigger rules may match
// - Value `and` means all the defined trigger rules must match
type URLRewriteCondition string

const (
	InputQuery           URLRewriteInput = "query"
	InputPath            URLRewriteInput = "path"
	InputHeader          URLRewriteInput = "header"
	InputSessionMetadata URLRewriteInput = "sessionMetadata"
	InputRequestBody     URLRewriteInput = "requestBody"
	InputRequestContext  URLRewriteInput = "requestContext"

	ConditionAll    URLRewriteCondition = "all"
	ConditionAny    URLRewriteCondition = "any"
	ConditionIgnore URLRewriteCondition = ""
)

var (
	// URLRewriteInputs contains all valid URL rewrite input types.
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
type URLRewriteTrigger struct {
	// Condition represents a boolean operator for rules.
	//
	// If set to "and", all rules must match to trigger the rewrite.
	// If set to "or", any of the rules can match to trigger the rewrite.
	Condition URLRewriteCondition `bson:"condition" json:"condition"`

	// Rules contain conditional triggers for URL rewriting.
	// If empty, it enables non-conditional rewrites.
	Rules []*URLRewriteRule `bson:"rules,omitempty" json:"rules,omitempty"`

	// RewriteTo specifies a URL to rewrite the request to, if the
	// conditions match.
	RewriteTo string `bson:"rewriteTo" json:"rewriteTo"`
}

// URLRewriteRule represents a rewrite matching rules.
type URLRewriteRule struct {
	// In specifies one of the valid inputs for URL rewriting.
	// By default, it uses `url` as the input source.
	In URLRewriteInput `bson:"in" json:"in"`

	// Name is the index in the inputs. It is ignored for InputRequestBody
	// as it contains only a single value, while the others are objects.
	Name string `bson:"name,omitempty" json:"name,omitempty"`

	// Pattern is the regular expression to match values against. If a value matches the
	// defined pattern, the URL rewrite is triggered for the rule.
	Pattern string `bson:"pattern" json:"pattern"`

	// Negate is a boolean negation operator. Setting it to true allows to negate
	// the match if any, allowing for a "match all except <pattern>" style matching.
	Negate bool `bson:"negate,omitempty" json:"negate,omitempty"`
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

func (v *URLRewrite) appendRules(rules *[]*URLRewriteRule, from map[string]apidef.StringRegexMap, in URLRewriteInput) {
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

func (v *URLRewrite) extractTriggerOptions(rules []*URLRewriteRule) apidef.RoutingTriggerOptions {
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
