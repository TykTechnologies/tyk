package user

import (
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/TykTechnologies/tyk/apidef"
)

// Errors reported when an access condition cannot be evaluated. Access
// conditions fail closed, so any of these means the enclosing AccessSpec will
// deny every request it would otherwise have granted. They are returned at
// save time so that a misconfiguration surfaces as an error rather than as a
// silent outage on live traffic.
var (
	// ErrAccessConditionEmpty is returned for a condition that configures no
	// options at all. A condition that constrains nothing cannot be satisfied.
	ErrAccessConditionEmpty = errors.New("access condition has no options set")

	// ErrAccessConditionOn is returned for an unrecognised On value. Only
	// apidef.All, apidef.Any and the empty string (which means apidef.All) are
	// accepted, so that a typo cannot quietly change how options combine.
	ErrAccessConditionOn = errors.New(`access condition "on" must be "all", "any" or empty`)
)

// Validate reports whether the condition is well formed enough to be
// evaluated. It is deliberately strict: because conditions decide access, a
// condition the Gateway cannot evaluate denies every request, so accepting one
// at save time trades an error message for an outage.
func (c AccessCondition) Validate() error {
	switch c.On {
	case apidef.All, apidef.Any, "":
	default:
		return fmt.Errorf("%w, got %q", ErrAccessConditionOn, c.On)
	}

	named := map[string]map[string]apidef.StringRegexMap{
		"header_matches":          c.Options.HeaderMatches,
		"query_val_matches":       c.Options.QueryValMatches,
		"path_part_matches":       c.Options.PathPartMatches,
		"session_meta_matches":    c.Options.SessionMetaMatches,
		"request_context_matches": c.Options.RequestContextMatches,
	}

	configured := 0

	// Iterating the maps in a fixed order keeps the reported error stable for
	// a given input, which matters for tests and for API responses.
	for _, field := range []string{
		"header_matches",
		"query_val_matches",
		"path_part_matches",
		"session_meta_matches",
		"request_context_matches",
	} {
		options := named[field]
		if len(options) == 0 {
			continue
		}

		configured++

		for _, name := range sortedKeys(options) {
			if err := validatePattern(options[name].MatchPattern); err != nil {
				return fmt.Errorf("%s.%s: %w", field, name, err)
			}
		}
	}

	if c.Options.PayloadMatches.MatchPattern != "" {
		configured++

		if err := validatePattern(c.Options.PayloadMatches.MatchPattern); err != nil {
			return fmt.Errorf("payload_matches: %w", err)
		}
	}

	if configured == 0 {
		return ErrAccessConditionEmpty
	}

	return nil
}

// Validate checks every condition on the spec, identifying failures by the URL
// they were configured against.
func (s AccessSpec) Validate() error {
	for index, condition := range s.Conditions {
		if err := condition.Validate(); err != nil {
			return fmt.Errorf("allowed_urls[%q].conditions[%d]: %w", s.URL, index, err)
		}
	}

	return nil
}

// ValidateAccessSpecs checks the conditions on every spec in the list. It is
// the entry point for callers that accept keys and policies over an API, such
// as the Dashboard.
func ValidateAccessSpecs(specs []AccessSpec) error {
	for _, spec := range specs {
		if err := spec.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// validatePattern reports whether a match pattern can be compiled. An empty
// pattern is valid and places no constraint on the value: paired with Reverse
// it is how a condition says "this name must not be supplied at all".
func validatePattern(pattern string) error {
	if pattern == "" {
		return nil
	}

	if _, err := regexp.Compile(pattern); err != nil {
		return fmt.Errorf("cannot compile match_rx %q: %w", pattern, err)
	}

	return nil
}

// sortedKeys returns the map's keys in a deterministic order.
func sortedKeys(in map[string]apidef.StringRegexMap) []string {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}
