// Package naming implements the MCP tool-naming algorithm specified in
// RFC-API-TO-MCP-V7 §9. It derives deterministic, MCP-compliant tool names
// of the form `<sanitised-source-slug>__<sanitised-op-name>` from OpenAPI
// operations.
//
// The two-character `__` sequence is reserved as the separator between the
// source slug and the operation name; runs of underscores inside either
// token are collapsed to a single `_`, so `__` only ever appears as the
// separator and a single split on the first `__` losslessly recovers
// (source-slug, op-name).
package naming

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Separator is the literal two-character delimiter between the sanitised
// source slug and the sanitised operation name in a tool name.
const Separator = "__"

var (
	// reNonAllowed matches any character outside the MCP tool-name allowed
	// alphabet `[a-zA-Z0-9_-]`. Such characters are replaced with `_`.
	reNonAllowed = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

	// reUnderscoreRun matches a run of one or more underscores; used to
	// collapse runs to a single `_` so the `__` separator is unambiguous.
	reUnderscoreRun = regexp.MustCompile(`_+`)

	// rePathSegment matches any run of non-alphanumeric characters within a
	// non-templated path segment; used by EncodePath to normalise segments.
	rePathSegment = regexp.MustCompile(`[^a-zA-Z0-9]+`)
)

// CollisionError is returned by DeriveOpName when a derived candidate
// op-name has already been used within the same source. The message names
// both colliding inputs so the operator can resolve it (typically by
// adding an `operationId` to one of them).
type CollisionError struct {
	// Candidate is the sanitised op-name that already exists in `used`.
	Candidate string
	// Existing identifies the previously-registered operation that produced
	// the candidate (free-form, e.g. "GET /v1/users").
	Existing string
	// Incoming identifies the operation currently being derived (free-form,
	// e.g. "GET /v1_users").
	Incoming string
}

// Error implements the error interface.
func (e *CollisionError) Error() string {
	return fmt.Sprintf(
		"mcp naming: tool-name collision on %q between %q and %q; add an `operationId` to one",
		e.Candidate, e.Existing, e.Incoming,
	)
}

// ErrCollision is a sentinel that callers can match with errors.Is.
var ErrCollision = errors.New("mcp naming: tool-name collision")

// Is reports whether target is ErrCollision so errors.Is works for the
// sentinel even when a *CollisionError carries the structured details.
func (e *CollisionError) Is(target error) bool {
	return target == ErrCollision
}

// Sanitise enforces the MCP tool-name alphabet `[a-zA-Z0-9_-]+` on s by
// replacing disallowed characters with `_`, lowercasing the result,
// collapsing runs of `_` to a single `_`, and trimming leading/trailing
// `_`. It is used for both the source slug and the operation name (this
// is the `sanitise_op` function from RFC §9.2).
func Sanitise(s string) string {
	cleaned := strings.ToLower(reNonAllowed.ReplaceAllString(s, "_"))
	cleaned = reUnderscoreRun.ReplaceAllString(cleaned, "_")
	return strings.Trim(cleaned, "_")
}

// EncodePath converts an OpenAPI path template into a flat, lowercase
// op-name fragment per RFC §9.2: leading/trailing `/` are stripped, the
// path is split on `/`, each `{var}` segment becomes `var`, every other
// segment has runs of non-alphanumeric characters replaced with `_`, the
// segments are joined with `_`, runs of `_` are collapsed, and the
// result is trimmed of leading/trailing `_` and lowercased.
func EncodePath(path string) string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return ""
	}
	segments := strings.Split(trimmed, "/")
	parts := make([]string, 0, len(segments))
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			parts = append(parts, seg[1:len(seg)-1])
			continue
		}
		parts = append(parts, rePathSegment.ReplaceAllString(seg, "_"))
	}
	// Filter out empty parts produced by all-symbol segments collapsing.
	nonEmpty := parts[:0]
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	joined := strings.ToLower(strings.Join(nonEmpty, "_"))
	joined = reUnderscoreRun.ReplaceAllString(joined, "_")
	return strings.Trim(joined, "_")
}

// DeriveOpName returns the op-name for an OpenAPI operation, registering
// it in `used` so subsequent calls within the same source can detect
// collisions. If `operationID` is non-empty the candidate is
// Sanitise(operationID); otherwise it is `<lower-method>_<EncodePath(path)>`.
// If the candidate is already present in `used`, a *CollisionError is
// returned (which also matches ErrCollision via errors.Is) and `used` is
// left unchanged. On success the candidate is inserted into `used`.
//
// `used` must be non-nil.
func DeriveOpName(method, path, operationID string, used map[string]struct{}) (string, error) {
	var candidate string
	if operationID != "" {
		candidate = Sanitise(operationID)
	} else {
		candidate = strings.ToLower(method) + "_" + EncodePath(path)
		candidate = strings.Trim(reUnderscoreRun.ReplaceAllString(candidate, "_"), "_")
	}

	incoming := fmt.Sprintf("%s %s", strings.ToUpper(method), path)
	if _, exists := used[candidate]; exists {
		return "", &CollisionError{
			Candidate: candidate,
			Existing:  fmt.Sprintf("previously-registered operation producing %q", candidate),
			Incoming:  incoming,
		}
	}
	used[candidate] = struct{}{}
	return candidate, nil
}

// BuildToolName assembles the full MCP tool name from a source slug and
// op-name per RFC §9.1: `Sanitise(sourceSlug) + "__" + Sanitise(opName)`.
// Both inputs are sanitised here so callers may pass raw strings.
func BuildToolName(sourceSlug, opName string) string {
	return Sanitise(sourceSlug) + Separator + Sanitise(opName)
}

// SplitToolName splits a tool name on the first `__` separator and
// returns (sourceSlug, opName, true). If the input does not contain the
// separator, it returns ("", "", false).
func SplitToolName(toolName string) (string, string, bool) {
	i := strings.Index(toolName, Separator)
	if i < 0 {
		return "", "", false
	}
	return toolName[:i], toolName[i+len(Separator):], true
}
