package httputil

import (
	"fmt"
	"strings"

	"github.com/TykTechnologies/tyk/internal/maps"
	"github.com/TykTechnologies/tyk/regexp"
)

// ParamSchema holds the OAS schema information for a single path parameter.
type ParamSchema struct {
	// Pattern is the explicit regex pattern from the OAS schema (schema.pattern).
	Pattern string
	// Type is the OAS type (e.g., "string", "number", "integer", "boolean").
	Type string
}

// schemaTypePatterns maps OAS schema types to default regex patterns.
var schemaTypePatterns = map[string]string{
	"string":  `[^/]+`,
	"number":  `[0-9]*\.?[0-9]+`,
	"integer": `[0-9]+`,
	"boolean": `true|false`,
}

// SchemaTypeToRegex returns a regex pattern for the given OAS schema type.
// If the type is unknown or empty, it returns a generic pattern matching
// any non-slash characters.
func SchemaTypeToRegex(schemaType string) string {
	if p, ok := schemaTypePatterns[schemaType]; ok {
		return p
	}
	return `[^/]+`
}

// ParamSchemaToRegex returns a regex pattern for a path parameter.
// If an explicit pattern is set, it is used (stripped of leading ^ and trailing $).
// Otherwise, the type-based default is used.
func ParamSchemaToRegex(ps ParamSchema) string {
	if ps.Pattern != "" {
		p := strings.TrimPrefix(ps.Pattern, "^")
		p = strings.TrimSuffix(p, "$")
		return p
	}
	return SchemaTypeToRegex(ps.Type)
}

// subSpecRegexpCache caches compiled sub-spec regex patterns.
var subSpecRegexpCache = maps.NewStringMap()

// PrepareSubSpecRegexp replaces mux-style path parameters with their
// schema-derived regex patterns instead of the generic ([^/]+).
// paramSchemas maps parameter names to their OAS schema info.
// prefix and suffix control anchoring (^ and $), same as PreparePathRegexp.
func PrepareSubSpecRegexp(pattern string, paramSchemas map[string]ParamSchema, prefix bool, suffix bool) string {
	key := fmt.Sprintf("sub:%s:%v:%v", pattern, prefix, suffix)
	for name, ps := range paramSchemas {
		key += fmt.Sprintf(":%s=%s/%s", name, ps.Type, ps.Pattern)
	}

	if val, ok := subSpecRegexpCache.Get(key); ok {
		return val
	}

	result := pattern
	for name, ps := range paramSchemas {
		placeholder := "{" + name + "}"
		paramRegex := ParamSchemaToRegex(ps)
		result = strings.ReplaceAll(result, placeholder, "("+paramRegex+")")
	}

	// Replace any remaining unmatched mux parameters with generic pattern.
	if IsMuxTemplate(result) {
		result = apiLangIDsRegex.ReplaceAllString(result, `([^/]+)`)
	}

	if prefix && strings.HasPrefix(result, "/") {
		result = "^" + result
	}

	if suffix && !strings.HasSuffix(result, "$") {
		result = result + "$"
	}

	subSpecRegexpCache.Set(key, result)
	return result
}

// CompileSubSpec compiles a sub-spec regex for a path with the given parameter schemas.
// Returns nil if the path has no mux-template parameters or if compilation fails.
func CompileSubSpec(path string, paramSchemas map[string]ParamSchema, prefix bool, suffix bool) *regexp.Regexp {
	if !IsMuxTemplate(path) {
		return nil
	}
	if len(paramSchemas) == 0 {
		return nil
	}

	pattern := PrepareSubSpecRegexp(path, paramSchemas, prefix, suffix)
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return compiled
}
