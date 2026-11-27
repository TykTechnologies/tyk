package oas

import (
	"regexp"

	"github.com/getkin/kin-openapi/openapi3"
)

// patCodepointRewrite mirrors kin-openapi's internal translation of JSON \uXXXX
// escapes into Go regexp \x{XXXX} form.
var patCodepointRewrite = regexp.MustCompile(`\\u([0-9A-F]{4})`)

// matchAllMatcher stands in for schema patterns the RE2 engine cannot compile:
// every string is accepted, i.e. the constraint is not enforced.
type matchAllMatcher struct{}

func (matchAllMatcher) MatchString(string) bool { return true }

// ForgivingPatternCompiler compiles OAS schema "pattern" values with the
// standard library RE2 engine. OpenAPI defines "pattern" against the ECMA-262
// dialect, a superset of RE2, and frameworks such as FastAPI/Pydantic emit
// lookarounds automatically (e.g. for Decimal fields). A pattern the engine
// cannot compile is skipped with a warning instead of failing the whole
// document or every matching request.
func ForgivingPatternCompiler(expr string) (openapi3.RegexMatcher, error) {
	re, err := regexp.Compile(patCodepointRewrite.ReplaceAllString(expr, `\x{$1}`))
	if err == nil {
		return re, nil
	}

	log.WithError(err).WithField("pattern", expr).
		Warn("OAS schema pattern uses regex features unsupported by the gateway's RE2 engine; the constraint is skipped")

	return matchAllMatcher{}, nil
}
