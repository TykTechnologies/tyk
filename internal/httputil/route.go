package httputil

import (
	"strings"
)

// RouteRegexString will convert a mux route url to a regular expression string.
//
// The `{id}` named parameters will be converted to `.*`.
// Extended `{id:regex}` parameters will use the defined regex.
// The returned regex is encapsulated with `^` (start) and `$` (end).
func RouteRegexString(pattern string) string {
	var builder strings.Builder
	start := 0

	builder.WriteString("^")
	for start < len(pattern) {
		open := strings.Index(pattern[start:], "{")
		if open == -1 {
			builder.WriteString(pattern[start:])
			break
		}
		open += start
		builder.WriteString(pattern[start:open])
		end := strings.Index(pattern[open:], "}")
		if end == -1 {
			builder.WriteString(pattern[open:])
			break
		}
		end += open
		tag := pattern[open+1 : end]

		colon := strings.Index(tag, ":")
		if colon == -1 {
			builder.WriteString(".*")
		} else {
			builder.WriteString(tag[colon+1:])
		}
		start = end + 1
	}
	builder.WriteString("$")

	return builder.String()
}
