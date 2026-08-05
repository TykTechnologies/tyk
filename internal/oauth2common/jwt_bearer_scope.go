package oauth2common

import "strings"

// RenderJWTBearerScope renders a resolved target into the RFC 7523 jwt-bearer
// `scope` value: each scope that does not already contain "/" is prefixed with
// "audience/"; a scope containing "/" is already fully qualified and passes
// verbatim. Nothing is ever invented — no scopes yields an empty string (no
// scope parameter), regardless of the audience.
func RenderJWTBearerScope(audience string, scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if audience != "" && !strings.Contains(s, "/") {
			s = audience + "/" + s
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}
