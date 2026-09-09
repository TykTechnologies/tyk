// Package oauth2common holds the pure-function helpers used by the
// gateway-side oauth2 security scheme to read and reason about JWT
// claims without depending on gateway concrete types.
//
// The package depends only on apidef/oas, the JWT library, and the
// standard library. The dependency arrow flows one direction:
// gateway/ depends on oauth2common, never the reverse.
package oauth2common

import (
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

// ParseUnverifiedClaims parses a JWT *without* verifying its signature
// or claims, returning the claim set as a map. Used for log/audit field
// extraction, cache-key derivation, and scope-check field reads. Never
// returns the token bytes.
//
// Security model: callers must ensure the token has been authenticated
// upstream (e.g. by the JWT or external OAuth introspection middleware).
// This function intentionally does not verify the JWT signature — the
// new oauth2 scheme relies on the existing authentication chain for
// token trust and only consults claim values here. Adding signature
// verification at this layer would require key material this layer does
// not own and would duplicate the upstream verifier.
func ParseUnverifiedClaims(token string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claim type %T", parsed.Claims)
	}
	return claims, nil
}

// StringClaim returns the string value at `key` or "" when the claim is
// absent or has a non-string shape.
func StringClaim(claims jwt.MapClaims, key string) string {
	if claims == nil {
		return ""
	}
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// StringFromAny returns the string value of v or "" when v isn't a
// string.
func StringFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
