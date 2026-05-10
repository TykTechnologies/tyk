package oauth2common

import "github.com/golang-jwt/jwt/v4"

// ParseUnverifiedClaims parses a JWT *without* verifying its signature
// or claims, returning the claim set as a map. Used for log/audit field
// extraction and for cache-key derivation. Never returns the token
// bytes.
func ParseUnverifiedClaims(token string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, _ := parsed.Claims.(jwt.MapClaims)
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
