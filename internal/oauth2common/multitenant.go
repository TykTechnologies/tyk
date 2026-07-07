package oauth2common

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v4"
)

// issuerRegexCache caches compiled regex: issuer entries by pattern. Entries
// are validated at config load, so a cache miss compiles at most once per
// pattern for the process lifetime.
var issuerRegexCache sync.Map

// compiledIssuerRegex returns the compiled regexp for a regex:-prefixed issuer
// entry (prefix already stripped), caching by pattern.
func compiledIssuerRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := issuerRegexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	issuerRegexCache.Store(pattern, re)
	return re, nil
}

// claimPlaceholderRE matches a {claim.<name>} placeholder in a tokenEndpoint.
var claimPlaceholderRE = regexp.MustCompile(`\{claim\.([A-Za-z0-9_-]+)\}`)

// endpointClaimValueRE is the charset guard for a substituted claim value:
// URL-safe unreserved characters only, in particular no "/" — the value must
// stay a single path segment.
var endpointClaimValueRE = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// ResolveTokenEndpoint substitutes every {claim.<name>} placeholder in the
// provider tokenEndpoint with the inbound token's claim value. A missing
// claim, a non-string value, or a value failing the charset guard rejects the
// request before any IdP call.
func ResolveTokenEndpoint(endpoint string, claims jwt.MapClaims) (string, error) {
	matches := claimPlaceholderRE.FindAllStringSubmatch(endpoint, -1)
	if len(matches) == 0 {
		return endpoint, nil
	}
	resolved := endpoint
	for _, m := range matches {
		placeholder, name := m[0], m[1]
		raw, ok := claims[name]
		if !ok {
			return "", fmt.Errorf("tokenEndpoint placeholder %s: inbound token has no %q claim", placeholder, name)
		}
		value, ok := raw.(string)
		// "." and ".." pass the charset but are dot-segments — path
		// navigation, not a path segment value.
		if !ok || !endpointClaimValueRE.MatchString(value) || value == "." || value == ".." {
			return "", fmt.Errorf("tokenEndpoint placeholder %s: claim value is not a single URL-safe path segment", placeholder)
		}
		resolved = strings.ReplaceAll(resolved, placeholder, value)
	}
	return resolved, nil
}
