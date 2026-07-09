package oauth2common

import (
	"regexp"
	"sync"
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
	// LoadOrStore atomically resolves a concurrent first-miss: every caller
	// returns the one cached regexp instead of racing Load/Store as a pair.
	actual, _ := issuerRegexCache.LoadOrStore(pattern, re)
	return actual.(*regexp.Regexp), nil
}
