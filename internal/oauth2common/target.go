package oauth2common

import (
	"strings"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// Target is the (audience, scopes) pair sent to the IdP.
// Nil means no exchange target could be resolved.
type Target struct {
	Audience string
	Scopes   []string
}

// SelectExchangeProvider returns the provider whose Issuers matches iss, or
// the sole provider when iss is empty and only one is configured. Dispatch is
// deterministic: exact entries are checked first across all providers, then
// regex: entries in provider order — first match wins.
func SelectExchangeProvider(providers []oas.OAuth2TokenExchangeProvider, iss string) *oas.OAuth2TokenExchangeProvider {
	if iss == "" {
		if len(providers) == 1 {
			return &providers[0]
		}
		return nil
	}
	for i := range providers {
		p := &providers[i]
		for _, allowed := range p.Issuers {
			if !strings.HasPrefix(allowed, oas.OAuth2IssuerRegexPrefix) && allowed == iss {
				return p
			}
		}
	}
	for i := range providers {
		p := &providers[i]
		for _, allowed := range p.Issuers {
			pattern, isRegex := strings.CutPrefix(allowed, oas.OAuth2IssuerRegexPrefix)
			if !isRegex {
				continue
			}
			// Load-time validation guarantees the pattern compiles; a
			// non-compiling entry here simply never matches.
			if re, err := compiledIssuerRegex(pattern); err == nil && re.MatchString(iss) {
				return p
			}
		}
	}
	return nil
}

// MergeTargetForProvider merges the per-op exchange override with the provider
// defaultTarget (most-specific wins). Returns nil when no audience can be resolved.
func MergeTargetForProvider(ex *oas.OAuth2Exchange, provider *oas.OAuth2TokenExchangeProvider, inferredScopes []string) *Target {
	t := &Target{}
	if ex != nil {
		t.Audience = ex.Audience
		t.Scopes = append([]string(nil), ex.Scopes...)
		if len(t.Scopes) == 0 && ex.InfersScopesFromSecurity() && len(inferredScopes) > 0 {
			t.Scopes = append([]string(nil), inferredScopes...)
		}
	}
	if (t.Audience == "" || len(t.Scopes) == 0) && provider != nil && provider.DefaultTarget != nil {
		if t.Audience == "" {
			t.Audience = provider.DefaultTarget.Audience
		}
		if len(t.Scopes) == 0 {
			t.Scopes = append([]string(nil), provider.DefaultTarget.Scopes...)
		}
	}
	if t.Audience == "" {
		return nil
	}
	return t
}
