package oauth2common

import "github.com/TykTechnologies/tyk/apidef/oas"

// Target is the (audience, scopes) pair sent to the IdP.
// Nil means no exchange target could be resolved.
type Target struct {
	Audience string
	Scopes   []string
}

// SelectExchangeProvider returns the provider whose Issuers contains iss,
// or the sole provider when iss is empty and only one is configured.
func SelectExchangeProvider(providers []oas.OAuth2TokenExchangeProvider, iss string) *oas.OAuth2TokenExchangeProvider {
	if iss != "" {
		for i := range providers {
			p := &providers[i]
			for _, allowed := range p.Issuers {
				if allowed == iss {
					return p
				}
			}
		}
		return nil
	}
	if len(providers) == 1 {
		return &providers[0]
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
