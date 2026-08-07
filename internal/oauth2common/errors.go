package oauth2common

import (
	"encoding/json"
	"fmt"
)

// MisconfigError is raised when exchange is configured but the audience cannot be resolved.
type MisconfigError struct {
	Reason string
}

func (e *MisconfigError) Error() string { return e.Reason }

// NoMatchingProviderError is raised when no configured provider matches the inbound iss.
type NoMatchingProviderError struct {
	Iss string
}

func (e *NoMatchingProviderError) Error() string {
	if e.Iss == "" {
		return "no token-exchange provider configured for inbound token (missing iss claim)"
	}
	return fmt.Sprintf("no token-exchange provider configured for issuer %s", e.Iss)
}

// StepUpRequiredError is raised when a jwt-bearer exchange returns
// error=interaction_required instead of a token: the user must sign in again,
// which only the caller can act on. It is an expected control-flow event, not
// a failure: the gateway relays it to the caller as an HTTP 401 with a
// WWW-Authenticate insufficient_claims challenge, and it is never cached.
// Claims is the raw challenge from the IdP (a JSON string); AuthorizationURI
// is the authorize endpoint the caller completes the step-up against, when known.
type StepUpRequiredError struct {
	Claims           string
	AuthorizationURI string
}

func (e *StepUpRequiredError) Error() string {
	return "step_up_required: the IdP returned a claims challenge (interaction_required)"
}

// DecodeClaimsChallenge extracts the `claims` challenge and optional
// authorization_uri from an interaction_required error body.
func DecodeClaimsChallenge(body []byte) (claims, authorizationURI string) {
	var p struct {
		Claims           string `json:"claims"`
		AuthorizationURI string `json:"authorization_uri"`
	}
	_ = json.Unmarshal(body, &p)
	return p.Claims, p.AuthorizationURI
}

// ExchangeFailedError represents a non-2xx IdP token-endpoint response.
type ExchangeFailedError struct {
	Status      int
	IdpError    string
	Description string
}

func (e *ExchangeFailedError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("exchange_failed: idp_error=%s: %s", e.IdpError, e.Description)
	}
	return fmt.Sprintf("exchange_failed: idp_error=%s (status %d)", e.IdpError, e.Status)
}

// MaxIdPErrorBodyBytes caps the raw snippet captured from a non-JSON IdP error body.
const MaxIdPErrorBodyBytes = 256

// DecodeIdPError parses the OAuth2 error/error_description from an IdP error response.
func DecodeIdPError(body []byte) (idpErr, description string) {
	var p struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &p); err == nil && p.Error != "" {
		return p.Error, p.ErrorDescription
	}
	snippet := string(body)
	if len(snippet) > MaxIdPErrorBodyBytes {
		snippet = snippet[:MaxIdPErrorBodyBytes] + "...(truncated)"
	}
	return "unknown", snippet
}
