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

// ActorNotAuthorizedError is raised when actorToken.requireMayAct is set and
// the inbound subject token's may_act claim (RFC 8693 §4.4) does not authorize
// the configured actor. Rendered as HTTP 403 with no IdP call.
type ActorNotAuthorizedError struct {
	Reason string
}

func (e *ActorNotAuthorizedError) Error() string { return e.Reason }

// MissingActorTokenError is raised when actorToken.source=header is required
// but the configured header is absent. Rendered as HTTP 401 with an RFC 6750
// invalid_token Bearer challenge; no fallback to impersonation.
type MissingActorTokenError struct {
	Header string
}

func (e *MissingActorTokenError) Error() string {
	return fmt.Sprintf("missing actor token header %s", e.Header)
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
