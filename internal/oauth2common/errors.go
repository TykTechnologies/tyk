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
