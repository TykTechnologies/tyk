package errors

import "time"

// ResponseFlag represents a standardized error classification code
// following Envoy's response flags pattern for upstream errors.
type ResponseFlag string

const (
	// TLS-related errors
	TLE ResponseFlag = "TLE" // TLS certificate expired
	TLI ResponseFlag = "TLI" // TLS certificate invalid
	TLM ResponseFlag = "TLM" // TLS certificate mismatch (hostname)
	TLN ResponseFlag = "TLN" // TLS not configured
	TLH ResponseFlag = "TLH" // TLS handshake failed
	TLP ResponseFlag = "TLP" // TLS protocol error
	TLA ResponseFlag = "TLA" // TLS alert (handshake failure, version mismatch)
	TLC ResponseFlag = "TLC" // TLS certificate chain incomplete

	// Connection errors
	UCF ResponseFlag = "UCF" // Upstream connection failure
	UCT ResponseFlag = "UCT" // Upstream connection timeout
	URR ResponseFlag = "URR" // Upstream request rejected (connection reset)
	URT ResponseFlag = "URT" // Upstream request timeout
	EPI ResponseFlag = "EPI" // EPIPE - broken pipe
	CAB ResponseFlag = "CAB" // Connection aborted
	NRS ResponseFlag = "NRS" // Network reset (ENETRESET)

	// DNS errors
	DNS ResponseFlag = "DNS" // DNS resolution failure

	// Routing errors
	NRH ResponseFlag = "NRH" // No route to host
	NHU ResponseFlag = "NHU" // No healthy upstreams

	// Circuit breaker
	CBO ResponseFlag = "CBO" // Circuit breaker open

	// Client errors
	CDC ResponseFlag = "CDC" // Client disconnected

	// Upstream response errors
	URS ResponseFlag = "URS" // Upstream response status (5XX)

	// Generic errors
	UPE ResponseFlag = "UPE" // Upstream protocol error (generic fallback)

	// 4XX Gateway Error Flags (client/auth errors)
	RLT ResponseFlag = "RLT" // Rate limited (429)
	QEX ResponseFlag = "QEX" // Quota exceeded (403)
	AMF ResponseFlag = "AMF" // Auth field missing (400/401)
	AKI ResponseFlag = "AKI" // API key invalid (403)
	TKE ResponseFlag = "TKE" // Token/cert expired (403)
	TKI ResponseFlag = "TKI" // Token invalid (403)
	TCV ResponseFlag = "TCV" // Token claims invalid (401)
	EAD ResponseFlag = "EAD" // External auth denied (403)
	BTL ResponseFlag = "BTL" // Body too large (400)
	CLM ResponseFlag = "CLM" // Content-Length missing (411)
	BIV ResponseFlag = "BIV" // Body invalid (400/422)
	IHD ResponseFlag = "IHD" // Invalid header (400)
	CRQ ResponseFlag = "CRQ" // Cert required (401)
	CMM ResponseFlag = "CMM" // Cert mismatch (401)
)

// String returns the string representation of the ResponseFlag.
func (f ResponseFlag) String() string {
	return string(f)
}

// TykError ID constants for authentication errors.
// These match the error IDs defined in gateway middleware files.
const (
	// Auth key error IDs (from gateway/mw_auth_key.go)
	ErrAuthAuthorizationFieldMissing = "auth.auth_field_missing"
	ErrAuthKeyNotFound               = "auth.key_not_found"
	ErrAuthCertNotFound              = "auth.cert_not_found"
	ErrAuthKeyIsInvalid              = "auth.key_is_invalid"
	ErrAuthCertExpired               = "auth.cert_expired"
	ErrAuthCertRequired              = "auth.cert_required"
	ErrAuthCertMismatch              = "auth.cert_mismatch"

	// OAuth error IDs (from gateway/mw_oauth2_key_exists.go)
	ErrOAuthAuthorizationFieldMissing   = "oauth.auth_field_missing"
	ErrOAuthAuthorizationFieldMalformed = "oauth.auth_field_malformed"
	ErrOAuthKeyNotFound                 = "oauth.key_not_found"
	ErrOAuthClientDeleted               = "oauth.client_deleted"
)

// Error type constants for classifier functions.
const (
	// Generic error types (used by multiple auth methods)
	ErrTypeAuthFieldMissing = "auth_field_missing"

	// JWT error types
	ErrTypeClaimsInvalid           = "claims_invalid"
	ErrTypeTokenInvalid            = "token_invalid"
	ErrTypeUnexpectedSigningMethod = "unexpected_signing_method"

	// Basic auth error types
	ErrTypeHeaderMalformed     = "header_malformed"
	ErrTypeEncodingInvalid     = "encoding_invalid"
	ErrTypeValuesMalformed     = "values_malformed"
	ErrTypeBodyUsernameMissing = "body_username_missing"
	ErrTypeBodyPasswordMissing = "body_password_missing"

	// Request size error types
	ErrTypeContentLengthMissing = "content_length_missing"
	ErrTypeBodyTooLarge         = "body_too_large"

	// JSON validation error types
	ErrTypeJSONParseError         = "json_parse_error"
	ErrTypeSchemaValidationFailed = "schema_validation_failed"
)

// Error detail constants for access log output (snake_case).
const (
	// Auth details
	detailAuthFieldMissing = "auth_field_missing"
	detailAuthKeyNotFound  = "auth_key_not_found"
	detailAuthCertNotFound = "auth_cert_not_found"
	detailAuthKeyIsInvalid = "auth_key_is_invalid"
	detailAuthCertExpired  = "auth_cert_expired"
	detailAuthCertRequired = "auth_cert_required"
	detailAuthCertMismatch = "auth_cert_mismatch"

	// OAuth details
	detailOAuthFieldMissing   = "oauth_field_missing"
	detailOAuthFieldMalformed = "oauth_field_malformed"
	detailOAuthKeyNotFound    = "oauth_key_not_found"
	detailOAuthClientDeleted  = "oauth_client_deleted"

	// Rate limit details
	detailRateLimited   = "rate_limited"
	detailQuotaExceeded = "quota_exceeded"

	// JWT details
	detailJWTFieldMissing            = "jwt_field_missing"
	detailJWTClaimsInvalid           = "jwt_claims_invalid"
	detailJWTTokenInvalid            = "jwt_token_invalid"
	detailJWTUnexpectedSigningMethod = "jwt_unexpected_signing_method"

	// Basic auth details
	detailBasicAuthFieldMissing        = "basic_auth_field_missing"
	detailBasicAuthHeaderMalformed     = "basic_auth_header_malformed"
	detailBasicAuthEncodingInvalid     = "basic_auth_encoding_invalid"
	detailBasicAuthValuesMalformed     = "basic_auth_values_malformed"
	detailBasicAuthBodyUsernameMissing = "basic_auth_body_username_missing"
	detailBasicAuthBodyPasswordMissing = "basic_auth_body_password_missing"

	// Request size details
	detailContentLengthMissing = "content_length_missing"
	detailBodyTooLarge         = "body_too_large"

	// JSON validation details
	detailJSONParseError         = "json_parse_error"
	detailSchemaValidationFailed = "schema_validation_failed"
)

// ErrorClassification contains structured error information for access logs.
// Fields are only populated when applicable to the specific error type.
type ErrorClassification struct {
	// Flag is the standardized error code (e.g., "TLE", "UCF")
	Flag ResponseFlag

	// Details provides a snake_case description of the error (e.g., "tls_certificate_expired")
	Details string

	// Source identifies the component where the error originated (e.g., "ReverseProxy")
	Source string

	// Target is the upstream address that was being accessed (e.g., "api.backend.com:443")
	Target string

	// UpstreamStatus is the HTTP status code from the upstream (0 for connection errors)
	UpstreamStatus int

	// TLSCertExpiry is the expiration time of the TLS certificate (for TLS errors)
	TLSCertExpiry time.Time

	// TLSCertSubject is the subject of the TLS certificate (for TLS errors)
	TLSCertSubject string

	// CircuitBreakerState indicates the state of the circuit breaker (e.g., "OPEN", "HALF-OPEN")
	CircuitBreakerState string
}

// NewErrorClassification creates a new ErrorClassification with the given flag and details.
func NewErrorClassification(flag ResponseFlag, details string) *ErrorClassification {
	return &ErrorClassification{
		Flag:    flag,
		Details: details,
	}
}

// WithSource sets the error source and returns the classification for chaining.
func (ec *ErrorClassification) WithSource(source string) *ErrorClassification {
	ec.Source = source
	return ec
}

// WithTarget sets the upstream target and returns the classification for chaining.
func (ec *ErrorClassification) WithTarget(target string) *ErrorClassification {
	ec.Target = target
	return ec
}

// WithTLSInfo sets the TLS certificate information and returns the classification for chaining.
func (ec *ErrorClassification) WithTLSInfo(expiry time.Time, subject string) *ErrorClassification {
	ec.TLSCertExpiry = expiry
	ec.TLSCertSubject = subject
	return ec
}

// WithCircuitBreakerState sets the circuit breaker state and returns the classification for chaining.
func (ec *ErrorClassification) WithCircuitBreakerState(state string) *ErrorClassification {
	ec.CircuitBreakerState = state
	return ec
}

// WithUpstreamStatus sets the upstream HTTP status code and returns the classification for chaining.
func (ec *ErrorClassification) WithUpstreamStatus(status int) *ErrorClassification {
	ec.UpstreamStatus = status
	return ec
}
