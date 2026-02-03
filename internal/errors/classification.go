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
)

// String returns the string representation of the ResponseFlag.
func (f ResponseFlag) String() string {
	return string(f)
}

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
