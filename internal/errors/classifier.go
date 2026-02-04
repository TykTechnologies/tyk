package errors

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"strings"
	"syscall"
)

const (
	sourceReverseProxy = "ReverseProxy"
	sourceUpstream     = "Upstream"
)

// ClassifyUpstreamError analyzes an error from an upstream request and returns
// a structured ErrorClassification. Returns nil if err is nil.
//
// The classification follows this priority order:
// 1. Unwrap url.Error to get underlying error
// 2. TLS errors (x509.*, tls.*)
// 3. Connection errors (syscall.ECONNREFUSED, ECONNRESET, etc.)
// 4. DNS errors (net.DNSError)
// 5. Timeout errors (net.Error.Timeout(), context.DeadlineExceeded)
// 6. Context errors (context.Canceled)
// 7. String-based fallback detection
// 8. Generic fallback (UPE)
func ClassifyUpstreamError(err error, target string) *ErrorClassification {
	if err == nil {
		return nil
	}

	// Unwrap url.Error to get the underlying error
	var urlErr *url.Error
	if As(err, &urlErr) {
		err = urlErr.Err
	}

	// Unwrap net.OpError to get the underlying error
	var opErr *net.OpError
	if As(err, &opErr) {
		err = opErr.Err
	}

	// Check for TLS errors
	if ec := classifyTLSError(err, target); ec != nil {
		return ec
	}

	// Check for syscall/connection errors
	if ec := classifySyscallError(err, target); ec != nil {
		return ec
	}

	// Check for DNS errors
	if ec := classifyDNSError(err, target); ec != nil {
		return ec
	}

	// Check for context errors BEFORE net.Error timeout check
	// (context.DeadlineExceeded implements net.Error with Timeout() = true)
	if Is(err, context.DeadlineExceeded) {
		return NewErrorClassification(URT, "context_deadline_exceeded").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	if Is(err, context.Canceled) {
		return NewErrorClassification(CDC, "client_disconnected").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// Check for timeout errors (net.Error interface)
	var netErr net.Error
	if As(err, &netErr) {
		return NewErrorClassification(URT, "request_timeout").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// String-based fallback detection
	if ec := classifyByErrorString(err, target); ec != nil {
		return ec
	}

	// Generic fallback
	return NewErrorClassification(UPE, "upstream_error").
		WithSource(sourceReverseProxy).
		WithTarget(target)
}

// classifyTLSError checks for TLS-related errors and returns appropriate classification.
func classifyTLSError(err error, target string) *ErrorClassification {
	// Check for certificate invalid error
	var certInvalidErr x509.CertificateInvalidError
	if As(err, &certInvalidErr) {
		switch certInvalidErr.Reason {
		case x509.Expired:
			ec := NewErrorClassification(TLE, "tls_certificate_expired").
				WithSource(sourceReverseProxy).
				WithTarget(target)
			if certInvalidErr.Cert != nil {
				ec.WithTLSInfo(certInvalidErr.Cert.NotAfter, certInvalidErr.Cert.Subject.String())
			}
			return ec
		default:
			return NewErrorClassification(TLI, "tls_certificate_invalid").
				WithSource(sourceReverseProxy).
				WithTarget(target)
		}
	}

	// Check for hostname mismatch
	var hostnameErr x509.HostnameError
	if As(err, &hostnameErr) {
		return NewErrorClassification(TLM, "tls_hostname_mismatch").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// Check for unknown authority
	var unknownAuthErr x509.UnknownAuthorityError
	if As(err, &unknownAuthErr) {
		return NewErrorClassification(TLI, "tls_unknown_authority").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// Check for TLS record header error
	var recordHeaderErr tls.RecordHeaderError
	if As(err, &recordHeaderErr) {
		return NewErrorClassification(TLP, "tls_protocol_error").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// Check for TLS alert errors (handshake failures, unsupported versions)
	var alertErr tls.AlertError
	if As(err, &alertErr) {
		return NewErrorClassification(TLA, "tls_alert_error").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// Check for certificate chain errors (incomplete chain)
	var certChainErr x509.SystemRootsError
	if As(err, &certChainErr) {
		return NewErrorClassification(TLC, "tls_certificate_chain_incomplete").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	return nil
}

// classifySyscallError checks for syscall-level connection errors.
func classifySyscallError(err error, target string) *ErrorClassification {
	// Handle both direct syscall.Errno and wrapped errors
	var errno syscall.Errno
	if As(err, &errno) {
		return classifyErrno(errno, target)
	}

	return nil
}

// classifyErrno maps syscall.Errno values to error classifications.
func classifyErrno(errno syscall.Errno, target string) *ErrorClassification {
	switch errno {
	case syscall.ECONNREFUSED:
		return NewErrorClassification(UCF, "connection_refused").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	case syscall.ETIMEDOUT:
		return NewErrorClassification(UCT, "connection_timeout").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	case syscall.ECONNRESET:
		return NewErrorClassification(URR, "connection_reset").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	case syscall.ENETUNREACH:
		return NewErrorClassification(NRH, "network_unreachable").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	case syscall.EHOSTUNREACH:
		return NewErrorClassification(NRH, "host_unreachable").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	case syscall.EPIPE:
		return NewErrorClassification(EPI, "broken_pipe").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	case syscall.ECONNABORTED:
		return NewErrorClassification(CAB, "connection_aborted").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	case syscall.ENETRESET:
		return NewErrorClassification(NRS, "network_reset").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}
	return nil
}

// classifyDNSError checks for DNS resolution errors.
func classifyDNSError(err error, target string) *ErrorClassification {
	var dnsErr *net.DNSError
	if As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return NewErrorClassification(DNS, "dns_not_found").
				WithSource(sourceReverseProxy).
				WithTarget(target)
		}
		if dnsErr.IsTimeout {
			return NewErrorClassification(DNS, "dns_timeout").
				WithSource(sourceReverseProxy).
				WithTarget(target)
		}
		return NewErrorClassification(DNS, "dns_resolution_failed").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}
	return nil
}

// classifyByErrorString performs string-based pattern matching as a fallback.
func classifyByErrorString(err error, target string) *ErrorClassification {
	errStr := strings.ToLower(err.Error())

	// Check for timeout patterns
	if strings.Contains(errStr, "timeout awaiting response headers") {
		return NewErrorClassification(URT, "response_headers_timeout").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// Check for DNS patterns
	if strings.Contains(errStr, "no such host") {
		return NewErrorClassification(DNS, "dns_not_found").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// Check for connection patterns
	if strings.Contains(errStr, "connection refused") {
		return NewErrorClassification(UCF, "connection_refused").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	if strings.Contains(errStr, "connection reset") {
		return NewErrorClassification(URR, "connection_reset").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	if strings.Contains(errStr, "broken pipe") {
		return NewErrorClassification(EPI, "broken_pipe").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// TLS protocol/version errors (checked first - more specific)
	// Error: "remote error: tls: protocol version not supported"
	// Note: Go's internal tls.alert type cannot be matched with errors.As(tls.AlertError)
	// so we fall back to string matching for these TLS errors
	if strings.Contains(errStr, "protocol version not supported") ||
		strings.Contains(errStr, "no supported versions") {
		return NewErrorClassification(TLP, "tls_protocol_version_error").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// TLS handshake failures
	// Error: "remote error: tls: handshake failure" or "tls: internal error"
	if strings.Contains(errStr, "handshake failure") ||
		strings.Contains(errStr, "tls: internal error") ||
		strings.Contains(errStr, "bad certificate") ||
		strings.Contains(errStr, "certificate required") ||
		strings.Contains(errStr, "first record does not look like a tls handshake") {
		return NewErrorClassification(TLH, "tls_handshake_failure").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	// Generic TLS remote errors (fallback for other TLS alerts)
	// Matches: "remote error: tls: ..." patterns not caught above
	if strings.Contains(errStr, "remote error: tls:") {
		return NewErrorClassification(TLA, "tls_alert_received").
			WithSource(sourceReverseProxy).
			WithTarget(target)
	}

	return nil
}

// ClassifyCircuitBreakerError creates an error classification for circuit breaker events.
func ClassifyCircuitBreakerError(target, state string) *ErrorClassification {
	return NewErrorClassification(CBO, "circuit_breaker_open").
		WithSource(sourceReverseProxy).
		WithTarget(target).
		WithCircuitBreakerState(state)
}

// ClassifyNoHealthyUpstreamsError creates an error classification when no healthy upstreams are available.
func ClassifyNoHealthyUpstreamsError(target string) *ErrorClassification {
	return NewErrorClassification(NHU, "no_healthy_upstreams").
		WithSource(sourceReverseProxy).
		WithTarget(target)
}

// ClassifyUpstreamResponse creates an error classification for 5XX upstream responses.
// Unlike connection errors, the upstream received the request and responded with an error.
func ClassifyUpstreamResponse(statusCode int, target string) *ErrorClassification {
	return NewErrorClassification(URS, "upstream_response_5xx").
		WithSource(sourceUpstream).
		WithTarget(target).
		WithUpstreamStatus(statusCode)
}
