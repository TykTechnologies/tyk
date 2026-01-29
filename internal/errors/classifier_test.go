package errors

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyUpstreamError_Nil(t *testing.T) {
	result := ClassifyUpstreamError(nil, "api.backend.com:443")
	assert.Nil(t, result)
}

func TestClassifyUpstreamError_TLSErrors(t *testing.T) {
	target := "api.backend.com:443"

	tests := []struct {
		name           string
		err            error
		expectedFlag   ResponseFlag
		expectedDetail string
	}{
		{
			name: "certificate expired",
			err: x509.CertificateInvalidError{
				Cert:   &x509.Certificate{NotAfter: time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)},
				Reason: x509.Expired,
			},
			expectedFlag:   TLE,
			expectedDetail: "tls_certificate_expired",
		},
		{
			name: "certificate invalid - incompatible usage",
			err: x509.CertificateInvalidError{
				Cert:   &x509.Certificate{},
				Reason: x509.IncompatibleUsage,
			},
			expectedFlag:   TLI,
			expectedDetail: "tls_certificate_invalid",
		},
		{
			name: "certificate invalid - CA not authorized",
			err: x509.CertificateInvalidError{
				Cert:   &x509.Certificate{},
				Reason: x509.CANotAuthorizedForThisName,
			},
			expectedFlag:   TLI,
			expectedDetail: "tls_certificate_invalid",
		},
		{
			name:           "hostname mismatch",
			err:            x509.HostnameError{Certificate: &x509.Certificate{}, Host: "wrong.host.com"},
			expectedFlag:   TLM,
			expectedDetail: "tls_hostname_mismatch",
		},
		{
			name:           "unknown authority",
			err:            x509.UnknownAuthorityError{},
			expectedFlag:   TLI,
			expectedDetail: "tls_unknown_authority",
		},
		{
			name:           "TLS record header error",
			err:            tls.RecordHeaderError{Msg: "bad record"},
			expectedFlag:   TLP,
			expectedDetail: "tls_protocol_error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyUpstreamError(tc.err, target)
			require.NotNil(t, result)
			assert.Equal(t, tc.expectedFlag, result.Flag)
			assert.Equal(t, tc.expectedDetail, result.Details)
			assert.Equal(t, "ReverseProxy", result.Source)
			assert.Equal(t, target, result.Target)
		})
	}
}

func TestClassifyUpstreamError_ConnectionErrors(t *testing.T) {
	target := "api.backend.com:443"

	tests := []struct {
		name           string
		err            error
		expectedFlag   ResponseFlag
		expectedDetail string
	}{
		{
			name:           "connection refused",
			err:            syscall.ECONNREFUSED,
			expectedFlag:   UCF,
			expectedDetail: "connection_refused",
		},
		{
			name:           "connection timed out",
			err:            syscall.ETIMEDOUT,
			expectedFlag:   UCT,
			expectedDetail: "connection_timeout",
		},
		{
			name:           "connection reset",
			err:            syscall.ECONNRESET,
			expectedFlag:   URR,
			expectedDetail: "connection_reset",
		},
		{
			name:           "network unreachable",
			err:            syscall.ENETUNREACH,
			expectedFlag:   NRH,
			expectedDetail: "network_unreachable",
		},
		{
			name:           "host unreachable",
			err:            syscall.EHOSTUNREACH,
			expectedFlag:   NRH,
			expectedDetail: "host_unreachable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyUpstreamError(tc.err, target)
			require.NotNil(t, result)
			assert.Equal(t, tc.expectedFlag, result.Flag)
			assert.Equal(t, tc.expectedDetail, result.Details)
		})
	}
}

func TestClassifyUpstreamError_WrappedErrors(t *testing.T) {
	target := "api.backend.com:443"

	t.Run("url.Error wrapping syscall error", func(t *testing.T) {
		err := &url.Error{
			Op:  "Get",
			URL: "https://api.backend.com/test",
			Err: syscall.ECONNREFUSED,
		}
		result := ClassifyUpstreamError(err, target)
		require.NotNil(t, result)
		assert.Equal(t, UCF, result.Flag)
		assert.Equal(t, "connection_refused", result.Details)
	})

	t.Run("url.Error wrapping net.OpError", func(t *testing.T) {
		err := &url.Error{
			Op:  "Get",
			URL: "https://api.backend.com/test",
			Err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: syscall.ECONNREFUSED,
			},
		}
		result := ClassifyUpstreamError(err, target)
		require.NotNil(t, result)
		assert.Equal(t, UCF, result.Flag)
	})

	t.Run("net.OpError wrapping syscall error", func(t *testing.T) {
		err := &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: syscall.ETIMEDOUT,
		}
		result := ClassifyUpstreamError(err, target)
		require.NotNil(t, result)
		assert.Equal(t, UCT, result.Flag)
	})
}

func TestClassifyUpstreamError_DNSErrors(t *testing.T) {
	target := "unknown.host.com:443"

	tests := []struct {
		name           string
		err            error
		expectedFlag   ResponseFlag
		expectedDetail string
	}{
		{
			name: "DNS not found",
			err: &net.DNSError{
				Err:        "no such host",
				Name:       "unknown.host.com",
				IsNotFound: true,
			},
			expectedFlag:   DNS,
			expectedDetail: "dns_not_found",
		},
		{
			name: "DNS timeout",
			err: &net.DNSError{
				Err:       "lookup timed out",
				Name:      "slow.dns.com",
				IsTimeout: true,
			},
			expectedFlag:   DNS,
			expectedDetail: "dns_timeout",
		},
		{
			name: "DNS generic error",
			err: &net.DNSError{
				Err:  "server misbehaving",
				Name: "bad.dns.com",
			},
			expectedFlag:   DNS,
			expectedDetail: "dns_resolution_failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyUpstreamError(tc.err, target)
			require.NotNil(t, result)
			assert.Equal(t, tc.expectedFlag, result.Flag)
			assert.Equal(t, tc.expectedDetail, result.Details)
		})
	}
}

func TestClassifyUpstreamError_TimeoutErrors(t *testing.T) {
	target := "slow.backend.com:443"

	t.Run("net.Error timeout", func(t *testing.T) {
		err := &timeoutError{timeout: true}
		result := ClassifyUpstreamError(err, target)
		require.NotNil(t, result)
		assert.Equal(t, URT, result.Flag)
		assert.Equal(t, "request_timeout", result.Details)
	})

	t.Run("context deadline exceeded", func(t *testing.T) {
		result := ClassifyUpstreamError(context.DeadlineExceeded, target)
		require.NotNil(t, result)
		assert.Equal(t, URT, result.Flag)
		assert.Equal(t, "context_deadline_exceeded", result.Details)
	})
}

func TestClassifyUpstreamError_ContextErrors(t *testing.T) {
	target := "api.backend.com:443"

	t.Run("context canceled", func(t *testing.T) {
		result := ClassifyUpstreamError(context.Canceled, target)
		require.NotNil(t, result)
		assert.Equal(t, CDC, result.Flag)
		assert.Equal(t, "client_disconnected", result.Details)
	})
}

func TestClassifyUpstreamError_StringFallback(t *testing.T) {
	target := "api.backend.com:443"

	tests := []struct {
		name           string
		err            error
		expectedFlag   ResponseFlag
		expectedDetail string
	}{
		{
			name:           "timeout string in error",
			err:            errors.New("timeout awaiting response headers"),
			expectedFlag:   URT,
			expectedDetail: "response_headers_timeout",
		},
		// Note: "context deadline exceeded" and "context canceled" string-based checks were removed
		// because they are redundant - these errors are already handled by type-based checks
		// using errors.Is(err, context.DeadlineExceeded) and errors.Is(err, context.Canceled)
		// at the start of ClassifyUpstreamError. In practice, context errors are always passed
		// as the actual context sentinel errors, not as plain string errors.
		{
			name:           "no such host string in error",
			err:            errors.New("dial tcp: lookup unknown.host: no such host"),
			expectedFlag:   DNS,
			expectedDetail: "dns_not_found",
		},
		{
			name:           "connection refused string in error",
			err:            errors.New("dial tcp 192.168.1.1:443: connect: connection refused"),
			expectedFlag:   UCF,
			expectedDetail: "connection_refused",
		},
		{
			name:           "connection reset string in error",
			err:            errors.New("read tcp: connection reset by peer"),
			expectedFlag:   URR,
			expectedDetail: "connection_reset",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyUpstreamError(tc.err, target)
			require.NotNil(t, result)
			assert.Equal(t, tc.expectedFlag, result.Flag)
			assert.Equal(t, tc.expectedDetail, result.Details)
		})
	}
}

func TestClassifyUpstreamError_GenericFallback(t *testing.T) {
	target := "api.backend.com:443"

	t.Run("unknown error falls back to UPE", func(t *testing.T) {
		err := errors.New("some completely unknown error")
		result := ClassifyUpstreamError(err, target)
		require.NotNil(t, result)
		assert.Equal(t, UPE, result.Flag)
		assert.Equal(t, "upstream_error", result.Details)
	})
}

func TestClassifyCircuitBreakerError(t *testing.T) {
	t.Run("circuit breaker open", func(t *testing.T) {
		result := ClassifyCircuitBreakerError("api.backend.com:443", "OPEN")
		require.NotNil(t, result)
		assert.Equal(t, CBO, result.Flag)
		assert.Equal(t, "circuit_breaker_open", result.Details)
		assert.Equal(t, "ReverseProxy", result.Source)
		assert.Equal(t, "api.backend.com:443", result.Target)
		assert.Equal(t, "OPEN", result.CircuitBreakerState)
	})

	t.Run("circuit breaker half-open", func(t *testing.T) {
		result := ClassifyCircuitBreakerError("api.backend.com:443", "HALF-OPEN")
		require.NotNil(t, result)
		assert.Equal(t, "HALF-OPEN", result.CircuitBreakerState)
	})
}

func TestClassifyNoHealthyUpstreamsError(t *testing.T) {
	result := ClassifyNoHealthyUpstreamsError("api.backend.com:443")
	require.NotNil(t, result)
	assert.Equal(t, NHU, result.Flag)
	assert.Equal(t, "no_healthy_upstreams", result.Details)
	assert.Equal(t, "ReverseProxy", result.Source)
	assert.Equal(t, "api.backend.com:443", result.Target)
}

func TestClassifyUpstreamResponse(t *testing.T) {
	target := "api.backend.com:443"

	tests := []struct {
		name       string
		statusCode int
	}{
		{
			name:       "500 Internal Server Error",
			statusCode: 500,
		},
		{
			name:       "502 Bad Gateway",
			statusCode: 502,
		},
		{
			name:       "503 Service Unavailable",
			statusCode: 503,
		},
		{
			name:       "504 Gateway Timeout",
			statusCode: 504,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyUpstreamResponse(tc.statusCode, target)
			require.NotNil(t, result)
			assert.Equal(t, URS, result.Flag)
			assert.Equal(t, "upstream_response_5xx", result.Details)
			assert.Equal(t, "ReverseProxy", result.Source)
			assert.Equal(t, target, result.Target)
			assert.Equal(t, tc.statusCode, result.UpstreamStatus)
		})
	}
}

// timeoutError implements net.Error for testing timeout detection
type timeoutError struct {
	timeout   bool
	temporary bool
}

func (e *timeoutError) Error() string   { return "timeout error" }
func (e *timeoutError) Timeout() bool   { return e.timeout }
func (e *timeoutError) Temporary() bool { return e.temporary }

func TestClassifyUpstreamError_AdditionalTLSErrors(t *testing.T) {
	target := "api.backend.com:443"

	tests := []struct {
		name           string
		err            error
		expectedFlag   ResponseFlag
		expectedDetail string
	}{
		{
			name:           "TLS alert error",
			err:            tls.AlertError(40), // handshake_failure alert
			expectedFlag:   TLA,
			expectedDetail: "tls_alert_error",
		},
		{
			name:           "TLS alert error - protocol version",
			err:            tls.AlertError(70), // protocol_version alert
			expectedFlag:   TLA,
			expectedDetail: "tls_alert_error",
		},
		{
			name:           "system roots error",
			err:            x509.SystemRootsError{},
			expectedFlag:   TLC,
			expectedDetail: "tls_certificate_chain_incomplete",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyUpstreamError(tc.err, target)
			require.NotNil(t, result)
			assert.Equal(t, tc.expectedFlag, result.Flag)
			assert.Equal(t, tc.expectedDetail, result.Details)
			assert.Equal(t, "ReverseProxy", result.Source)
			assert.Equal(t, target, result.Target)
		})
	}
}

func TestClassifyUpstreamError_AdditionalSyscallErrors(t *testing.T) {
	target := "api.backend.com:443"

	tests := []struct {
		name           string
		err            error
		expectedFlag   ResponseFlag
		expectedDetail string
	}{
		{
			name:           "broken pipe (EPIPE)",
			err:            syscall.EPIPE,
			expectedFlag:   EPI,
			expectedDetail: "broken_pipe",
		},
		{
			name:           "connection aborted (ECONNABORTED)",
			err:            syscall.ECONNABORTED,
			expectedFlag:   CAB,
			expectedDetail: "connection_aborted",
		},
		{
			name:           "network reset (ENETRESET)",
			err:            syscall.ENETRESET,
			expectedFlag:   NRS,
			expectedDetail: "network_reset",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyUpstreamError(tc.err, target)
			require.NotNil(t, result)
			assert.Equal(t, tc.expectedFlag, result.Flag)
			assert.Equal(t, tc.expectedDetail, result.Details)
			assert.Equal(t, "ReverseProxy", result.Source)
			assert.Equal(t, target, result.Target)
		})
	}
}

func TestClassifyUpstreamError_WrappedAdditionalErrors(t *testing.T) {
	target := "api.backend.com:443"

	t.Run("url.Error wrapping EPIPE", func(t *testing.T) {
		err := &url.Error{
			Op:  "Post",
			URL: "https://api.backend.com/test",
			Err: syscall.EPIPE,
		}
		result := ClassifyUpstreamError(err, target)
		require.NotNil(t, result)
		assert.Equal(t, EPI, result.Flag)
		assert.Equal(t, "broken_pipe", result.Details)
	})

	t.Run("net.OpError wrapping ECONNABORTED", func(t *testing.T) {
		err := &net.OpError{
			Op:  "write",
			Net: "tcp",
			Err: syscall.ECONNABORTED,
		}
		result := ClassifyUpstreamError(err, target)
		require.NotNil(t, result)
		assert.Equal(t, CAB, result.Flag)
	})

	t.Run("url.Error wrapping TLS alert", func(t *testing.T) {
		err := &url.Error{
			Op:  "Get",
			URL: "https://api.backend.com/test",
			Err: tls.AlertError(40),
		}
		result := ClassifyUpstreamError(err, target)
		require.NotNil(t, result)
		assert.Equal(t, TLA, result.Flag)
	})
}

func TestClassifyUpstreamError_TLSStringFallback(t *testing.T) {
	target := "api.backend.com:443"

	tests := []struct {
		name           string
		err            error
		expectedFlag   ResponseFlag
		expectedDetail string
	}{
		// TLP - Protocol version errors
		{
			name:           "remote error protocol version",
			err:            errors.New("remote error: tls: protocol version not supported"),
			expectedFlag:   TLP,
			expectedDetail: "tls_protocol_version_error",
		},
		{
			name:           "no supported versions",
			err:            errors.New("tls: no supported versions satisfy MinVersion and MaxVersion"),
			expectedFlag:   TLP,
			expectedDetail: "tls_protocol_version_error",
		},
		// TLH - Handshake failures
		{
			name:           "remote error internal error",
			err:            errors.New("remote error: tls: internal error"),
			expectedFlag:   TLH,
			expectedDetail: "tls_handshake_failure",
		},
		{
			name:           "handshake failure",
			err:            errors.New("remote error: tls: handshake failure"),
			expectedFlag:   TLH,
			expectedDetail: "tls_handshake_failure",
		},
		{
			name:           "bad certificate",
			err:            errors.New("remote error: tls: bad certificate"),
			expectedFlag:   TLH,
			expectedDetail: "tls_handshake_failure",
		},
		{
			name:           "first record not TLS",
			err:            errors.New("tls: first record does not look like a tls handshake"),
			expectedFlag:   TLH,
			expectedDetail: "tls_handshake_failure",
		},
		{
			name:           "certificate required",
			err:            errors.New("remote error: tls: certificate required"),
			expectedFlag:   TLH,
			expectedDetail: "tls_handshake_failure",
		},
		// TLA - Generic TLS alerts (fallback)
		{
			name:           "generic remote tls error",
			err:            errors.New("remote error: tls: unknown certificate"),
			expectedFlag:   TLA,
			expectedDetail: "tls_alert_received",
		},
		{
			name:           "unrecognized name alert",
			err:            errors.New("remote error: tls: unrecognized name"),
			expectedFlag:   TLA,
			expectedDetail: "tls_alert_received",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyUpstreamError(tc.err, target)
			require.NotNil(t, result)
			assert.Equal(t, tc.expectedFlag, result.Flag)
			assert.Equal(t, tc.expectedDetail, result.Details)
			assert.Equal(t, "ReverseProxy", result.Source)
			assert.Equal(t, target, result.Target)
		})
	}
}

func TestClassifyUpstreamError_EdgeCases(t *testing.T) {
	t.Run("empty target string", func(t *testing.T) {
		err := syscall.ECONNREFUSED
		result := ClassifyUpstreamError(err, "")
		require.NotNil(t, result)
		assert.Equal(t, UCF, result.Flag)
		assert.Equal(t, "", result.Target) // Should accept empty target
	})

	t.Run("certificate expired with nil cert", func(t *testing.T) {
		err := x509.CertificateInvalidError{
			Cert:   nil, // Edge case: nil certificate
			Reason: x509.Expired,
		}
		result := ClassifyUpstreamError(err, "api.backend.com:443")
		require.NotNil(t, result)
		assert.Equal(t, TLE, result.Flag)
		assert.True(t, result.TLSCertExpiry.IsZero()) // No panic, zero time
		assert.Empty(t, result.TLSCertSubject)        // No panic, empty subject
	})

	t.Run("TLS expired cert populates TLSInfo", func(t *testing.T) {
		expiry := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
		cert := &x509.Certificate{
			NotAfter: expiry,
			Subject:  pkix.Name{CommonName: "api.backend.com"},
		}
		err := x509.CertificateInvalidError{Cert: cert, Reason: x509.Expired}
		result := ClassifyUpstreamError(err, "api.backend.com:443")

		require.NotNil(t, result)
		assert.Equal(t, TLE, result.Flag)
		assert.Equal(t, expiry, result.TLSCertExpiry)
		assert.Contains(t, result.TLSCertSubject, "api.backend.com")
	})

	t.Run("very long error message string fallback", func(t *testing.T) {
		longMsg := strings.Repeat("x", 10000) + " connection refused"
		err := errors.New(longMsg)
		result := ClassifyUpstreamError(err, "api.backend.com:443")
		require.NotNil(t, result)
		assert.Equal(t, UCF, result.Flag) // Still detects pattern
	})

	t.Run("case insensitive string matching", func(t *testing.T) {
		err := errors.New("CONNECTION REFUSED by server")
		result := ClassifyUpstreamError(err, "api.backend.com:443")
		require.NotNil(t, result)
		assert.Equal(t, UCF, result.Flag)
	})

	t.Run("deeply nested url.Error and net.OpError", func(t *testing.T) {
		err := &url.Error{
			Op:  "Get",
			URL: "https://api.backend.com/test",
			Err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &net.OpError{
					Op:  "connect",
					Net: "tcp",
					Err: syscall.ETIMEDOUT,
				},
			},
		}
		result := ClassifyUpstreamError(err, "api.backend.com:443")
		require.NotNil(t, result)
		assert.Equal(t, UCT, result.Flag)
	})

	t.Run("mixed case timeout string", func(t *testing.T) {
		err := errors.New("TIMEOUT awaiting RESPONSE HEADERS")
		result := ClassifyUpstreamError(err, "api.backend.com:443")
		require.NotNil(t, result)
		assert.Equal(t, URT, result.Flag)
	})

	t.Run("broken pipe string fallback", func(t *testing.T) {
		err := errors.New("write tcp: broken pipe")
		result := ClassifyUpstreamError(err, "api.backend.com:443")
		require.NotNil(t, result)
		assert.Equal(t, EPI, result.Flag)
		assert.Equal(t, "broken_pipe", result.Details)
	})
}
