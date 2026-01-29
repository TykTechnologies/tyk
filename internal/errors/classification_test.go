package errors

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestResponseFlagConstants(t *testing.T) {
	// Verify all 22 flag values are distinct and have expected string representations
	flags := []struct {
		flag        ResponseFlag
		expected    string
		description string
	}{
		{TLE, "TLE", "TLS certificate expired"},
		{TLI, "TLI", "TLS certificate invalid"},
		{TLM, "TLM", "TLS certificate mismatch"},
		{TLN, "TLN", "TLS not configured"},
		{TLH, "TLH", "TLS handshake failed"},
		{TLP, "TLP", "TLS protocol error"},
		{TLA, "TLA", "TLS alert"},
		{TLC, "TLC", "TLS certificate chain incomplete"},
		{UCF, "UCF", "Upstream connection failure"},
		{UCT, "UCT", "Upstream connection timeout"},
		{URR, "URR", "Upstream request rejected"},
		{URT, "URT", "Upstream request timeout"},
		{EPI, "EPI", "EPIPE - broken pipe"},
		{CAB, "CAB", "Connection aborted"},
		{NRS, "NRS", "Network reset"},
		{DNS, "DNS", "DNS resolution failure"},
		{NRH, "NRH", "No route to host"},
		{NHU, "NHU", "No healthy upstreams"},
		{CBO, "CBO", "Circuit breaker open"},
		{CDC, "CDC", "Client disconnected"},
		{URS, "URS", "Upstream response status"},
		{UPE, "UPE", "Upstream protocol error"},
	}

	seen := make(map[ResponseFlag]bool)
	for _, tc := range flags {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.flag.String(), "flag should match expected string: %s", tc.description)
			assert.False(t, seen[tc.flag], "flag %s should be unique", tc.expected)
			seen[tc.flag] = true
		})
	}

	// Ensure we have exactly 22 flags
	assert.Len(t, flags, 22, "should have exactly 22 response flags")
}

func TestNewErrorClassification(t *testing.T) {
	t.Run("creates classification with flag and details", func(t *testing.T) {
		ec := NewErrorClassification(TLE, "tls_certificate_expired")
		assert.Equal(t, TLE, ec.Flag)
		assert.Equal(t, "tls_certificate_expired", ec.Details)
	})

	t.Run("default values are empty/zero", func(t *testing.T) {
		ec := NewErrorClassification(UCF, "connection_refused")
		assert.Empty(t, ec.Source)
		assert.Empty(t, ec.Target)
		assert.Zero(t, ec.UpstreamStatus)
		assert.True(t, ec.TLSCertExpiry.IsZero())
		assert.Empty(t, ec.TLSCertSubject)
		assert.Empty(t, ec.CircuitBreakerState)
	})
}

func TestErrorClassificationBuilderChaining(t *testing.T) {
	t.Run("WithSource returns same instance", func(t *testing.T) {
		ec := NewErrorClassification(UCF, "connection_refused")
		result := ec.WithSource("ReverseProxy")
		assert.Same(t, ec, result)
		assert.Equal(t, "ReverseProxy", ec.Source)
	})

	t.Run("WithTarget returns same instance", func(t *testing.T) {
		ec := NewErrorClassification(UCF, "connection_refused")
		result := ec.WithTarget("api.backend.com:443")
		assert.Same(t, ec, result)
		assert.Equal(t, "api.backend.com:443", ec.Target)
	})

	t.Run("WithTLSInfo sets both fields", func(t *testing.T) {
		ec := NewErrorClassification(TLE, "tls_certificate_expired")
		expiry := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
		result := ec.WithTLSInfo(expiry, "CN=api.backend.com")
		assert.Same(t, ec, result)
		assert.Equal(t, expiry, ec.TLSCertExpiry)
		assert.Equal(t, "CN=api.backend.com", ec.TLSCertSubject)
	})

	t.Run("WithCircuitBreakerState sets state", func(t *testing.T) {
		ec := NewErrorClassification(CBO, "circuit_breaker_open")
		result := ec.WithCircuitBreakerState("OPEN")
		assert.Same(t, ec, result)
		assert.Equal(t, "OPEN", ec.CircuitBreakerState)
	})

	t.Run("WithUpstreamStatus sets status", func(t *testing.T) {
		ec := NewErrorClassification(URS, "upstream_response_5xx")
		result := ec.WithUpstreamStatus(503)
		assert.Same(t, ec, result)
		assert.Equal(t, 503, ec.UpstreamStatus)
	})

	t.Run("chaining multiple methods", func(t *testing.T) {
		expiry := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
		ec := NewErrorClassification(TLE, "tls_certificate_expired").
			WithSource("ReverseProxy").
			WithTarget("api.backend.com:443").
			WithTLSInfo(expiry, "CN=api.backend.com")

		assert.Equal(t, TLE, ec.Flag)
		assert.Equal(t, "tls_certificate_expired", ec.Details)
		assert.Equal(t, "ReverseProxy", ec.Source)
		assert.Equal(t, "api.backend.com:443", ec.Target)
		assert.Equal(t, expiry, ec.TLSCertExpiry)
		assert.Equal(t, "CN=api.backend.com", ec.TLSCertSubject)
	})
}
