package gateway

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDashboardAuthError_Error(t *testing.T) {
	err := &DashboardAuthError{StatusCode: 403, Body: "Nonce failed"}
	assert.Equal(t, "dashboard authentication failed (status 403): Nonce failed", err.Error())
}

func Test_shouldRetryOnNetworkError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		retry bool
	}{
		{"nil error", nil, false},
		{"io.EOF", io.EOF, true},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, true},
		{"string EOF", errors.New("read tcp: EOF"), true},
		{"connection refused", errors.New("dial tcp: connection refused"), true},
		{"connection reset", errors.New("read tcp: connection reset by peer"), true},
		{"broken pipe", errors.New("write tcp: broken pipe"), true},
		{"i/o timeout", errors.New("dial tcp: i/o timeout"), true},
		{"no such host", errors.New("dial tcp: no such host"), true},
		{"network is unreachable", errors.New("connect: network is unreachable"), true},
		{"unrelated error", errors.New("something else entirely"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.retry, shouldRetryOnNetworkError(tc.err))
		})
	}
}

func Test_isNonceRelatedError(t *testing.T) {
	tests := []struct {
		msg   string
		match bool
	}{
		{"Nonce failed", true},
		{"nonce mismatch detected", true},
		{"No node ID Found", true},
		{"dashboard is down", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q", tc.msg), func(t *testing.T) {
			assert.Equal(t, tc.match, isNonceRelatedError(tc.msg))
		})
	}
}

func Test_isEOFError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		match bool
	}{
		{"io.EOF", io.EOF, true},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, true},
		{"string containing EOF", errors.New("read tcp: EOF"), true},
		{"unrelated error", errors.New("some other error"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.match, isEOFError(tc.err))
		})
	}
}
