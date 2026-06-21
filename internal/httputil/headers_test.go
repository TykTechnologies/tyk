package httputil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

// Verifies: STK-REQ-085, SYS-REQ-173, SW-REQ-160
// SW-REQ-160:nominal:nominal
// SW-REQ-160:boundary:nominal
// SW-REQ-160:encoding_safety:nominal
// SW-REQ-160:determinism:nominal
func TestAuthHeader(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		want     string
	}{
		{name: "plain credentials", username: "user", password: "password", want: "Basic dXNlcjpwYXNzd29yZA=="},
		{name: "empty password", username: "user", password: "", want: "Basic dXNlcjo="},
		{name: "colon remains part of credential payload", username: "user:name", password: "pass:word", want: "Basic dXNlcjpuYW1lOnBhc3M6d29yZA=="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, httputil.AuthHeader(tt.username, tt.password))
		})
	}
}
