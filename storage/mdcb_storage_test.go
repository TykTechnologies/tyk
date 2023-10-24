package storage

import "testing"

func TestGetResourceType(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"oauth-clientid.client-id", "Oauth Client"},
		{"cert.something", "certificate"},
		{"apikey.something", "api key"},
		{"unmatched-key", "key"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := getResourceType(tt.key)
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}
