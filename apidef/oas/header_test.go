package oas

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-104, SW-REQ-047
// SW-REQ-047:nominal:nominal
// SW-REQ-047:boundary:boundary
// SW-REQ-047:determinism:nominal
func TestHeaders_Map(t *testing.T) {
	tests := []struct {
		name    string
		headers *Headers
		want    map[string]string
	}{
		{
			name: "populated headers",
			headers: &Headers{
				{
					Name:  "k1",
					Value: "v1",
				},
				{
					Name:  "k2",
					Value: "v2",
				},
			},
			want: map[string]string{
				"k1": "v1",
				"k2": "v2",
			},
		},
		{
			name:    "nil receiver returns empty map",
			headers: nil,
			want:    map[string]string{},
		},
		{
			name:    "empty list returns empty map",
			headers: &Headers{},
			want:    map[string]string{},
		},
		{
			name: "duplicate names use last value",
			headers: &Headers{
				{
					Name:  "X-Test",
					Value: "first",
				},
				{
					Name:  "X-Test",
					Value: "last",
				},
			},
			want: map[string]string{
				"X-Test": "last",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.headers.Map())
		})
	}
}

// Verifies: SYS-REQ-104, SW-REQ-047
// SW-REQ-047:nominal:nominal
func TestHeaders_Add(t *testing.T) {
	var headers Headers

	headers.Add("X-Test", "value")
	headers.Add("X-Other", "other")

	require.Equal(t, Headers{
		{Name: "X-Test", Value: "value"},
		{Name: "X-Other", Value: "other"},
	}, headers)
}

// Verifies: SYS-REQ-104, SW-REQ-047
// SW-REQ-047:nominal:nominal
// SW-REQ-047:boundary:boundary
// SW-REQ-047:determinism:nominal
func TestNewHeaders(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]string
		want Headers
	}{
		{
			name: "sorts input map by name",
			in: map[string]string{
				"k2": "v2",
				"k1": "v1",
			},
			want: Headers{
				{
					Name:  "k1",
					Value: "v1",
				},
				{
					Name:  "k2",
					Value: "v2",
				},
			},
		},
		{
			name: "nil map returns empty headers",
			in:   nil,
			want: Headers{},
		},
		{
			name: "empty map returns empty headers",
			in:   map[string]string{},
			want: Headers{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, NewHeaders(tt.in))
		})
	}
}
