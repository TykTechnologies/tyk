package rpc

import (
	"errors"
	"testing"
)

func TestEqualStringSlices(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "empty slices",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
		{
			name:     "nil slices",
			a:        nil,
			b:        nil,
			expected: true,
		},
		{
			name:     "nil and empty",
			a:        nil,
			b:        []string{},
			expected: true,
		},
		{
			name:     "single element same",
			a:        []string{"test"},
			b:        []string{"test"},
			expected: true,
		},
		{
			name:     "single element different",
			a:        []string{"test1"},
			b:        []string{"test2"},
			expected: false,
		},
		{
			name:     "multiple elements same order",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "c"},
			expected: true,
		},
		{
			name:     "multiple elements different order",
			a:        []string{"a", "b", "c"},
			b:        []string{"c", "a", "b"},
			expected: true,
		},
		{
			name:     "different lengths",
			a:        []string{"a", "b"},
			b:        []string{"a", "b", "c"},
			expected: false,
		},
		{
			name:     "subset",
			a:        []string{"a", "b"},
			b:        []string{"a", "b", "a"},
			expected: false,
		},
		{
			name:     "same elements with duplicates",
			a:        []string{"a", "b", "a"},
			b:        []string{"a", "a", "b"},
			expected: true,
		},
		{
			name:     "different elements with same length",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "d"},
			expected: false,
		},
		{
			name:     "empty string elements",
			a:        []string{"", "b"},
			b:        []string{"", "b"},
			expected: true,
		},
		{
			name:     "case sensitivity",
			a:        []string{"A", "b"},
			b:        []string{"a", "b"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := equalStringSlices(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("equalStringSlices(%v, %v) = %v, expected %v",
					tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestIsDNSError tests the isDNSError function
func TestIsDNSError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "non-DNS error",
			err:      errors.New("some random error"),
			expected: false,
		},
		// Generic RPC errors should NOT be treated as DNS errors
		{
			name:     "unexpected response type error - not DNS related",
			err:      errors.New("unexpected response type: <nil>. Expected *dispatcherResponse"),
			expected: false,
		},
		{
			name:     "timeout error - not DNS related",
			err:      errors.New("Cannot obtain response during timeout=30s"),
			expected: false,
		},
		{
			name:     "rpc down error - not DNS related",
			err:      errors.New("rpc is either down or was not configured"),
			expected: false,
		},
		{
			name:     "decode error - not DNS related",
			err:      errors.New("Cannot decode response"),
			expected: false,
		},
		// Actual DNS errors SHOULD be detected
		{
			name:     "no such host - DNS error",
			err:      errors.New("dial tcp: lookup mdcb.example.com: no such host"),
			expected: true,
		},
		{
			name:     "DNS lookup timeout",
			err:      errors.New("dial tcp: lookup mdcb.example.com on 8.8.8.8:53: i/o timeout"),
			expected: true,
		},
		{
			name:     "lookup without timeout - not a DNS error",
			err:      errors.New("lookup failed for other reasons"),
			expected: false,
		},
		{
			name:     "timeout without lookup - not a DNS error",
			err:      errors.New("connection timeout"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isDNSError(tt.err)
			if result != tt.expected {
				t.Errorf("isDNSError(%v) = %v, expected %v", tt.err, result, tt.expected)
			}
		})
	}
}
