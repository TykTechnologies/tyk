package url

import (
	"net/url"
	"testing"
)

func TestQueryHas(t *testing.T) {
	tests := []struct {
		name     string
		values   url.Values
		key      string
		expected bool
	}{
		{
			name:     "Key present",
			values:   url.Values{"test": []string{"value"}},
			key:      "test",
			expected: true,
		},
		{
			name:     "Key absent",
			values:   url.Values{"test": []string{"value"}},
			key:      "missing",
			expected: false,
		},
		{
			name:     "Empty values",
			values:   url.Values{},
			key:      "any",
			expected: false,
		},
		{
			name:     "Multiple keys, target present",
			values:   url.Values{"test": []string{"value"}, "another": []string{"value2"}},
			key:      "another",
			expected: true,
		},
		{
			name:     "Multiple keys, target absent",
			values:   url.Values{"test": []string{"value"}, "another": []string{"value2"}},
			key:      "missing",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := QueryHas(tt.values, tt.key)
			if result != tt.expected {
				t.Errorf("QueryHas(%v, %q) = %v; want %v", tt.values, tt.key, result, tt.expected)
			}
		})
	}
}
