package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple name",
			input:    "get-weather",
			expected: "get-weather",
		},
		{
			name:     "resource pattern with file protocol",
			input:    "file:///repo/*",
			expected: "file__repo_*",
		},
		{
			name:     "resource pattern with http protocol",
			input:    "http://example.com/api",
			expected: "http_example.com_api",
		},
		{
			name:     "name with colons",
			input:    "my:tool:name",
			expected: "my_tool_name",
		},
		{
			name:     "name with slashes",
			input:    "path/to/resource",
			expected: "path_to_resource",
		},
		{
			name:     "complex pattern",
			input:    "https://api.example.com:8080/v1/resources/*",
			expected: "https_api.example.com_8080_v1_resources_*",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single character",
			input:    "a",
			expected: "a",
		},
		{
			name:     "name with spaces",
			input:    "my tool name",
			expected: "my tool name",
		},
		{
			name:     "name with dots",
			input:    "api.example.com",
			expected: "api.example.com",
		},
		{
			name:     "multiple consecutive slashes",
			input:    "path///to///resource",
			expected: "path___to___resource",
		},
		{
			name:     "only special characters",
			input:    ":///::",
			expected: "____",
		},
		{
			name:     "unicode characters",
			input:    "工具-天气",
			expected: "工具-天气",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
