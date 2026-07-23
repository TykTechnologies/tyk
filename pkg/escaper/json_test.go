package escaper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJsonEscapeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain_string",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "html_tags_and_ampersand",
			input:    "<script> & </script>",
			expected: `\u003Cscript\u003E \u0026 \u003C/script\u003E`,
		},
		{
			name:     "double_quotes",
			input:    `"hello world"`,
			expected: `\"hello world\"`,
		},
		{
			name:     "single_quote_skipped",
			input:    `it's a trap`,
			expected: `it's a trap`,
		},
		{
			name:     "control_characters",
			input:    "null\x00_bell\x07_escape\x1B",
			expected: `null\u0000_bell\u0007_escape\u001B`,
		},
		{
			name:     "standard_whitespace_escapes",
			input:    "line1\nline2\r\ttabbed",
			expected: `line1\u000Aline2\u000D\u0009tabbed`,
		},
		{
			name:     "unicode_separators",
			input:    "line\u2028paragraph\u2029",
			expected: `line\u2028paragraph\u2029`,
		},
		{
			name:     "chinese_characters_untouched",
			input:    "Tyk API 网关",
			expected: "Tyk API 网关",
		},
		{
			name:     "mixed_complex_payload",
			input:    "<\n\u2028'汉字'\u2029\r>",
			expected: "\\u003C\\u000A\\u2028'汉字'\\u2029\\u000D\\u003E",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, JsonEscapeString(tt.input))
		})
	}
}
