package apidef

import (
	"bytes"
	"errors"
	"testing"
)

func TestTransformUnicodeEscapesToRE2(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "Pattern with unicode range",
			input:    []byte("{\"pattern\": \"^[\\\\u0000-\\\\u017f]*$\"}"),
			expected: []byte("{\"pattern\": \"^[\\\\x{0000}-\\\\x{017f}]*$\"}"),
		},
		{
			name:     "Null character",
			input:    []byte("{\"pattern\": \"\\\\u0000\"}"),
			expected: []byte("{\"pattern\": \"\\\\x{0000}\"}"),
		},
		{
			name:     "Multiple unicode characters",
			input:    []byte("{\"pattern\": \"\\\\u0041\\\\u0042\\\\u0043\"}"),
			expected: []byte("{\"pattern\": \"\\\\x{0041}\\\\x{0042}\\\\x{0043}\"}"),
		},
		{
			name:     "No unicode characters",
			input:    []byte("{\"pattern\": \"^[a-zA-Z0-9]*$\"}"),
			expected: []byte("{\"pattern\": \"^[a-zA-Z0-9]*$\"}"),
		},
		{
			name:     "Empty input",
			input:    []byte(``),
			expected: []byte(``),
		},
		{
			name:     "Mixed content",
			input:    []byte("{\"description\": \"A string with \\\\u0020 space\"}"),
			expected: []byte("{\"description\": \"A string with \\\\x{0020} space\"}"),
		},
		{
			name:     "Already contains RE2 escapes",
			input:    []byte("\"pattern\": \"\\\\x{1234}\""),
			expected: []byte("\"pattern\": \"\\\\x{1234}\""),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := TransformUnicodeEscapesToRE2(tc.input)
			if !bytes.Equal(actual, tc.expected) {
				t.Errorf("expected %s, but got %s", tc.expected, actual)
			}
		})
	}
}

func TestRestoreUnicodeEscapesFromRE2(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "Pattern with RE2 range",
			input:    []byte("{\"pattern\": \"^[\\\\x{0000}-\\\\x{017f}]*$\"}"),
			expected: []byte("{\"pattern\": \"^[\\\\u0000-\\\\u017f]*$\"}"),
		},
		{
			name:     "Null character escape",
			input:    []byte("{\"pattern\": \"\\\\x{0000}\"}"),
			expected: []byte("{\"pattern\": \"\\\\u0000\"}"),
		},
		{
			name:     "Multiple RE2 escapes",
			input:    []byte("{\"pattern\": \"\\\\x{0041}\\\\x{0042}\\\\x{0043}\"}"),
			expected: []byte("{\"pattern\": \"\\\\u0041\\\\u0042\\\\u0043\"}"),
		},
		{
			name:     "No RE2 escapes",
			input:    []byte("{\"pattern\": \"^[a-zA-Z0-9]*$\"}"),
			expected: []byte("{\"pattern\": \"^[a-zA-Z0-9]*$\"}"),
		},
		{
			name:     "Empty input",
			input:    []byte(``),
			expected: []byte(``),
		},
		{
			name:     "Mixed content",
			input:    []byte("{{\"description\": \"A string with \\\\x{0020} space\"}}"),
			expected: []byte("{{\"description\": \"A string with \\\\u0020 space\"}}"),
		},
		{
			name:     "Already contains unicode escapes",
			input:    []byte("{\"pattern\": \"\\\\u1234\"}"),
			expected: []byte("{\"pattern\": \"\\\\u1234\"}"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RestoreUnicodeEscapesFromRE2(tc.input)
			if !bytes.Equal(actual, tc.expected) {
				t.Errorf("expected %s, but got %s", tc.expected, actual)
			}
		})
	}
}

func TestRestoreUnicodeEscapesInError(t *testing.T) {
	tests := []struct {
		name      string
		input     error
		wantError bool
		want      string
	}{
		{
			name:      "Error with a single unicode escape",
			input:     errors.New("invalid sequence: \\x{005C}"),
			wantError: true,
			want:      "invalid sequence: \\u005C",
		},
		{
			name:      "Error with multiple unicode escapes",
			input:     errors.New("found invalid chars: \\x{0041}, \\x{0042}"),
			wantError: true,
			want:      "found invalid chars: \\u0041, \\u0042",
		},
		{
			name:      "Error with no unicode escapes",
			input:     errors.New("this is a standard error"),
			wantError: true,
			want:      "this is a standard error",
		},
		{
			name:      "Nil error",
			input:     nil,
			wantError: false,
			want:      "",
		},
		{
			name:      "Empty error message",
			input:     errors.New(""),
			wantError: true,
			want:      "",
		},
		{
			name:      "Malformed escape sequence",
			input:     errors.New("malformed: \\x{123}"),
			wantError: true,
			want:      "malformed: \\x{123}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RestoreUnicodeEscapesInError(tt.input)

			if (got != nil) != tt.wantError {
				t.Fatalf("RestoreUnicodeEscapesInError() error = %v, wantError %v", got, tt.wantError)
			}

			if tt.wantError && got.Error() != tt.want {
				t.Errorf("RestoreUnicodeEscapesInError() = %q, want %q", got.Error(), tt.want)
			}
		})
	}
}
