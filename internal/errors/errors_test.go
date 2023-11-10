package errors

import (
	"errors"
	"testing"
)

func TestErrorFormatter(t *testing.T) {
	tests := []struct {
		name     string
		errs     []error
		expected string
	}{
		{
			name:     "No errors",
			errs:     []error{},
			expected: "",
		},
		{
			name:     "Single error",
			errs:     []error{errors.New("error 1")},
			expected: "error 1",
		},
		{
			name:     "Multiple errors",
			errs:     []error{errors.New("error 1"), errors.New("error 2")},
			expected: "error 1\nerror 2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ErrorFormatter(tc.errs)
			if result != tc.expected {
				t.Errorf("ErrorFormatter() = %v, want %v", result, tc.expected)
			}
		})
	}
}
